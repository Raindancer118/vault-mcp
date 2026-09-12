/**
 * Local search cache — metadata-only mirror of Vaultwarden items.
 * Contains NO secret values. Used for fast fuzzy search without round-tripping to the vault.
 *
 * DB: ~/.cache/vault-mcp/search.db (SQLite via better-sqlite3)
 */

import Database from 'better-sqlite3';
import Fuse from 'fuse.js';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { BwItemMeta } from '../vault/bw-client.js';

const CACHE_DIR = join(homedir(), '.cache', 'vault-mcp');
const DB_PATH = join(CACHE_DIR, 'search.db');

export interface CachedItem {
  id: string;
  vault: string;
  name: string;
  /** 1=login  2=note  3=card  4=identity */
  type: number;
  folderId: string | null;
  folderName: string | null;
  favorite: boolean;
  uris: string[];
  username: string | null;
  /** Names of custom fields only — no values */
  fieldNames: string[];
  revisionDate: string;
}

export interface SearchResult extends CachedItem {
  /** Fuse.js score: 0 = perfect match, 1 = no match */
  score: number;
  /** Human-readable reasons this item matched, e.g. "field name: API Token", "domain: coolify.tstieh.de" */
  matchedOn: string[];
}

export interface SyncStats {
  vault: string;
  upserted: number;
  removed: number;
  syncedAt: string;
}

// ─── DB setup ─────────────────────────────────────────────────────────────────

function openDb(): Database.Database {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR, { recursive: true, mode: 0o700 });
  const db = new Database(DB_PATH, { fileMustExist: false });
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS items (
      id            TEXT NOT NULL,
      vault         TEXT NOT NULL,
      name          TEXT NOT NULL,
      type          INTEGER NOT NULL,
      folder_id     TEXT,
      folder_name   TEXT,
      favorite      INTEGER NOT NULL DEFAULT 0,
      uris          TEXT NOT NULL DEFAULT '[]',
      username      TEXT,
      field_names   TEXT NOT NULL DEFAULT '[]',
      revision_date TEXT NOT NULL,
      synced_at     TEXT NOT NULL,
      PRIMARY KEY (id, vault)
    );
    CREATE TABLE IF NOT EXISTS sync_log (
      vault      TEXT PRIMARY KEY,
      synced_at  TEXT NOT NULL,
      item_count INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_items_vault ON items(vault);
    CREATE INDEX IF NOT EXISTS idx_items_name  ON items(name COLLATE NOCASE);
  `);
  return db;
}

// ─── Sync ─────────────────────────────────────────────────────────────────────

/**
 * Replaces all cached items for `vaultName` with the provided metadata array.
 * Folder names are resolved via the `folderMap` (id → name).
 */
export function syncVault(
  vaultName: string,
  items: BwItemMeta[],
  folderMap: Map<string, string>,
): SyncStats {
  const db = openDb();
  const now = new Date().toISOString();

  const upsert = db.prepare(`
    INSERT INTO items (id, vault, name, type, folder_id, folder_name, favorite, uris, username, field_names, revision_date, synced_at)
    VALUES (@id, @vault, @name, @type, @folderId, @folderName, @favorite, @uris, @username, @fieldNames, @revisionDate, @syncedAt)
    ON CONFLICT(id, vault) DO UPDATE SET
      name          = excluded.name,
      type          = excluded.type,
      folder_id     = excluded.folder_id,
      folder_name   = excluded.folder_name,
      favorite      = excluded.favorite,
      uris          = excluded.uris,
      username      = excluded.username,
      field_names   = excluded.field_names,
      revision_date = excluded.revision_date,
      synced_at     = excluded.synced_at
  `);

  const incomingIds = new Set(items.map(i => i.id));

  const existingIds = (
    db.prepare('SELECT id FROM items WHERE vault = ?').all(vaultName) as { id: string }[]
  ).map(r => r.id);

  const toRemove = existingIds.filter(id => !incomingIds.has(id));

  const syncAll = db.transaction(() => {
    let upserted = 0;
    for (const item of items) {
      upsert.run({
        id: item.id,
        vault: vaultName,
        name: item.name,
        type: item.type,
        folderId: item.folderId,
        folderName: item.folderId ? (folderMap.get(item.folderId) ?? null) : null,
        favorite: item.favorite ? 1 : 0,
        uris: JSON.stringify(item.login?.uris ?? []),
        username: item.login?.username ?? null,
        fieldNames: JSON.stringify((item.fields ?? []).map(f => f.name)),
        revisionDate: item.revisionDate,
        syncedAt: now,
      });
      upserted++;
    }

    if (toRemove.length > 0) {
      const placeholders = toRemove.map(() => '?').join(',');
      db.prepare(`DELETE FROM items WHERE vault = ? AND id IN (${placeholders})`).run(
        vaultName, ...toRemove,
      );
    }

    db.prepare(`
      INSERT INTO sync_log (vault, synced_at, item_count) VALUES (?, ?, ?)
      ON CONFLICT(vault) DO UPDATE SET synced_at = excluded.synced_at, item_count = excluded.item_count
    `).run(vaultName, now, items.length);

    return upserted;
  });

  const upserted = syncAll() as number;
  db.close();

  return { vault: vaultName, upserted, removed: toRemove.length, syncedAt: now };
}

// ─── Query ────────────────────────────────────────────────────────────────────

function rowToItem(row: Record<string, unknown>): CachedItem {
  return {
    id: row.id as string,
    vault: row.vault as string,
    name: row.name as string,
    type: row.type as number,
    folderId: row.folder_id as string | null,
    folderName: row.folder_name as string | null,
    favorite: Boolean(row.favorite),
    uris: JSON.parse(row.uris as string) as string[],
    username: row.username as string | null,
    fieldNames: JSON.parse(row.field_names as string) as string[],
    revisionDate: row.revision_date as string,
  };
}

/** Load all cached items — optionally filtered by vault. */
function loadAll(vaultFilter?: string): CachedItem[] {
  const db = openDb();
  const rows = vaultFilter
    ? (db.prepare('SELECT * FROM items WHERE vault = ?').all(vaultFilter) as Record<string, unknown>[])
    : (db.prepare('SELECT * FROM items').all() as Record<string, unknown>[]);
  db.close();
  return rows.map(rowToItem);
}

/** Extract a bare hostname from a URI for cleaner, more precise domain matching. */
function extractDomain(uri: string): string | null {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(uri) ? uri : `https://${uri}`;
    return new URL(withScheme).hostname.replace(/^www\./, '') || null;
  } catch {
    return null;
  }
}

/** Friendly labels for Fuse key paths, used to build human-readable `matchedOn` reasons. */
const KEY_LABELS: Record<string, string> = {
  name: 'name',
  username: 'username',
  domains: 'domain',
  uris: 'URI',
  folderName: 'folder',
  fieldNames: 'field name',
};

/**
 * Fuzzy search across cached item metadata.
 *
 * Searches: name, username, individual URIs, extracted domains, folder name,
 * and each custom field name — each indexed as its own candidate (not a joined
 * blob), so a match against e.g. one field name among many is still precise.
 * Never returns secret values, only which attribute matched.
 *
 * Near-ties with the best match are kept even beyond `limit`, so closely
 * related items (e.g. "Coolify", "Coolify API Token", "Coolify XY") surface
 * together instead of one crowding the others out.
 */
export function fuzzySearch(
  query: string,
  options: { vault?: string; limit?: number; threshold?: number } = {},
): SearchResult[] {
  const items = loadAll(options.vault);
  if (items.length === 0) return [];

  const searchable = items.map(item => ({
    ...item,
    domains: [...new Set(item.uris.map(extractDomain).filter((d): d is string => !!d))],
  }));

  const fuse = new Fuse(searchable, {
    keys: [
      { name: 'name',       weight: 3.0 },
      { name: 'fieldNames', weight: 1.5 },
      { name: 'domains',    weight: 1.5 },
      { name: 'username',   weight: 1.3 },
      { name: 'uris',       weight: 0.8 },
      { name: 'folderName', weight: 0.8 },
    ],
    threshold: options.threshold ?? 0.45,
    includeScore: true,
    includeMatches: true,
    ignoreLocation: true,
    useExtendedSearch: false,
    minMatchCharLength: 2,
  });

  const limit = options.limit ?? 20;
  const pool = fuse.search(query, { limit: Math.max(limit * 3, 30) });
  if (pool.length === 0) return [];

  const bestScore = pool[0].score ?? 1;
  const tieClusterSize = pool.filter(r => (r.score ?? 1) <= bestScore + 0.05).length;
  const keep = Math.min(Math.max(limit, tieClusterSize), 30);

  return pool.slice(0, keep).map(r => {
    const matchedOn = (r.matches ?? []).map(m => {
      const label = KEY_LABELS[m.key ?? ''] ?? m.key ?? 'field';
      return m.value ? `${label}: ${m.value}` : label;
    });
    const { domains: _domains, ...item } = r.item;
    return {
      ...item,
      score: r.score ?? 1,
      matchedOn: [...new Set(matchedOn)],
    };
  });
}

/** Return the last sync timestamps for all vaults. */
export function getSyncStatus(): Array<{ vault: string; syncedAt: string; itemCount: number }> {
  const db = openDb();
  const rows = db.prepare('SELECT vault, synced_at, item_count FROM sync_log ORDER BY synced_at DESC').all() as
    Array<{ vault: string; synced_at: string; item_count: number }>;
  db.close();
  return rows.map(r => ({ vault: r.vault, syncedAt: r.synced_at, itemCount: r.item_count }));
}

/** Total number of cached items. */
export function getCachedItemCount(vaultFilter?: string): number {
  const db = openDb();
  const row = vaultFilter
    ? (db.prepare('SELECT COUNT(*) as n FROM items WHERE vault = ?').get(vaultFilter) as { n: number })
    : (db.prepare('SELECT COUNT(*) as n FROM items').get() as { n: number });
  db.close();
  return row.n;
}
