/**
 * Favorites vault — stores complete item snapshots (including passwords) locally.
 *
 * Encryption: AES-256-GCM with a key derived via scrypt from a user passphrase.
 * The derived key is NEVER written to disk. Only the scrypt salt, IV, ciphertext,
 * and GCM auth-tag are stored. The passphrase must be supplied on every operation.
 *
 * File layout: [salt 32B | IV 12B | ciphertext | auth-tag 16B]
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'crypto';
import { ensureConfigDirs } from '../config/loader.js';

const FAVORITES_FILE = join(homedir(), '.config', 'vault-mcp', 'favorites.vault');

const SCRYPT_N = 65536;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const KEY_LEN = 32;
const SALT_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;

export interface FavoriteItem {
  id: string;
  name: string;
  sourceVault: string;
  sourceItemId: string;
  /** Bitwarden item type (1=login, 2=note, 3=card, 4=identity) */
  sourceType: number;
  username: string | null;
  password: string | null;
  notes: string | null;
  uris: string[];
  fields: Array<{ name: string; value: string | null; type: number }>;
  addedAt: string;
  updatedAt: string;
}

export interface FavoriteItemMeta extends Omit<FavoriteItem, 'password' | 'notes' | 'fields'> {
  hasPassword: boolean;
  hasNotes: boolean;
  fieldCount: number;
}

interface FavoritesData {
  version: 1;
  items: FavoriteItem[];
}

// ─── Crypto helpers ───────────────────────────────────────────────────────────

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, KEY_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
}

function encrypt(key: Buffer, data: FavoritesData): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(data), 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ct, tag]);
}

function decrypt(key: Buffer, blob: Buffer): FavoritesData {
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(IV_LEN, blob.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  try {
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
    return JSON.parse(plain) as FavoritesData;
  } catch {
    throw new Error('Wrong passphrase or corrupted favorites vault.');
  }
}

// ─── I/O ──────────────────────────────────────────────────────────────────────

function load(passphrase: string): { data: FavoritesData; salt: Buffer } {
  if (!existsSync(FAVORITES_FILE)) {
    return { data: { version: 1, items: [] }, salt: randomBytes(SALT_LEN) };
  }
  const file = readFileSync(FAVORITES_FILE);
  if (file.length < SALT_LEN + IV_LEN + TAG_LEN) {
    throw new Error('Favorites vault file is too short — may be corrupted.');
  }
  const salt = file.subarray(0, SALT_LEN);
  const blob = file.subarray(SALT_LEN);
  const key = deriveKey(passphrase, salt);
  const data = decrypt(key, blob);
  return { data, salt };
}

function save(passphrase: string, salt: Buffer, data: FavoritesData): void {
  ensureConfigDirs();
  const key = deriveKey(passphrase, salt);
  const blob = encrypt(key, data);
  writeFileSync(FAVORITES_FILE, Buffer.concat([salt, blob]), { mode: 0o600 });
}

// ─── Public API ───────────────────────────────────────────────────────────────

function toMeta(item: FavoriteItem): FavoriteItemMeta {
  const { password, notes, fields, ...rest } = item;
  return {
    ...rest,
    hasPassword: password !== null && password !== '',
    hasNotes: notes !== null && notes !== '',
    fieldCount: fields.length,
  };
}

export function favoritesFileExists(): boolean {
  return existsSync(FAVORITES_FILE);
}

export function listFavorites(passphrase: string): FavoriteItemMeta[] {
  const { data } = load(passphrase);
  return data.items.map(toMeta);
}

export function addFavorite(
  passphrase: string,
  item: Omit<FavoriteItem, 'id' | 'addedAt' | 'updatedAt'>,
): FavoriteItemMeta {
  const { data, salt } = load(passphrase);
  const duplicate = data.items.find(
    i => i.sourceVault === item.sourceVault && i.sourceItemId === item.sourceItemId,
  );
  if (duplicate) {
    throw new Error(
      `"${duplicate.name}" from vault "${item.sourceVault}" is already in favorites (id: ${duplicate.id}). Use vault_favorites_update to refresh it.`,
    );
  }
  const now = new Date().toISOString();
  const newItem: FavoriteItem = { id: crypto.randomUUID(), ...item, addedAt: now, updatedAt: now };
  data.items.push(newItem);
  save(passphrase, salt, data);
  return toMeta(newItem);
}

export function updateFavorite(
  passphrase: string,
  nameOrId: string,
  updates: Partial<Omit<FavoriteItem, 'id' | 'addedAt' | 'updatedAt'>>,
): FavoriteItemMeta {
  const { data, salt } = load(passphrase);
  const item = data.items.find(i => i.id === nameOrId || i.name === nameOrId);
  if (!item) throw new Error(`Favorite "${nameOrId}" not found.`);
  Object.assign(item, updates, { updatedAt: new Date().toISOString() });
  save(passphrase, salt, data);
  return toMeta(item);
}

export function getFavoriteSensitive(passphrase: string, nameOrId: string): FavoriteItem {
  const { data } = load(passphrase);
  const item = data.items.find(i => i.id === nameOrId || i.name === nameOrId);
  if (!item) throw new Error(`Favorite "${nameOrId}" not found.`);
  return item;
}

export function removeFavorite(passphrase: string, nameOrId: string): void {
  const { data, salt } = load(passphrase);
  const idx = data.items.findIndex(i => i.id === nameOrId || i.name === nameOrId);
  if (idx === -1) throw new Error(`Favorite "${nameOrId}" not found.`);
  data.items.splice(idx, 1);
  save(passphrase, salt, data);
}
