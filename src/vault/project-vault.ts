import {
  readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync,
} from 'fs';
import { join, resolve as resolvePath } from 'path';
import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from 'crypto';
import { getProjectsDir, ensureConfigDirs } from '../config/loader.js';
import { generateTotpSecret, totpUri } from '../tools/totp.js';

const MARKER_FILENAME = '.vault-project';
const COMMITTED_VAULT_FILENAME = '.vault-project.enc';
const VAULT_VERSION = 1 as const;

export type ProjectVaultStorage = 'external' | 'committed';

export interface VaultMarker {
  id: string;
  name: string;
  createdAt: string;
  /**
   * 'external' (default): the encrypted vault lives outside the repo, under this
   * machine's vault-mcp config dir — nothing project-vault-related is ever committed.
   * 'committed': the encrypted vault lives at `<projectDir>/.vault-project.enc` and is
   * meant to be `git add`ed/pushed. Always paired with `totpEnabled: true` — the master
   * key alone is not enough to decrypt a committed vault, see deriveKey().
   */
  storage: ProjectVaultStorage;
  totpEnabled: boolean;
}

interface ProjectVaultItem {
  id: string;
  name: string;
  value: string;
  createdAt: string;
  updatedAt: string;
}

interface ProjectVaultData {
  version: typeof VAULT_VERSION;
  items: ProjectVaultItem[];
}

export interface ProjectItemMeta {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface InitProjectResult {
  marker: VaultMarker;
  /** Only present when a TOTP seed was just generated (commit: true). Shown once — back it up now. */
  totpSeedBase32?: string;
  totpUri?: string;
}

export interface EnableTotpResult {
  totpSeedBase32: string;
  totpUri: string;
}

// ─── Crypto ───────────────────────────────────────────────────────────────────

/**
 * With no TOTP seed: unchanged v1 scheme (master key only).
 * With a TOTP seed: the seed is folded into the HKDF input keying material alongside
 * the master key, under a distinct info string, so the vault is a genuinely different
 * key — not just an extra check layered on top. Ciphertext + master key alone is not
 * enough; the local TOTP seed file is equally load-bearing. We use the static seed
 * (not the rotating 6-digit code) because the code changing every 30s cannot gate a
 * persistent ciphertext without making it undecryptable a minute later — the seed is
 * what actually has to survive across time, and it's exactly what an agent can read
 * and use automatically without any human typing a code.
 */
function deriveKey(masterKey: string, projectId: string, totpSeedBase32?: string): Buffer {
  const ikm = totpSeedBase32
    ? Buffer.concat([Buffer.from(masterKey, 'hex'), Buffer.from(totpSeedBase32, 'utf-8')])
    : Buffer.from(masterKey, 'hex');
  const info = totpSeedBase32 ? 'vault-mcp-project-v2-totp' : 'vault-mcp-project-v1';
  return Buffer.from(hkdfSync('sha256', ikm, Buffer.from(projectId, 'utf-8'), info, 32));
}

function encryptVault(key: Buffer, data: ProjectVaultData): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(data), 'utf-8'), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  // Layout: [IV 12B][ciphertext][auth-tag 16B]
  return Buffer.concat([iv, ct, tag]);
}

function decryptVault(key: Buffer, buf: Buffer): ProjectVaultData {
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf-8');
  return JSON.parse(plain) as ProjectVaultData;
}

// ─── I/O ──────────────────────────────────────────────────────────────────────

function vaultPath(projectDir: string, marker: VaultMarker): string {
  return marker.storage === 'committed'
    ? join(resolvePath(projectDir), COMMITTED_VAULT_FILENAME)
    : join(getProjectsDir(), `${marker.id}.vault`);
}

function totpSecretPath(projectId: string): string {
  return join(getProjectsDir(), `${projectId}.totp`);
}

function writeTotpSecret(projectId: string, secretBase32: string): void {
  ensureConfigDirs();
  writeFileSync(totpSecretPath(projectId), JSON.stringify({ secretBase32 }, null, 2), { mode: 0o600 });
}

function requireTotpSeed(projectId: string): string {
  const p = totpSecretPath(projectId);
  if (!existsSync(p)) {
    throw new Error(
      `This project vault requires a local TOTP seed that is missing on this machine (expected at ${p}). ` +
      'It cannot be decrypted here without it. If you backed up the seed (e.g. as an item in a Bitwarden vault), ' +
      'restore that JSON file to the path above. Otherwise the vault is unrecoverable — you would need to ' +
      'delete .vault-project(.enc) and start over.',
    );
  }
  const data = JSON.parse(readFileSync(p, 'utf-8')) as { secretBase32: string };
  return data.secretBase32;
}

function markerPath(projectDir: string): string {
  return join(resolvePath(projectDir), MARKER_FILENAME);
}

function normalizeMarker(raw: Partial<VaultMarker> & { id: string; name: string; createdAt: string }): VaultMarker {
  return {
    id: raw.id,
    name: raw.name,
    createdAt: raw.createdAt,
    storage: raw.storage === 'committed' ? 'committed' : 'external',
    totpEnabled: raw.totpEnabled === true,
  };
}

function readMarker(projectDir: string): VaultMarker | null {
  const p = markerPath(projectDir);
  if (!existsSync(p)) return null;
  return normalizeMarker(JSON.parse(readFileSync(p, 'utf-8')));
}

function writeMarker(projectDir: string, marker: VaultMarker): void {
  writeFileSync(markerPath(projectDir), JSON.stringify(marker, null, 2));
}

function requireMarker(projectDir: string): VaultMarker {
  const m = readMarker(projectDir);
  if (!m) throw new Error(`No project vault at "${projectDir}". Run vault_init_project first.`);
  return m;
}

function loadVault(masterKey: string, projectDir: string, marker: VaultMarker): ProjectVaultData {
  const p = vaultPath(projectDir, marker);
  if (!existsSync(p)) return { version: VAULT_VERSION, items: [] };
  const totpSeed = marker.totpEnabled ? requireTotpSeed(marker.id) : undefined;
  const key = deriveKey(masterKey, marker.id, totpSeed);
  return decryptVault(key, readFileSync(p));
}

function saveVault(masterKey: string, projectDir: string, marker: VaultMarker, data: ProjectVaultData): void {
  ensureConfigDirs();
  const totpSeed = marker.totpEnabled ? requireTotpSeed(marker.id) : undefined;
  const key = deriveKey(masterKey, marker.id, totpSeed);
  writeFileSync(vaultPath(projectDir, marker), encryptVault(key, data), { mode: 0o600 });
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function initProjectVault(
  masterKey: string, projectDir: string, name: string, opts: { commit?: boolean } = {},
): InitProjectResult {
  const existing = readMarker(projectDir);
  if (existing) return { marker: existing };

  const commit = opts.commit === true;
  const marker: VaultMarker = {
    id: crypto.randomUUID(),
    name,
    createdAt: new Date().toISOString(),
    storage: commit ? 'committed' : 'external',
    // Committed vaults are always TOTP-protected: the master key alone (which some
    // future clone of this machine's config could carry) is not sufficient once the
    // ciphertext itself is public.
    totpEnabled: commit,
  };

  let totpSeedBase32: string | undefined;
  if (commit) {
    totpSeedBase32 = generateTotpSecret();
    writeTotpSecret(marker.id, totpSeedBase32);
  }

  writeMarker(projectDir, marker);
  saveVault(masterKey, projectDir, marker, { version: VAULT_VERSION, items: [] });

  return totpSeedBase32
    ? { marker, totpSeedBase32, totpUri: totpUri(totpSeedBase32, name) }
    : { marker };
}

export function getProjectInfo(projectDir: string): VaultMarker | null {
  return readMarker(projectDir);
}

/** Upgrade an existing project vault (external or committed) to require a TOTP seed. */
export function enableTotp(masterKey: string, projectDir: string): EnableTotpResult {
  const marker = requireMarker(projectDir);
  if (marker.totpEnabled) throw new Error('TOTP is already enabled for this project vault.');

  const data = loadVault(masterKey, projectDir, marker); // decrypt under the old (no-TOTP) key
  const seed = generateTotpSecret();
  writeTotpSecret(marker.id, seed);

  const updated: VaultMarker = { ...marker, totpEnabled: true };
  saveVault(masterKey, projectDir, updated, data); // re-encrypt under the combined key
  writeMarker(projectDir, updated);

  return { totpSeedBase32: seed, totpUri: totpUri(seed, marker.name) };
}

/** Move an external vault's ciphertext into the project dir so it can be committed. Requires TOTP already on. */
export function enableCommitStorage(projectDir: string): void {
  const marker = requireMarker(projectDir);
  if (marker.storage === 'committed') return;
  if (!marker.totpEnabled) {
    throw new Error('Enable TOTP first (vault_project_totp_enable) — committed project vaults must be TOTP-protected.');
  }

  const oldPath = vaultPath(projectDir, marker);
  const updated: VaultMarker = { ...marker, storage: 'committed' };
  const newPath = vaultPath(projectDir, updated);

  const bytes = readFileSync(oldPath);
  writeFileSync(newPath, bytes, { mode: 0o600 });
  writeMarker(projectDir, updated);
  unlinkSync(oldPath);
}

export function listProjectItems(masterKey: string, projectDir: string): ProjectItemMeta[] {
  const marker = requireMarker(projectDir);
  return loadVault(masterKey, projectDir, marker).items.map(({ id, name, createdAt, updatedAt }) => ({
    id, name, createdAt, updatedAt,
  }));
}

export function createProjectItem(
  masterKey: string, projectDir: string, name: string, value: string,
): ProjectItemMeta {
  const marker = requireMarker(projectDir);
  const vault = loadVault(masterKey, projectDir, marker);

  if (vault.items.some(i => i.name === name)) {
    throw new Error(`Item "${name}" already exists. Use vault_project_update_item to change it.`);
  }

  const now = new Date().toISOString();
  const item: ProjectVaultItem = { id: crypto.randomUUID(), name, value, createdAt: now, updatedAt: now };
  vault.items.push(item);
  saveVault(masterKey, projectDir, marker, vault);
  return { id: item.id, name: item.name, createdAt: item.createdAt, updatedAt: item.updatedAt };
}

export function updateProjectItem(
  masterKey: string, projectDir: string, nameOrId: string, value: string,
): void {
  const marker = requireMarker(projectDir);
  const vault = loadVault(masterKey, projectDir, marker);
  const item = vault.items.find(i => i.id === nameOrId || i.name === nameOrId);
  if (!item) throw new Error(`Item "${nameOrId}" not found.`);
  item.value = value;
  item.updatedAt = new Date().toISOString();
  saveVault(masterKey, projectDir, marker, vault);
}

export function deleteProjectItem(masterKey: string, projectDir: string, nameOrId: string): void {
  const marker = requireMarker(projectDir);
  const vault = loadVault(masterKey, projectDir, marker);
  const idx = vault.items.findIndex(i => i.id === nameOrId || i.name === nameOrId);
  if (idx === -1) throw new Error(`Item "${nameOrId}" not found.`);
  vault.items.splice(idx, 1);
  saveVault(masterKey, projectDir, marker, vault);
}

export function resolveProjectValue(masterKey: string, projectDir: string, nameOrId: string): string {
  const marker = requireMarker(projectDir);
  const item = loadVault(masterKey, projectDir, marker).items.find(i => i.id === nameOrId || i.name === nameOrId);
  if (!item) throw new Error(`Item "${nameOrId}" not found.`);
  return item.value;
}
