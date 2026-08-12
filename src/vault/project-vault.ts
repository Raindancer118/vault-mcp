/**
 * Local, per-project secret store — deliberately unrelated to any Bitwarden/
 * Vaultwarden vault. It never mirrors, syncs, or exports a remote vault: items
 * only ever get in here one at a time, via an explicit vault_project_create_item
 * call, and are meant to hold ONLY the handful of secrets a given repo actually
 * needs at runtime (an API key for CI, a deploy token, ...). A full Bitwarden/
 * Vaultwarden vault (personal or org) must NEVER be committed or pushed — if you
 * need something from one, copy just that one value across via create_item.
 */

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
  /** Only present when the vault was just created as committed. Shown once — back both up now. */
  totpSeedBase32?: string;
  totpUri?: string;
  vaultKeyHex?: string;
}

export interface EnableTotpResult {
  totpSeedBase32: string;
  totpUri: string;
}

export interface EnableCommitResult {
  vaultKeyHex: string;
}

// ─── Crypto ───────────────────────────────────────────────────────────────────

/**
 * External storage (default, not committed): unchanged from before.
 * With no TOTP seed: v1 scheme (shared per-machine master key only).
 * With a TOTP seed (enableTotp on an external vault): the seed is folded into the
 * HKDF input keying material alongside the master key, under a distinct info string.
 */
function deriveKey(masterKey: string, projectId: string, totpSeedBase32?: string): Buffer {
  const ikm = totpSeedBase32
    ? Buffer.concat([Buffer.from(masterKey, 'hex'), Buffer.from(totpSeedBase32, 'utf-8')])
    : Buffer.from(masterKey, 'hex');
  const info = totpSeedBase32 ? 'vault-mcp-project-v2-totp' : 'vault-mcp-project-v1';
  return Buffer.from(hkdfSync('sha256', ikm, Buffer.from(projectId, 'utf-8'), info, 32));
}

/**
 * Committed storage: intentionally does NOT use the shared per-machine master key at
 * all. Instead a dedicated, single-purpose, high-entropy "vault key" (512 bits,
 * generated once per project) plus the TOTP seed are both required and both folded
 * into the HKDF input keying material. This decouples a pushed vault's security from
 * the master key entirely — leaking the master key (which every vault on this machine
 * shares) has zero effect on a committed vault, and either the vault key or the TOTP
 * seed alone is still insufficient. Both files stay local, never touch the repo, and
 * both are handed back once (at creation / enableCommitStorage) for backup.
 */
function deriveCommittedKey(vaultKeyHex: string, projectId: string, totpSeedBase32: string): Buffer {
  const ikm = Buffer.concat([Buffer.from(vaultKeyHex, 'hex'), Buffer.from(totpSeedBase32, 'utf-8')]);
  return Buffer.from(hkdfSync('sha256', ikm, Buffer.from(projectId, 'utf-8'), 'vault-mcp-project-v3-committed', 32));
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

function vaultKeyFilePath(projectId: string): string {
  return join(getProjectsDir(), `${projectId}.key`);
}

function generateVaultKey(): string {
  return randomBytes(64).toString('hex'); // 512 bits — deliberately independent of and much larger than the shared master key.
}

function writeVaultKey(projectId: string, vaultKeyHex: string): void {
  ensureConfigDirs();
  writeFileSync(vaultKeyFilePath(projectId), JSON.stringify({ vaultKeyHex }, null, 2), { mode: 0o600 });
}

function requireVaultKey(projectId: string): string {
  const p = vaultKeyFilePath(projectId);
  if (!existsSync(p)) {
    throw new Error(
      `This committed project vault requires a local dedicated vault key that is missing on this machine ` +
      `(expected at ${p}). It cannot be decrypted here without it — the shared master key is not sufficient ` +
      'for committed vaults by design. If you backed up the key (e.g. as an item in a Bitwarden vault), restore ' +
      'that JSON file to the path above. Otherwise the vault is unrecoverable — you would need to delete ' +
      '.vault-project(.enc) and start over.',
    );
  }
  const data = JSON.parse(readFileSync(p, 'utf-8')) as { vaultKeyHex: string };
  return data.vaultKeyHex;
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

/**
 * Picks the right key derivation for a marker's storage mode. Committed vaults are
 * fully independent of `masterKey` — it is accepted for a uniform call signature
 * across both storage modes but simply unused once storage === 'committed'.
 */
function deriveKeyForMarker(masterKey: string, marker: VaultMarker): Buffer {
  if (marker.storage === 'committed') {
    const vaultKeyHex = requireVaultKey(marker.id);
    const totpSeed = requireTotpSeed(marker.id); // committed always implies totpEnabled
    return deriveCommittedKey(vaultKeyHex, marker.id, totpSeed);
  }
  const totpSeed = marker.totpEnabled ? requireTotpSeed(marker.id) : undefined;
  return deriveKey(masterKey, marker.id, totpSeed);
}

function loadVault(masterKey: string, projectDir: string, marker: VaultMarker): ProjectVaultData {
  const p = vaultPath(projectDir, marker);
  if (!existsSync(p)) return { version: VAULT_VERSION, items: [] };
  const key = deriveKeyForMarker(masterKey, marker);
  return decryptVault(key, readFileSync(p));
}

function saveVault(masterKey: string, projectDir: string, marker: VaultMarker, data: ProjectVaultData): void {
  ensureConfigDirs();
  const key = deriveKeyForMarker(masterKey, marker);
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
  let vaultKeyHex: string | undefined;
  if (commit) {
    totpSeedBase32 = generateTotpSecret();
    writeTotpSecret(marker.id, totpSeedBase32);
    vaultKeyHex = generateVaultKey();
    writeVaultKey(marker.id, vaultKeyHex);
  }

  writeMarker(projectDir, marker);
  saveVault(masterKey, projectDir, marker, { version: VAULT_VERSION, items: [] });

  return totpSeedBase32 && vaultKeyHex
    ? { marker, totpSeedBase32, totpUri: totpUri(totpSeedBase32, name), vaultKeyHex }
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

/**
 * Move an external vault's ciphertext into the project dir so it can be committed.
 * Requires TOTP already on. Mints a brand-new dedicated vault key and re-encrypts
 * under the committed scheme (vault key + TOTP seed, independent of the master key)
 * — the old external-scheme ciphertext (tied to the shared master key) is never
 * itself pushed; only the freshly re-encrypted bytes are.
 */
export function enableCommitStorage(masterKey: string, projectDir: string): EnableCommitResult {
  const marker = requireMarker(projectDir);
  if (marker.storage === 'committed') throw new Error('This project vault is already using committed storage.');
  if (!marker.totpEnabled) {
    throw new Error('Enable TOTP first (vault_project_totp_enable) — committed project vaults must be TOTP-protected.');
  }

  const data = loadVault(masterKey, projectDir, marker); // decrypt under the old external (master-key-based) scheme
  const oldPath = vaultPath(projectDir, marker);

  const vaultKeyHex = generateVaultKey();
  writeVaultKey(marker.id, vaultKeyHex);

  const updated: VaultMarker = { ...marker, storage: 'committed' };
  saveVault(masterKey, projectDir, updated, data); // re-encrypt under the new committed scheme
  writeMarker(projectDir, updated);
  unlinkSync(oldPath);

  return { vaultKeyHex };
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
