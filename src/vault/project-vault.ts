import {
  readFileSync, writeFileSync, existsSync, mkdirSync,
} from 'fs';
import { join, resolve as resolvePath } from 'path';
import { randomBytes, createCipheriv, createDecipheriv, hkdfSync } from 'crypto';
import { PROJECTS_DIR, ensureConfigDirs } from '../config/loader.js';

const MARKER_FILENAME = '.vault-project';
const VAULT_VERSION = 1 as const;

interface VaultMarker {
  id: string;
  name: string;
  createdAt: string;
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

// ─── Crypto ───────────────────────────────────────────────────────────────────

function deriveKey(masterKey: string, projectId: string): Buffer {
  return Buffer.from(
    hkdfSync('sha256', Buffer.from(masterKey, 'hex'), Buffer.from(projectId, 'utf-8'), 'vault-mcp-project-v1', 32),
  );
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

function vaultPath(projectId: string): string {
  return join(PROJECTS_DIR, `${projectId}.vault`);
}

function markerPath(projectDir: string): string {
  return join(resolvePath(projectDir), MARKER_FILENAME);
}

function readMarker(projectDir: string): VaultMarker | null {
  const p = markerPath(projectDir);
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf-8')) as VaultMarker;
}

function requireMarker(projectDir: string): VaultMarker {
  const m = readMarker(projectDir);
  if (!m) throw new Error(`No project vault at "${projectDir}". Run vault_init_project first.`);
  return m;
}

function loadVault(masterKey: string, projectId: string): ProjectVaultData {
  const p = vaultPath(projectId);
  if (!existsSync(p)) return { version: VAULT_VERSION, items: [] };
  const key = deriveKey(masterKey, projectId);
  return decryptVault(key, readFileSync(p));
}

function saveVault(masterKey: string, projectId: string, data: ProjectVaultData): void {
  ensureConfigDirs();
  const key = deriveKey(masterKey, projectId);
  writeFileSync(vaultPath(projectId), encryptVault(key, data), { mode: 0o600 });
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function initProjectVault(masterKey: string, projectDir: string, name: string): VaultMarker {
  const existing = readMarker(projectDir);
  if (existing) return existing;

  const marker: VaultMarker = {
    id: crypto.randomUUID(),
    name,
    createdAt: new Date().toISOString(),
  };

  writeFileSync(markerPath(projectDir), JSON.stringify(marker, null, 2));
  saveVault(masterKey, marker.id, { version: VAULT_VERSION, items: [] });
  return marker;
}

export function getProjectInfo(projectDir: string): VaultMarker | null {
  return readMarker(projectDir);
}

export function listProjectItems(masterKey: string, projectDir: string): ProjectItemMeta[] {
  const { id } = requireMarker(projectDir);
  return loadVault(masterKey, id).items.map(({ id, name, createdAt, updatedAt }) => ({
    id, name, createdAt, updatedAt,
  }));
}

export function createProjectItem(
  masterKey: string, projectDir: string, name: string, value: string,
): ProjectItemMeta {
  const { id: pid } = requireMarker(projectDir);
  const vault = loadVault(masterKey, pid);

  if (vault.items.some(i => i.name === name)) {
    throw new Error(`Item "${name}" already exists. Use vault_project_update_item to change it.`);
  }

  const now = new Date().toISOString();
  const item: ProjectVaultItem = { id: crypto.randomUUID(), name, value, createdAt: now, updatedAt: now };
  vault.items.push(item);
  saveVault(masterKey, pid, vault);
  return { id: item.id, name: item.name, createdAt: item.createdAt, updatedAt: item.updatedAt };
}

export function updateProjectItem(
  masterKey: string, projectDir: string, nameOrId: string, value: string,
): void {
  const { id: pid } = requireMarker(projectDir);
  const vault = loadVault(masterKey, pid);
  const item = vault.items.find(i => i.id === nameOrId || i.name === nameOrId);
  if (!item) throw new Error(`Item "${nameOrId}" not found.`);
  item.value = value;
  item.updatedAt = new Date().toISOString();
  saveVault(masterKey, pid, vault);
}

export function deleteProjectItem(masterKey: string, projectDir: string, nameOrId: string): void {
  const { id: pid } = requireMarker(projectDir);
  const vault = loadVault(masterKey, pid);
  const idx = vault.items.findIndex(i => i.id === nameOrId || i.name === nameOrId);
  if (idx === -1) throw new Error(`Item "${nameOrId}" not found.`);
  vault.items.splice(idx, 1);
  saveVault(masterKey, pid, vault);
}

export function resolveProjectValue(masterKey: string, projectDir: string, nameOrId: string): string {
  const { id: pid } = requireMarker(projectDir);
  const item = loadVault(masterKey, pid).items.find(i => i.id === nameOrId || i.name === nameOrId);
  if (!item) throw new Error(`Item "${nameOrId}" not found.`);
  return item.value;
}
