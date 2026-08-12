import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { randomBytes } from 'crypto';
import {
  initProjectVault, getProjectInfo, listProjectItems, createProjectItem,
  updateProjectItem, deleteProjectItem, resolveProjectValue,
  enableTotp, enableCommitStorage,
} from './project-vault.js';
import { getProjectsDir, getClaudeBackupsDir } from '../config/loader.js';

const MASTER_KEY = randomBytes(32).toString('hex');
const OTHER_MASTER_KEY = randomBytes(32).toString('hex');

describe('project-vault', () => {
  let configDir: string;
  let claudeDir: string;
  let projectDir: string;

  beforeEach(() => {
    configDir = mkdtempSync(join(tmpdir(), 'vault-mcp-config-'));
    claudeDir = mkdtempSync(join(tmpdir(), 'vault-mcp-claude-'));
    projectDir = mkdtempSync(join(tmpdir(), 'vault-mcp-project-'));
    process.env.VAULT_MCP_CONFIG_DIR = configDir;
    process.env.VAULT_MCP_CLAUDE_DIR = claudeDir;
  });

  afterEach(() => {
    delete process.env.VAULT_MCP_CONFIG_DIR;
    delete process.env.VAULT_MCP_CLAUDE_DIR;
    rmSync(configDir, { recursive: true, force: true });
    rmSync(claudeDir, { recursive: true, force: true });
    rmSync(projectDir, { recursive: true, force: true });
  });

  describe('external storage (default, unchanged behaviour)', () => {
    it('stores the vault outside the project dir and requires no TOTP', () => {
      const { marker, totpSeedBase32, vaultKeyHex } = initProjectVault(MASTER_KEY, projectDir, 'demo');
      expect(marker.storage).toBe('external');
      expect(marker.totpEnabled).toBe(false);
      expect(totpSeedBase32).toBeUndefined();
      expect(vaultKeyHex).toBeUndefined();
      expect(existsSync(join(projectDir, '.vault-project.enc'))).toBe(false);
      expect(existsSync(join(getProjectsDir(), `${marker.id}.vault`))).toBe(true);
    });

    it('supports full CRUD without a TOTP code', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo');
      const created = createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      expect(listProjectItems(MASTER_KEY, projectDir).map(i => i.name)).toEqual(['npmpass']);
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
      updateProjectItem(MASTER_KEY, projectDir, created.id, 'new-value');
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('new-value');
      deleteProjectItem(MASTER_KEY, projectDir, created.id);
      expect(listProjectItems(MASTER_KEY, projectDir)).toHaveLength(0);
    });
  });

  describe('committed storage (commit: true) — dedicated vault key + TOTP, independent of the shared master key', () => {
    it('writes the encrypted vault inside the project dir, forces TOTP on, and hands out a dedicated 512-bit vault key', () => {
      const { marker, totpSeedBase32, totpUri, vaultKeyHex } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      expect(marker.storage).toBe('committed');
      expect(marker.totpEnabled).toBe(true);
      expect(totpSeedBase32).toMatch(/^[A-Z2-7]+$/);
      expect(totpUri).toContain('otpauth://totp/');
      expect(vaultKeyHex).toMatch(/^[0-9a-f]{128}$/); // 64 bytes = 512 bits
      expect(existsSync(join(projectDir, '.vault-project.enc'))).toBe(true);
      expect(existsSync(join(getProjectsDir(), `${marker.id}.vault`))).toBe(false);
    });

    it('never writes the TOTP seed or the vault key anywhere under the project dir', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      const projectFiles = [join(projectDir, '.vault-project'), join(projectDir, '.vault-project.enc')];
      for (const f of projectFiles) {
        const content = readFileSync(f, 'utf-8');
        expect(content).not.toMatch(/[A-Z2-7]{20,}/); // no base32 TOTP seed
        expect(content).not.toMatch(/[0-9a-f]{100,}/); // no hex vault key
      }
    });

    it('supports full CRUD transparently, reading the local TOTP seed and vault key automatically', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
    });

    it('is completely independent of the machine master key — decrypts fine even with a totally different one', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      expect(resolveProjectValue(OTHER_MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
      createProjectItem(OTHER_MASTER_KEY, projectDir, 'second', 'another-value');
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'second')).toBe('another-value');
    });

    it('throws a clear error when both the primary and the ~/.claude backup TOTP seed are missing', () => {
      const { marker } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      rmSync(join(getProjectsDir(), `${marker.id}.totp`));
      rmSync(join(getClaudeBackupsDir(), `${marker.id}.json`));
      expect(() => resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toThrow(/TOTP seed/);
    });

    it('throws a clear error when both the primary and the ~/.claude backup vault key are missing', () => {
      const { marker } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      rmSync(join(getProjectsDir(), `${marker.id}.key`));
      rmSync(join(getClaudeBackupsDir(), `${marker.id}.json`));
      expect(() => resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toThrow(/vault key/);
    });

    it('cannot be decrypted with the master key alone if both TOTP seed copies are missing (master key plays no role here at all)', () => {
      const { marker } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      rmSync(join(getProjectsDir(), `${marker.id}.totp`));
      rmSync(join(getClaudeBackupsDir(), `${marker.id}.json`));
      expect(() => listProjectItems(MASTER_KEY, projectDir)).toThrow();
    });

    it('cannot be decrypted with only the TOTP seed if both vault key copies are missing', () => {
      const { marker } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      rmSync(join(getProjectsDir(), `${marker.id}.key`));
      rmSync(join(getClaudeBackupsDir(), `${marker.id}.json`));
      expect(() => listProjectItems(MASTER_KEY, projectDir)).toThrow();
    });
  });

  describe('automatic ~/.claude backup + fallback restore for committed vaults', () => {
    it('writes a redundant backup of both secrets under ~/.claude on init', () => {
      const { marker, totpSeedBase32, vaultKeyHex } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      const backupPath = join(getClaudeBackupsDir(), `${marker.id}.json`);
      expect(existsSync(backupPath)).toBe(true);
      const backup = JSON.parse(readFileSync(backupPath, 'utf-8'));
      expect(backup.totpSeedBase32).toBe(totpSeedBase32);
      expect(backup.vaultKeyHex).toBe(vaultKeyHex);
    });

    it('falls back to the ~/.claude backup and keeps working when the primary vault key file is wiped', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      const marker = getProjectInfo(projectDir)!;
      rmSync(join(getProjectsDir(), `${marker.id}.key`));
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
    });

    it('falls back to the ~/.claude backup and keeps working when the primary TOTP seed file is wiped', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      const marker = getProjectInfo(projectDir)!;
      rmSync(join(getProjectsDir(), `${marker.id}.totp`));
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
    });

    it('still works when the entire primary vault-mcp config dir is wiped, restoring both files transparently', () => {
      const { marker } = initProjectVault(MASTER_KEY, projectDir, 'demo', { commit: true });
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      rmSync(join(getProjectsDir(), `${marker.id}.key`));
      rmSync(join(getProjectsDir(), `${marker.id}.totp`));

      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
      // Using the backup should also have restored the primary copies for next time.
      expect(existsSync(join(getProjectsDir(), `${marker.id}.key`))).toBe(true);
      expect(existsSync(join(getProjectsDir(), `${marker.id}.totp`))).toBe(true);
    });

    it('writes a fresh ~/.claude backup when enableCommitStorage mints a new vault key', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo');
      enableTotp(MASTER_KEY, projectDir);
      const { vaultKeyHex } = enableCommitStorage(MASTER_KEY, projectDir);
      const marker = getProjectInfo(projectDir)!;
      const backup = JSON.parse(readFileSync(join(getClaudeBackupsDir(), `${marker.id}.json`), 'utf-8'));
      expect(backup.vaultKeyHex).toBe(vaultKeyHex);
    });
  });

  describe('enableTotp — upgrading an existing external vault', () => {
    it('adds a TOTP seed and keeps existing items readable afterwards', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo');
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');

      const { totpSeedBase32 } = enableTotp(MASTER_KEY, projectDir);
      expect(totpSeedBase32).toMatch(/^[A-Z2-7]+$/);

      const info = getProjectInfo(projectDir)!;
      expect(info.totpEnabled).toBe(true);
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
    });

    it('refuses to enable TOTP twice', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo');
      enableTotp(MASTER_KEY, projectDir);
      expect(() => enableTotp(MASTER_KEY, projectDir)).toThrow(/already enabled/);
    });
  });

  describe('enableCommitStorage — moving an external vault into the repo, minting a dedicated vault key', () => {
    it('requires TOTP to already be enabled', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo');
      expect(() => enableCommitStorage(MASTER_KEY, projectDir)).toThrow(/TOTP/);
    });

    it('moves the ciphertext into the project dir once TOTP is enabled, mints a vault key, and preserves items', () => {
      const { marker } = initProjectVault(MASTER_KEY, projectDir, 'demo');
      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      enableTotp(MASTER_KEY, projectDir);

      const { vaultKeyHex } = enableCommitStorage(MASTER_KEY, projectDir);

      expect(vaultKeyHex).toMatch(/^[0-9a-f]{128}$/);
      const info = getProjectInfo(projectDir)!;
      expect(info.storage).toBe('committed');
      expect(existsSync(join(projectDir, '.vault-project.enc'))).toBe(true);
      expect(existsSync(join(getProjectsDir(), `${marker.id}.vault`))).toBe(false);
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
      // Now fully independent of the master key, same as a from-the-start committed vault.
      expect(resolveProjectValue(OTHER_MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
    });

    it('refuses to run twice on an already-committed vault', () => {
      initProjectVault(MASTER_KEY, projectDir, 'demo');
      enableTotp(MASTER_KEY, projectDir);
      enableCommitStorage(MASTER_KEY, projectDir);
      expect(() => enableCommitStorage(MASTER_KEY, projectDir)).toThrow(/already/i);
    });
  });

  describe('backward compatibility with pre-existing (legacy) markers', () => {
    it('treats a marker without storage/totpEnabled fields as external, non-TOTP', () => {
      const legacyMarker = { id: crypto.randomUUID(), name: 'legacy', createdAt: new Date().toISOString() };
      writeFileSync(join(projectDir, '.vault-project'), JSON.stringify(legacyMarker, null, 2));

      const info = getProjectInfo(projectDir)!;
      expect(info.storage).toBe('external');
      expect(info.totpEnabled).toBe(false);

      createProjectItem(MASTER_KEY, projectDir, 'npmpass', 's3cr3t-value');
      expect(resolveProjectValue(MASTER_KEY, projectDir, 'npmpass')).toBe('s3cr3t-value');
    });
  });
});
