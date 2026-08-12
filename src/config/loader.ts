import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes } from 'crypto';
import type { Config } from './types.js';

// Read live (not cached at import time) so tests can redirect all local, never-committed
// vault-mcp state (master key, project vaults, TOTP seeds) into an isolated temp dir via
// VAULT_MCP_CONFIG_DIR without touching the real user config.
export function getConfigDir(): string {
  return process.env.VAULT_MCP_CONFIG_DIR ?? join(homedir(), '.config', 'vault-mcp');
}
export function getConfigFile(): string {
  return join(getConfigDir(), 'config.json');
}
export function getProjectsDir(): string {
  return join(getConfigDir(), 'projects');
}

/**
 * Secondary, redundant local-only backup location for committed-project-vault secrets
 * (dedicated vault key + TOTP seed) — never in the repo, never synced anywhere. Lives
 * under Claude Code's own per-user config dir rather than a password manager note, so
 * a committed vault keeps decrypting automatically on this machine even if
 * ~/.config/vault-mcp/projects gets wiped (e.g. a config reset). Override via
 * VAULT_MCP_CLAUDE_DIR for tests, same pattern as VAULT_MCP_CONFIG_DIR.
 */
export function getClaudeBackupsDir(): string {
  return join(process.env.VAULT_MCP_CLAUDE_DIR ?? join(homedir(), '.claude'), 'vault-mcp-backups');
}

export function ensureConfigDirs(): void {
  for (const dir of [getConfigDir(), getProjectsDir(), getClaudeBackupsDir(), join(homedir(), '.cache', 'vault-mcp')]) {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

export function loadConfig(): Config {
  ensureConfigDirs();
  const configFile = getConfigFile();

  if (!existsSync(configFile)) {
    const fresh: Config = {
      version: 1,
      masterKey: randomBytes(32).toString('hex'),
      vaults: {},
    };
    saveConfig(fresh);
    return fresh;
  }

  return JSON.parse(readFileSync(configFile, 'utf-8')) as Config;
}

export function saveConfig(config: Config): void {
  ensureConfigDirs();
  const configFile = getConfigFile();
  writeFileSync(configFile, JSON.stringify(config, null, 2), { mode: 0o600 });
  chmodSync(configFile, 0o600);
}
