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

export function ensureConfigDirs(): void {
  for (const dir of [getConfigDir(), getProjectsDir(), join(homedir(), '.cache', 'vault-mcp')]) {
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
