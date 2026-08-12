import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { randomBytes } from 'crypto';
import type { Config } from './types.js';

export const CONFIG_DIR = join(homedir(), '.config', 'vault-mcp');
export const CONFIG_FILE = join(CONFIG_DIR, 'config.json');
export const PROJECTS_DIR = join(CONFIG_DIR, 'projects');

export function ensureConfigDirs(): void {
  for (const dir of [CONFIG_DIR, PROJECTS_DIR, join(homedir(), '.cache', 'vault-mcp')]) {
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

export function loadConfig(): Config {
  ensureConfigDirs();

  if (!existsSync(CONFIG_FILE)) {
    const fresh: Config = {
      version: 1,
      masterKey: randomBytes(32).toString('hex'),
      vaults: {},
    };
    saveConfig(fresh);
    return fresh;
  }

  return JSON.parse(readFileSync(CONFIG_FILE, 'utf-8')) as Config;
}

export function saveConfig(config: Config): void {
  ensureConfigDirs();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), { mode: 0o600 });
  chmodSync(CONFIG_FILE, 0o600);
}
