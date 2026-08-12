import { appendFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CACHE_DIR = join(homedir(), '.cache', 'vault-mcp');
const AUDIT_LOG = join(CACHE_DIR, 'audit.log');

function ensureDir(): void {
  if (!existsSync(CACHE_DIR)) mkdirSync(CACHE_DIR, { recursive: true, mode: 0o700 });
}

/**
 * Record a secret access event. NEVER include secret values in any parameter.
 */
export function auditLog(
  action: string,
  vault: string,
  item?: string,
  details?: Record<string, string>,
): void {
  ensureDir();
  const entry = {
    ts: new Date().toISOString(),
    action,
    vault,
    item: item ?? null,
    ...(details ?? {}),
  };
  appendFileSync(AUDIT_LOG, JSON.stringify(entry) + '\n');
}
