/**
 * Pre-push secret scanner. Looks for hardcoded credentials in a project directory
 * so they can be moved into a project vault (see project-vault.ts) and referenced
 * via {{placeholder}} instead of being committed in plaintext. Never returns the
 * raw matched value — findings are redacted, consistent with the rest of this
 * server's "secrets are never returned" contract.
 */

import { readFileSync, readdirSync, statSync } from 'fs';
import { join, relative, extname, basename } from 'path';
import { execFileSync } from 'child_process';

export interface SecretFinding {
  file: string;
  line: number;
  column: number;
  rule: string;
  confidence: 'high' | 'medium';
  redacted: string;
}

export interface ScanResult {
  scanned: number;
  usedGit: boolean;
  findings: SecretFinding[];
}

// ─── Pattern rules ──────────────────────────────────────────────────────────────

interface PatternRule {
  name: string;
  regex: RegExp;
  confidence: 'high' | 'medium';
}

const PATTERN_RULES: PatternRule[] = [
  { name: 'aws-access-key-id', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, confidence: 'high' },
  { name: 'github-token', regex: /\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g, confidence: 'high' },
  { name: 'slack-token', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, confidence: 'high' },
  { name: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, confidence: 'high' },
  { name: 'stripe-key', regex: /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b/g, confidence: 'high' },
  { name: 'openai-key', regex: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/g, confidence: 'high' },
  { name: 'private-key-block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g, confidence: 'high' },
];

// key="value" / key: 'value' where key looks like a credential name.
const GENERIC_ASSIGNMENT_RE =
  /(?:["'`]?[\w.-]*(?:pass(?:word)?|secret|token|api[_-]?key|auth|credential)[\w.-]*["'`]?)\s*[:=]\s*["'`]([^"'`\n]{8,})["'`]/gi;

const PLACEHOLDER_RE = /^\{\{.*\}\}$|^\$\{.*\}$/;
const FALSE_POSITIVE_RE =
  /changeme|change_me|example|placeholder|dummy|fake|xxx+|your[-_ ]?(?:api[-_ ]?)?key|your[-_ ]?token|todo|redacted|insert.*here|<.*>|\.\.\./i;

function isLikelyRealSecret(value: string): boolean {
  if (value.length < 12) return false;
  if (PLACEHOLDER_RE.test(value)) return false;
  if (value.includes('{{') || value.includes('${')) return false;
  if (FALSE_POSITIVE_RE.test(value)) return false;
  if (/^process\.env\./.test(value)) return false;
  const hasLetter = /[A-Za-z]/.test(value);
  const hasDigitOrSymbol = /[0-9!@#$%^&*()_+\-=[\]{};:,.<>/?]/.test(value);
  return hasLetter && hasDigitOrSymbol;
}

function redact(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}...${value.slice(-4)} (${value.length} chars)`;
}

function lineAndColumnOf(content: string, index: number): { line: number; column: number } {
  const before = content.slice(0, index);
  const line = before.split('\n').length;
  const lastNewline = before.lastIndexOf('\n');
  const column = index - lastNewline;
  return { line, column };
}

/** Scan raw file content for likely secrets. Pure function — no filesystem access. */
export function detectSecretsInContent(content: string): Omit<SecretFinding, 'file'>[] {
  const findings: Omit<SecretFinding, 'file'>[] = [];

  for (const rule of PATTERN_RULES) {
    rule.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.regex.exec(content)) !== null) {
      const { line, column } = lineAndColumnOf(content, m.index);
      findings.push({ line, column, rule: rule.name, confidence: rule.confidence, redacted: redact(m[0]) });
    }
  }

  GENERIC_ASSIGNMENT_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = GENERIC_ASSIGNMENT_RE.exec(content)) !== null) {
    const value = m[1];
    if (!isLikelyRealSecret(value)) continue;
    const valueIndex = m.index + m[0].lastIndexOf(value);
    const { line, column } = lineAndColumnOf(content, valueIndex);
    findings.push({ line, column, rule: 'generic-credential-assignment', confidence: 'medium', redacted: redact(value) });
  }

  return findings.sort((a, b) => a.line - b.line || a.column - b.column);
}

// ─── File discovery ─────────────────────────────────────────────────────────────

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'target', 'vendor', '.next', 'coverage']);
const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.woff', '.woff2', '.ttf', '.eot',
  '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3', '.wasm', '.map',
]);
const SKIP_BASENAMES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml']);
const MAX_FILE_BYTES = 2 * 1024 * 1024;

function runGit(dir: string, args: string[]): string[] {
  try {
    const out = execFileSync('git', args, { cwd: dir, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out.split('\n').map(s => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function listGitFiles(dir: string): string[] | null {
  const tracked = runGit(dir, ['ls-files']);
  const staged = runGit(dir, ['diff', '--cached', '--name-only', '--diff-filter=ACM']);
  const untracked = runGit(dir, ['ls-files', '--others', '--exclude-standard']);
  if (tracked.length === 0 && staged.length === 0 && untracked.length === 0) return null;
  return [...new Set([...tracked, ...staged, ...untracked])];
}

function walkDir(dir: string, root: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) {
      walkDir(full, root, acc);
    } else {
      acc.push(relative(root, full));
    }
  }
  return acc;
}

function isScannable(relPath: string): boolean {
  if (SKIP_EXTENSIONS.has(extname(relPath).toLowerCase())) return false;
  if (SKIP_BASENAMES.has(basename(relPath))) return false;
  return true;
}

/** Scan a directory for hardcoded secrets. Prefers git file listing (tracked + staged + untracked-but-not-ignored) so `.gitignore`d files are skipped; falls back to a plain directory walk outside git repos. */
export function scanForSecrets(dir: string): ScanResult {
  const gitFiles = listGitFiles(dir);
  const usedGit = gitFiles !== null;
  const relFiles = (gitFiles ?? walkDir(dir, dir)).filter(isScannable);

  const findings: SecretFinding[] = [];
  let scanned = 0;

  for (const relFile of relFiles) {
    const full = join(dir, relFile);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue; // e.g. a git-listed file deleted from the working tree
    }
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) continue;

    let content: string;
    try {
      content = readFileSync(full, 'utf-8');
    } catch {
      continue; // binary or unreadable
    }

    scanned++;
    for (const f of detectSecretsInContent(content)) {
      findings.push({ file: relFile, ...f });
    }
  }

  return { scanned, usedGit, findings };
}
