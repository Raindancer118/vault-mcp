import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { execFileSync } from 'child_process';
import { detectSecretsInContent, scanForSecrets } from './secret-scan.js';

describe('detectSecretsInContent — pattern rules', () => {
  it('flags an AWS access key ID', () => {
    const findings = detectSecretsInContent('const key = "AKIAIOSFODNN7EXAMPLE";');
    expect(findings.some(f => f.rule === 'aws-access-key-id')).toBe(true);
  });

  it('flags a GitHub personal access token', () => {
    const findings = detectSecretsInContent('TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz');
    expect(findings.some(f => f.rule === 'github-token')).toBe(true);
  });

  it('flags a Slack bot token', () => {
    const findings = detectSecretsInContent('slack: "xoxb-1234567890-abcdefghijklmnop"');
    expect(findings.some(f => f.rule === 'slack-token')).toBe(true);
  });

  it('flags an OpenAI-style API key', () => {
    const findings = detectSecretsInContent('OPENAI_API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"');
    expect(findings.some(f => f.rule === 'openai-key')).toBe(true);
  });

  it('flags a PEM private key block', () => {
    const findings = detectSecretsInContent('-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----');
    expect(findings.some(f => f.rule === 'private-key-block')).toBe(true);
  });

  it('flags a generic hardcoded password/secret assignment', () => {
    const findings = detectSecretsInContent('const npmpass = "Tr0ub4dor&3xyz9";');
    expect(findings.some(f => f.rule === 'generic-credential-assignment')).toBe(true);
  });

  it('flags a secret embedded in a larger JSON body literal', () => {
    const findings = detectSecretsInContent('const body = \'{"identity":"me","secret":"Tr0ub4dor&3xyz9"}\';');
    expect(findings.some(f => f.rule === 'generic-credential-assignment')).toBe(true);
  });

  it('redacts the matched value in the finding', () => {
    const findings = detectSecretsInContent('const npmpass = "Tr0ub4dor&3xyz9";');
    expect(findings[0].redacted).not.toContain('Tr0ub4dor&3xyz9');
    expect(findings[0].redacted).toMatch(/\.\.\./);
  });

  it('reports 1-based line and column numbers', () => {
    const findings = detectSecretsInContent('line one\nconst npmpass = "Tr0ub4dor&3xyz9";');
    expect(findings[0].line).toBe(2);
    expect(findings[0].column).toBeGreaterThan(0);
  });

  it('does not flag a {{placeholder}} reference', () => {
    const findings = detectSecretsInContent('headers: { Authorization: "Bearer {{GROQ_KEY}}" }');
    expect(findings).toHaveLength(0);
  });

  it('does not flag a ${placeholder} reference', () => {
    const findings = detectSecretsInContent('const token = "${API_TOKEN}";');
    expect(findings).toHaveLength(0);
  });

  it('does not flag process.env access', () => {
    const findings = detectSecretsInContent('const token = process.env.API_TOKEN;');
    expect(findings).toHaveLength(0);
  });

  it('does not flag obvious placeholder/example values', () => {
    const findings = detectSecretsInContent([
      'const password = "changeme";',
      'const apiKey = "your-api-key-here";',
      'const token = "example-token";',
      'const secret = "<insert-secret-here>";',
    ].join('\n'));
    expect(findings).toHaveLength(0);
  });

  it('does not flag short or low-entropy values', () => {
    const findings = detectSecretsInContent('const password = "short";');
    expect(findings).toHaveLength(0);
  });

  it('does not flag mentions of the words secret/token/password without an assigned literal', () => {
    const findings = detectSecretsInContent([
      '/** Secrets are fetched, used in-memory, and never returned to the caller. */',
      'export type Resolver = (nameOrId: string) => Promise<string>;',
      'secretRefs: Record<string, string>;',
    ].join('\n'));
    expect(findings).toHaveLength(0);
  });
});

describe('scanForSecrets — directory scanning', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vault-mcp-secret-scan-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('finds a hardcoded secret in a tracked git file and skips ignored files', () => {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    writeFileSync(join(dir, '.gitignore'), 'ignored.js\n');
    writeFileSync(join(dir, 'app.js'), 'const npmpass = "Tr0ub4dor&3xyz9";');
    writeFileSync(join(dir, 'ignored.js'), 'const npmpass = "Tr0ub4dor&3xyz9";');
    execFileSync('git', ['add', 'app.js', '.gitignore'], { cwd: dir });

    const result = scanForSecrets(dir);

    expect(result.usedGit).toBe(true);
    expect(result.findings.some(f => f.file === 'app.js')).toBe(true);
    expect(result.findings.some(f => f.file === 'ignored.js')).toBe(false);
  });

  it('skips node_modules and dist even without git', () => {
    mkdirSync(join(dir, 'node_modules'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'dep.js'), 'const npmpass = "Tr0ub4dor&3xyz9";');
    mkdirSync(join(dir, 'dist'), { recursive: true });
    writeFileSync(join(dir, 'dist', 'out.js'), 'const npmpass = "Tr0ub4dor&3xyz9";');
    writeFileSync(join(dir, 'app.js'), 'const npmpass = "Tr0ub4dor&3xyz9";');

    const result = scanForSecrets(dir);

    expect(result.usedGit).toBe(false);
    expect(result.findings.map(f => f.file)).toEqual(['app.js']);
  });

  it('finds nothing in a clean project', () => {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    writeFileSync(join(dir, 'app.js'), 'const token = process.env.API_TOKEN;');
    execFileSync('git', ['add', 'app.js'], { cwd: dir });

    const result = scanForSecrets(dir);
    expect(result.findings).toHaveLength(0);
  });
});

describe('scanForSecrets — regression against this repo', () => {
  it('finds zero findings in this project\'s own application code (test fixtures deliberately contain fake secrets and are excluded)', () => {
    const projectRoot = join(__dirname, '..', '..');
    const result = scanForSecrets(join(projectRoot, 'src'));
    const nonFixtureFindings = result.findings.filter(f => !f.file.endsWith('.test.ts'));
    if (nonFixtureFindings.length > 0) {
      // eslint-disable-next-line no-console
      console.error('Unexpected findings in own source tree:', nonFixtureFindings);
    }
    expect(nonFixtureFindings).toHaveLength(0);
  });
});
