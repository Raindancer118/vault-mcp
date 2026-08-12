import { describe, it, expect } from 'vitest';
import { parseLaunchArgs } from './launch.js';

describe('parseLaunchArgs', () => {
  it('parses vault, env and arg flags plus the child command after "--"', () => {
    const p = parseLaunchArgs([
      '--vault', 'nak',
      '--env', 'CIS_USER=nordakademie.de:username',
      '--env', 'CIS_PASS=nordakademie.de:password',
      '--', '/abs/cis', 'mcp',
    ]);
    expect(p.vault).toBe('nak');
    expect(p.envMappings).toEqual({
      CIS_USER: 'nordakademie.de:username',
      CIS_PASS: 'nordakademie.de:password',
    });
    expect(p.argRefs).toEqual({});
    expect(p.command).toEqual(['/abs/cis', 'mcp']);
  });

  it('keeps only the first "=" as the separator so refs may contain "="', () => {
    const p = parseLaunchArgs(['--env', 'TOKEN=Item:field=weird', '--', 'srv']);
    expect(p.envMappings).toEqual({ TOKEN: 'Item:field=weird' });
  });

  it('supports --arg placeholder substitution refs', () => {
    const p = parseLaunchArgs(['--arg', '{{PW}}=My Login', '--', 'tool', '--pass', '{{PW}}']);
    expect(p.argRefs).toEqual({ '{{PW}}': 'My Login' });
    expect(p.command).toEqual(['tool', '--pass', '{{PW}}']);
  });

  it('defaults vault to undefined when --vault is omitted', () => {
    const p = parseLaunchArgs(['--env', 'A=B', '--', 'x']);
    expect(p.vault).toBeUndefined();
  });

  it('treats everything after "--" as the verbatim child command, even flag-like args', () => {
    const p = parseLaunchArgs(['--', 'node', 'server.js', '--vault', '--env']);
    expect(p.command).toEqual(['node', 'server.js', '--vault', '--env']);
    expect(p.envMappings).toEqual({});
  });

  it('throws when no child command is given', () => {
    expect(() => parseLaunchArgs(['--vault', 'nak'])).toThrow(/No child command/);
    expect(() => parseLaunchArgs(['--vault', 'nak', '--'])).toThrow(/No child command/);
  });

  it('throws on a malformed --env pair', () => {
    expect(() => parseLaunchArgs(['--env', 'NOEQUALS', '--', 'x'])).toThrow(/NAME=ItemRef/);
    expect(() => parseLaunchArgs(['--env', '=novar', '--', 'x'])).toThrow(/NAME=ItemRef/);
  });

  it('throws on an unknown flag before "--"', () => {
    expect(() => parseLaunchArgs(['--bogus', '--', 'x'])).toThrow(/Unknown launch flag/);
  });
});
