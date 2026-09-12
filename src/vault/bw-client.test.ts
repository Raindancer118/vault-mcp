import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

// bw-client shells out via child_process.execFile (wrapped with util.promisify) and
// child_process.exec. Mock both with the callback signature promisify expects.
const execFileMock = vi.fn();
const execMock = vi.fn();

vi.mock('child_process', () => ({
  execFile: (...args: unknown[]) => (execFileMock as any)(...args),
  exec: (...args: unknown[]) => (execMock as any)(...args),
}));

function cb(stdout: string) {
  return (_file: string, _args: string[], _opts: unknown, callback: (err: unknown, r: { stdout: string; stderr: string }) => void) => {
    callback(null, { stdout, stderr: '' });
  };
}

function cbFail(message: string) {
  return (_file: string, _args: string[], _opts: unknown, callback: (err: unknown) => void) => {
    callback(Object.assign(new Error(message), { stderr: message, stdout: '' }));
  };
}

describe('BitwardenClient.getRawItem', () => {
  let tmpHome: string;

  beforeEach(() => {
    execFileMock.mockReset();
    execMock.mockReset();
    tmpHome = mkdtempSync(join(tmpdir(), 'vault-mcp-test-'));
    vi.spyOn(require('os'), 'homedir').mockReturnValue(tmpHome);
  });

  it('retries after a sync when "bw get item" reports Not found, and succeeds if the retry finds it', async () => {
    const { BitwardenClient } = await import('./bw-client.js');
    const client = new BitwardenClient('testvault', {
      url: 'https://vault.example.com',
      clientId: 'id',
      clientSecret: 'secret',
      masterPassword: 'pw',
    } as any);

    // Force an already-valid in-memory session so ensureSession() short-circuits.
    (client as any).sessionToken = 'session-token';
    (client as any).sessionExpiry = Date.now() + 60_000;

    const item = { id: 'abc-123', name: 'Test Item', type: 1, login: { username: 'u', password: 'p' } };

    let getItemCalls = 0;
    execFileMock.mockImplementation((_file: string, args: string[], _opts: unknown, callback: (err: unknown, r?: { stdout: string; stderr: string }) => void) => {
      if (args.includes('get') && args.includes('item')) {
        getItemCalls++;
        if (getItemCalls === 1) {
          callback(Object.assign(new Error('Not found.'), { stderr: 'Not found.', stdout: '' }));
          return;
        }
        callback(null, { stdout: JSON.stringify(item), stderr: '' });
        return;
      }
      if (args.includes('sync')) {
        callback(null, { stdout: '', stderr: '' });
        return;
      }
      callback(null, { stdout: '{}', stderr: '' });
    });

    const result = await (client as any).getRawItem('abc-123');

    expect(result).toEqual(item);
    expect(getItemCalls).toBe(2); // first attempt failed, retry after sync succeeded
    const syncCalled = execFileMock.mock.calls.some(c => (c[1] as string[]).includes('sync'));
    expect(syncCalled).toBe(true);
  });

  it('surfaces the error if "Not found" persists even after a sync retry', async () => {
    const { BitwardenClient } = await import('./bw-client.js');
    const client = new BitwardenClient('testvault', {
      url: 'https://vault.example.com',
      clientId: 'id',
      clientSecret: 'secret',
      masterPassword: 'pw',
    } as any);

    (client as any).sessionToken = 'session-token';
    (client as any).sessionExpiry = Date.now() + 60_000;

    execFileMock.mockImplementation((_file: string, args: string[], _opts: unknown, callback: (err: unknown, r?: { stdout: string; stderr: string }) => void) => {
      if (args.includes('get') && args.includes('item')) {
        callback(Object.assign(new Error('Not found.'), { stderr: 'Not found.', stdout: '' }));
        return;
      }
      callback(null, { stdout: '', stderr: '' });
    });

    await expect((client as any).getRawItem('missing-id')).rejects.toThrow(/Not found/);
  });
});
