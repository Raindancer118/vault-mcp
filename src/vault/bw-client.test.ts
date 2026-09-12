import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, existsSync, utimesSync } from 'fs';
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

describe('BitwardenClient.acquireLock', () => {
  let tmpHome: string;

  beforeEach(() => {
    tmpHome = mkdtempSync(join(tmpdir(), 'vault-mcp-lock-test-'));
    vi.spyOn(require('os'), 'homedir').mockReturnValue(tmpHome);
  });

  async function makeClient() {
    const { BitwardenClient } = await import('./bw-client.js');
    return new BitwardenClient('testvault', {
      url: 'https://vault.example.com',
      clientId: 'id',
      clientSecret: 'secret',
      masterPassword: 'pw',
    } as any);
  }

  it('serializes two concurrent callers: the second only acquires after the first releases', async () => {
    const client = await makeClient();

    const release1 = await (client as any).acquireLock();
    expect(existsSync((client as any).lockPath)).toBe(true);

    let secondAcquired = false;
    const secondPromise = (client as any).acquireLock().then((release2: () => void) => {
      secondAcquired = true;
      release2();
    });

    // Give the poll loop a couple of ticks — it must still be waiting.
    await new Promise(r => setTimeout(r, 250));
    expect(secondAcquired).toBe(false);

    release1();
    await secondPromise;
    expect(secondAcquired).toBe(true);
    expect(existsSync((client as any).lockPath)).toBe(false);
  });

  it('steals a stale lock left behind by a crashed process instead of blocking forever', async () => {
    const client = await makeClient();
    const lockPath = (client as any).lockPath as string;

    // Simulate a lock directory abandoned by a crashed process: present on disk,
    // but old enough to exceed the staleness threshold.
    mkdirSync(lockPath, { recursive: true });
    const old = new Date(Date.now() - 60_000);
    utimesSync(lockPath, old, old);

    const release = await (client as any).acquireLock();
    expect(existsSync(lockPath)).toBe(true); // re-created by the successful acquire
    release();
    expect(existsSync(lockPath)).toBe(false);
  });
});
