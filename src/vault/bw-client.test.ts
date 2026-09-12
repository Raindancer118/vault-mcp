import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, existsSync, utimesSync, statSync } from 'fs';
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

  it('re-unlocks and retries when the cached session was invalidated by another process', async () => {
    const { BitwardenClient } = await import('./bw-client.js');
    const client = new BitwardenClient('testvault', {
      url: 'https://vault.example.com',
      clientId: 'id',
      clientSecret: 'secret',
      masterPassword: 'pw',
    } as any);

    (client as any).sessionToken = 'stale-token';
    (client as any).sessionExpiry = Date.now() + 60_000;

    const item = { id: 'abc-123', name: 'Test Item', type: 1, login: { username: 'u', password: 'p' } };
    let getItemCalls = 0;
    let unlocked = false;

    execFileMock.mockImplementation((_file: string, args: string[], _opts: unknown, callback: (err: unknown, r?: { stdout: string; stderr: string }) => void) => {
      if (args.includes('get') && args.includes('item')) {
        getItemCalls++;
        if (getItemCalls === 1) {
          callback(Object.assign(new Error('You are not logged in.'), { stderr: 'You are not logged in.', stdout: '' }));
          return;
        }
        callback(null, { stdout: JSON.stringify(item), stderr: '' });
        return;
      }
      if (args.includes('unlock')) {
        unlocked = true;
        callback(null, { stdout: 'fresh-token', stderr: '' });
        return;
      }
      if (args.includes('status')) {
        callback(null, { stdout: '{"status":"unauthenticated"}', stderr: '' });
        return;
      }
      callback(null, { stdout: '', stderr: '' });
    });

    const result = await (client as any).getRawItem('abc-123');

    expect(result).toEqual(item);
    expect(unlocked).toBe(true);
    expect((client as any).sessionToken).toBe('fresh-token');
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
      // The retry re-establishes the session first, so unlock must yield a token.
      if (args.includes('unlock')) {
        callback(null, { stdout: 'session-token', stderr: '' });
        return;
      }
      if (args.includes('status')) {
        callback(null, { stdout: '{"status":"unlocked","serverUrl":"https://vault.example.com"}', stderr: '' });
        return;
      }
      callback(null, { stdout: '', stderr: '' });
    });

    await expect((client as any).getRawItem('missing-id')).rejects.toThrow(/Not found/);
  });
});

describe('BitwardenClient session setup atomicity', () => {
  let tmpHome: string;

  beforeEach(() => {
    execFileMock.mockReset();
    execMock.mockReset();
    tmpHome = mkdtempSync(join(tmpdir(), 'vault-mcp-session-test-'));
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

  /**
   * Records, for every bw invocation, which lock directory instance was held at the
   * time (inode + birthtime). A sequence that spans several bw calls is only safe
   * against other processes if every call saw the *same* lock instance — i.e. the
   * lock was never released and re-acquired in between.
   */
  function mockBwRecordingLock(client: any, seen: Array<{ args: string[]; lock: string | null }>) {
    execFileMock.mockImplementation((_file: string, args: string[], _opts: unknown, callback: (err: unknown, r?: { stdout: string; stderr: string }) => void) => {
      let lock: string | null = null;
      try {
        const st = statSync(client.lockPath);
        lock = `${st.ino}:${st.birthtimeMs}`;
      } catch { /* no lock held */ }
      seen.push({ args, lock });

      if (args.includes('status')) {
        callback(null, { stdout: '{"status":"unauthenticated"}', stderr: '' });
        return;
      }
      if (args.includes('unlock')) {
        callback(null, { stdout: 'session-token', stderr: '' });
        return;
      }
      if (args.includes('get') && args.includes('item')) {
        callback(null, { stdout: JSON.stringify({ id: 'abc', name: 'Item', type: 1, login: { username: 'u', password: 'p' } }), stderr: '' });
        return;
      }
      callback(null, { stdout: '', stderr: '' });
    });
  }

  it('holds one uninterrupted lock across the whole status/config/login/unlock sequence', async () => {
    const client = await makeClient();
    const seen: Array<{ args: string[]; lock: string | null }> = [];
    mockBwRecordingLock(client, seen);

    await client.ensureSession();

    expect(seen.length).toBeGreaterThanOrEqual(3); // at least status, login, unlock
    expect(seen.every(s => s.lock !== null)).toBe(true);
    expect(new Set(seen.map(s => s.lock)).size).toBe(1);
  });

  it('keeps that same lock for the item read that follows session setup', async () => {
    const client = await makeClient();
    const seen: Array<{ args: string[]; lock: string | null }> = [];
    mockBwRecordingLock(client, seen);

    await (client as any).getRawItem('abc');

    const getCall = seen.find(s => s.args.includes('get'));
    expect(getCall?.lock).toBeTruthy();
    expect(new Set(seen.map(s => s.lock)).size).toBe(1);
  });

  it('does not interleave two concurrent operations from the same process', async () => {
    const client = await makeClient();
    const seen: Array<{ args: string[]; lock: string | null }> = [];
    mockBwRecordingLock(client, seen);

    await Promise.all([
      (client as any).getRawItem('abc'),
      (client as any).getRawItem('def'),
    ]);

    // Two operations → exactly two lock instances, and all calls of one operation
    // must come before any call of the other (no interleaving).
    const locks = seen.map(s => s.lock);
    expect(new Set(locks).size).toBe(2);
    const firstLock = locks[0];
    const switchIdx = locks.findIndex(l => l !== firstLock);
    expect(locks.slice(0, switchIdx).every(l => l === firstLock)).toBe(true);
    expect(locks.slice(switchIdx).every(l => l !== firstLock)).toBe(true);
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

  it('hands the lock to waiters in arrival order instead of letting one starve', async () => {
    // Two *separate* client objects, as two processes would be — they share only the
    // on-disk lock, so ordering must come from the lock itself, not from the in-process queue.
    const holder = await makeClient();
    const first = await makeClient();
    const second = await makeClient();

    const release0 = await (holder as any).acquireLock();

    const order: string[] = [];
    const firstWait = (first as any).acquireLock().then((r: () => void) => { order.push('first'); r(); });
    await new Promise(r => setTimeout(r, 150)); // ensure "first" queued before "second"
    const secondWait = (second as any).acquireLock().then((r: () => void) => { order.push('second'); r(); });
    await new Promise(r => setTimeout(r, 150));

    release0();
    await Promise.all([firstWait, secondWait]);

    expect(order).toEqual(['first', 'second']);
  });

  it('refreshes the lock while it is held so a slow holder is not mistaken for a crashed one', async () => {
    const client = await makeClient();
    const lockPath = (client as any).lockPath as string;

    vi.useFakeTimers();
    const release = await (client as any).acquireLock();
    try {
      // Backdate the lock as if the holder had been busy (e.g. waiting on a GUI
      // master-password prompt) for longer than the staleness threshold.
      const old = new Date(Date.now() - 60_000);
      utimesSync(lockPath, old, old);
      expect(Date.now() - statSync(lockPath).mtimeMs).toBeGreaterThan(30_000);

      await vi.advanceTimersByTimeAsync(11_000);

      expect(Date.now() - statSync(lockPath).mtimeMs).toBeLessThan(30_000);
    } finally {
      release();
      vi.useRealTimers();
    }
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
