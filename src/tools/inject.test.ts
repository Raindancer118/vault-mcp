import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { httpRequestWithSecrets, runCommandWithSecrets, prepareInjection } from './inject.js';

const SECRET = 'gsk_TESTKEY_1234567890';
const resolver = async (nameOrId: string) => {
  if (nameOrId === 'item-id') return SECRET;
  throw new Error(`unknown item ${nameOrId}`);
};

describe('httpRequestWithSecrets — placeholder injection', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn(async () => ({
      status: 200,
      statusText: 'OK',
      text: async () => 'ok',
      headers: { forEach: (_cb: (v: string, k: string) => void) => {} },
    }));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => vi.unstubAllGlobals());

  function sentHeaderAuth(): string {
    const [, init] = fetchMock.mock.calls[0];
    return (init.headers as Record<string, string>).Authorization;
  }

  it('replaces a {{NAME}} placeholder cleanly without leftover braces (regression)', async () => {
    await httpRequestWithSecrets(resolver, 'https://api.example.com', 'GET', {
      headers: { Authorization: 'Bearer {{GROQ_KEY}}' },
      secretRefs: { GROQ_KEY: 'item-id' },
    });
    expect(sentHeaderAuth()).toBe(`Bearer ${SECRET}`);
  });

  it('replaces a ${NAME} placeholder', async () => {
    await httpRequestWithSecrets(resolver, 'https://api.example.com', 'GET', {
      headers: { Authorization: 'Bearer ${GROQ_KEY}' },
      secretRefs: { GROQ_KEY: 'item-id' },
    });
    expect(sentHeaderAuth()).toBe(`Bearer ${SECRET}`);
  });

  it('still supports a bare placeholder (backwards compatible)', async () => {
    await httpRequestWithSecrets(resolver, 'https://api.example.com', 'GET', {
      headers: { Authorization: 'Bearer GROQ_KEY' },
      secretRefs: { GROQ_KEY: 'item-id' },
    });
    expect(sentHeaderAuth()).toBe(`Bearer ${SECRET}`);
  });

  it('also supports the placeholder key already wrapped in braces', async () => {
    await httpRequestWithSecrets(resolver, 'https://api.example.com', 'GET', {
      headers: { Authorization: 'Bearer {{GROQ_KEY}}' },
      secretRefs: { '{{GROQ_KEY}}': 'item-id' },
    });
    expect(sentHeaderAuth()).toBe(`Bearer ${SECRET}`);
  });

  it('throws when a placeholder never appears in the template', async () => {
    await expect(
      httpRequestWithSecrets(resolver, 'https://api.example.com', 'GET', {
        headers: { Authorization: 'Bearer static' },
        secretRefs: { GROQ_KEY: 'item-id' },
      }),
    ).rejects.toThrow(/not found in any header or body value/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('replaces a placeholder embedded inside a larger JSON body, even with an unrelated header present (regression)', async () => {
    await httpRequestWithSecrets(resolver, 'https://registry.npmjs.org/-/user/org.couchdb.user:me', 'PUT', {
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identity: 'me', secret: '{{GROQ_KEY}}' }),
      secretRefs: { GROQ_KEY: 'item-id' },
    });
    const [, init] = fetchMock.mock.calls[0];
    expect(init.body).toBe(JSON.stringify({ identity: 'me', secret: SECRET }));
  });

  it('does not require every placeholder to appear in every single header/body field, only somewhere across the request', async () => {
    await httpRequestWithSecrets(resolver, 'https://api.example.com', 'POST', {
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer {{TOKEN}}' },
      body: JSON.stringify({ secret: '{{BODY_SECRET}}' }),
      secretRefs: { TOKEN: 'item-id', BODY_SECRET: 'item-id' },
    });
    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers.Authorization).toBe(`Bearer ${SECRET}`);
    expect(init.body).toBe(JSON.stringify({ secret: SECRET }));
  });

  it('still throws when a placeholder appears in none of the headers or body', async () => {
    await expect(
      httpRequestWithSecrets(resolver, 'https://api.example.com', 'POST', {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity: 'me' }),
        secretRefs: { GROQ_KEY: 'item-id' },
      }),
    ).rejects.toThrow(/not found/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('runCommandWithSecrets — argRefs injection', () => {
  it('replaces {{NAME}} in a command arg cleanly', async () => {
    const res = await runCommandWithSecrets(
      resolver,
      ['printf', '%s', '{{TOK}}'],
      { argRefs: { TOK: 'item-id' } },
    );
    expect(res.exitCode).toBe(0);
    expect(res.stdout).toBe(SECRET);
  });

  it('throws when an arg placeholder is absent from every arg', async () => {
    await expect(
      runCommandWithSecrets(resolver, ['printf', '%s', 'static'], { argRefs: { TOK: 'item-id' } }),
    ).rejects.toThrow(/not found in command args/);
  });
});

describe('prepareInjection — shared resolve/build step (used by the MCP launcher)', () => {
  it('builds an env map of ENV_VAR → resolved secret without spawning', async () => {
    const plan = await prepareInjection(resolver, ['srv', 'mcp'], {
      envMappings: { CIS_PASS: 'item-id' },
    });
    expect(plan.env).toEqual({ CIS_PASS: SECRET });
    expect(plan.args).toEqual(['mcp']); // command[0] dropped, no arg refs to substitute
    expect(plan.stdinValue).toBeNull();
  });

  it('substitutes arg placeholders into the child args', async () => {
    const plan = await prepareInjection(resolver, ['tool', '--pass', '{{PW}}'], {
      argRefs: { '{{PW}}': 'item-id' },
    });
    expect(plan.args).toEqual(['--pass', SECRET]);
  });

  it('resolves a stdin secret into stdinValue', async () => {
    const plan = await prepareInjection(resolver, ['sudo', '-S', 'true'], { stdinSecret: 'item-id' });
    expect(plan.stdinValue).toBe(SECRET);
  });

  it('throws on an arg placeholder that never appears, before anything is spawned', async () => {
    await expect(
      prepareInjection(resolver, ['tool', 'static'], { argRefs: { PW: 'item-id' } }),
    ).rejects.toThrow(/not found in command args/);
  });

  it('rejects an empty command', async () => {
    await expect(prepareInjection(resolver, [], {})).rejects.toThrow(/must not be empty/);
  });
});
