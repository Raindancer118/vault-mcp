import { execFile, exec } from 'child_process';
import { promisify } from 'util';
import { randomBytes } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmdirSync, statSync, utimesSync, unlinkSync, readdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import type { VaultInstanceConfig } from '../config/types.js';
import { promptMasterPassword } from '../util/password-prompt.js';

const execFileAsync = promisify(execFile);
const execAsync = promisify(exec);

export interface BwUri {
  match: number | null;
  uri: string;
}

export interface BwField {
  name: string;
  value: string | null;
  /** 0=text  1=hidden  2=boolean */
  type: number;
}

export interface BwItemMeta {
  id: string;
  name: string;
  /** 1=login  2=secure-note  3=card  4=identity */
  type: number;
  folderId: string | null;
  revisionDate: string;
  favorite: boolean;
  /** 0=no reprompt  1=reprompt for master-password */
  reprompt: number;
  login?: {
    username: string | null;
    uris: string[];
    hasTotp: boolean;
  };
  /** Non-hidden custom fields (type 0=text, 2=boolean). Hidden fields are excluded. */
  fields?: Array<{ name: string; type: number; value: string | null }>;
}

/** All sensitive values for a single item — returned only by vault_reveal_password. */
export interface BwItemSensitive {
  id: string;
  name: string;
  type: number;
  /** login.password for login items */
  password: string | null;
  /** notes content (both secure-note content and login notes) */
  notes: string | null;
  /** Hidden custom fields (type=1) */
  hiddenFields: Array<{ name: string; value: string | null }>;
  /** TOTP seed (if present) */
  totp: string | null;
}

/** Full item as stored in Bitwarden — never leaves the vault boundary except for favorites. */
interface BwItemFull {
  id: string;
  name: string;
  organizationId: string | null;
  folderId: string | null;
  type: number;
  notes: string | null;
  favorite: boolean;
  reprompt: number;
  revisionDate: string;
  fields?: BwField[] | null;
  login?: {
    username: string | null;
    password: string | null;
    uris?: BwUri[] | null;
    totp?: string | null;
  } | null;
  secureNote?: { type: number } | null;
  card?: {
    cardholderName: string | null;
    brand: string | null;
    number: string | null;
    expMonth: string | null;
    expYear: string | null;
    code: string | null;
  } | null;
  identity?: Record<string, string | null> | null;
}

export interface BwFolder {
  id: string;
  name: string;
}

const SESSION_TTL_MS = 18 * 60 * 1000;

// The bw CLI's local vault cache (BITWARDENCLI_APPDATA_DIR/data.json) is a plain file
// with no locking of its own. This machine routinely runs many independent processes
// against the *same* vault instance concurrently — vault-mcp itself plus one vault-launch
// child per downstream MCP server (cis, obsidian, spoticontrol, github, gemini, ...), all
// spawned in a burst on every Claude Code restart. Two of them syncing/unlocking at the
// same time can interleave writes to that file and corrupt or truncate it, which then
// surfaces as `bw get item` reporting "Not found" for items that genuinely exist. Guard
// every bw invocation for a given instance with a cross-process lock (a lockfile-as-directory,
// since mkdir is atomic) so only one `bw` process touches that instance's appdata dir at a time.
//
// A single bw call being atomic is not enough: session setup is a *sequence*
// (status → logout → config server → login → unlock) and each step invalidates state the
// other steps depend on. With per-call locking, two processes interleave their sequences —
// one sees `unauthenticated`, another logs in underneath it, and the first then fails with
// "Logout required before server config update", or wipes the freshly synced local vault so
// the other's next `bw get item` reports "Not found". Every public operation therefore takes
// the lock exactly once and runs its whole sequence (session setup + the actual command)
// under it; the internal *Locked/bwRaw helpers are the unlocked building blocks.
const LOCK_STALE_MS = 30_000;
const LOCK_POLL_MS = 100;
// A single bw invocation takes 1-3s, and a whole Claude Code restart can queue a dozen
// vault-launch children behind each other on the same instance. The wait budget has to
// cover that whole queue, otherwise the serialization just converts the old corruption
// into spurious timeouts.
const LOCK_MAX_WAIT_MS = 180_000;
// Touch the lock while it is held so a legitimately slow holder (an unlock waiting on the
// GUI master-password prompt, a large sync) is never mistaken for a crashed one and stolen.
const LOCK_HEARTBEAT_MS = 10_000;

function normalizeUrl(url: string): string {
  return url.replace(/\/+$/, '').toLowerCase();
}

export class BitwardenClient {
  private sessionToken: string | null = null;
  private sessionExpiry = 0;
  private readonly dataDir: string;
  /**
   * Persisted bw session token, shared across vault-mcp processes (the MCP server
   * and the launcher). Lets an already-unlocked vault be reused so the master
   * password prompt only appears when the vault is genuinely locked. Mode 600.
   */
  private readonly sessionFile: string;
  /** Master password obtained via GUI prompt — held in RAM only, never written to disk. */
  private promptedPassword: string | null = null;
  /** In-process queue: serializes this client's own operations before the file lock. */
  private lockChain: Promise<void> = Promise.resolve();

  constructor(
    private readonly instanceName: string,
    private readonly cfg: VaultInstanceConfig,
  ) {
    this.dataDir = join(homedir(), '.cache', 'vault-mcp', 'bw-data', instanceName);
    this.sessionFile = join(this.dataDir, 'mcp-session.json');
  }

  private baseEnv(): NodeJS.ProcessEnv {
    return { ...process.env, BITWARDENCLI_APPDATA_DIR: this.dataDir };
  }

  private get lockPath(): string {
    return join(this.dataDir, '.bw-lock');
  }

  private get queuePath(): string {
    return join(this.dataDir, '.bw-queue');
  }

  /**
   * Acquire a cross-process lock on this instance's bw appdata dir. `mkdir` is atomic
   * (fails with EEXIST if the dir already exists), which makes it usable as a lockfile
   * without any extra dependency. A lock older than LOCK_STALE_MS is assumed to belong
   * to a crashed holder and is stolen. Returns a release function — always call it in a
   * `finally`.
   *
   * Waiters queue FIFO via a ticket file each: only the holder of the oldest live ticket
   * attempts the mkdir. Without that, every waiter races on each poll and, in a burst of
   * a dozen processes, one of them can lose every race until its budget runs out.
   */
  private async acquireLock(): Promise<() => void> {
    if (!existsSync(this.dataDir)) mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    if (!existsSync(this.queuePath)) mkdirSync(this.queuePath, { recursive: true, mode: 0o700 });

    const ticket = join(this.queuePath, `${Date.now().toString().padStart(14, '0')}-${process.pid}-${randomBytes(4).toString('hex')}`);
    writeFileSync(ticket, '', { mode: 0o600 });
    const dropTicket = () => { try { unlinkSync(ticket); } catch { /* already gone */ } };

    const deadline = Date.now() + LOCK_MAX_WAIT_MS;
    try {
      return await this.acquireLockQueued(ticket, deadline, dropTicket);
    } catch (err) {
      dropTicket();
      throw err;
    }
  }

  private async acquireLockQueued(ticket: string, deadline: number, dropTicket: () => void): Promise<() => void> {
    for (;;) {
      if (!this.isFirstInQueue(ticket)) {
        if (Date.now() > deadline) {
          throw new Error(
            `Timed out waiting for the bw CLI lock on vault "${this.instanceName}" — ` +
            `another process is using it. If this persists, remove ${this.lockPath}.`,
          );
        }
        // Keep our ticket alive so other waiters don't prune us as a crashed process.
        try { const now = new Date(); utimesSync(ticket, now, now); } catch { /* pruned — the next loop re-checks */ }
        await new Promise(resolve => setTimeout(resolve, LOCK_POLL_MS));
        continue;
      }
      try {
        mkdirSync(this.lockPath);
        const heartbeat = setInterval(() => {
          try {
            const now = new Date();
            utimesSync(this.lockPath, now, now);
          } catch { /* lock gone (stolen or released) — nothing to refresh */ }
        }, LOCK_HEARTBEAT_MS);
        heartbeat.unref?.();
        // Leave the queue only once the lock is actually ours, so no later arrival
        // can slip in front while we are between ticket and lock.
        dropTicket();
        return () => {
          clearInterval(heartbeat);
          try { rmdirSync(this.lockPath); } catch { /* already gone — fine */ }
        };
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw err;
        try {
          if (Date.now() - statSync(this.lockPath).mtimeMs > LOCK_STALE_MS) {
            rmdirSync(this.lockPath); // stale — steal it, loop retries immediately
            continue;
          }
        } catch { /* lock vanished between mkdir and stat — retry */ }
        if (Date.now() > deadline) {
          throw new Error(
            `Timed out waiting for the bw CLI lock on vault "${this.instanceName}" — ` +
            `another process is using it. If this persists, remove ${this.lockPath}.`,
          );
        }
        await new Promise(resolve => setTimeout(resolve, LOCK_POLL_MS));
      }
    }
  }

  /**
   * True if our ticket is the oldest live one. Tickets whose holder stopped refreshing
   * them (crashed process) are pruned so they can't block the queue forever.
   */
  private isFirstInQueue(ticket: string): boolean {
    let entries: string[];
    try {
      entries = readdirSync(this.queuePath);
    } catch {
      return true; // queue dir vanished — degrade to the plain mkdir race
    }
    const own = ticket.slice(this.queuePath.length + 1);
    const live: string[] = [];
    for (const name of entries) {
      if (name === own) { live.push(name); continue; }
      try {
        if (Date.now() - statSync(join(this.queuePath, name)).mtimeMs > LOCK_STALE_MS) {
          unlinkSync(join(this.queuePath, name)); // abandoned waiter
          continue;
        }
      } catch { continue; } // vanished between readdir and stat
      live.push(name);
    }
    // Filenames start with a zero-padded creation timestamp, so lexical order is arrival order.
    return live.sort()[0] === own;
  }

  /**
   * Run `fn` with this instance's bw appdata dir locked. In-process callers are queued on
   * a promise chain first (so concurrent MCP requests don't spin on the file lock), then the
   * cross-process file lock is taken for the whole of `fn`.
   */
  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.lockChain.then(async () => {
      const release = await this.acquireLock();
      try {
        return await fn();
      } finally {
        release();
      }
    });
    // Keep the chain alive regardless of this operation's outcome.
    this.lockChain = run.then(() => undefined, () => undefined);
    return run;
  }

  /** Single bw invocation, lock already held by the caller. */
  private async bwRaw(args: string[], extraEnv?: Record<string, string>): Promise<string> {
    {
      // --nointeraction: never let bw drop to an interactive stdin prompt (e.g. asking
      // for the master password when the session is locked). Without a TTY that would
      // hang forever; instead bw errors out and we surface it. Unlocking is handled
      // explicitly via resolveMasterPassword() + the GUI/HTTP prompt.
      const { stdout, stderr } = await execFileAsync('bw', ['--nointeraction', ...args], {
        env: { ...this.baseEnv(), ...extraEnv },
        maxBuffer: 50 * 1024 * 1024,
      }).catch((err: NodeJS.ErrnoException & { stdout?: string; stderr?: string }) => {
        if (err.code === 'ENOENT') {
          throw new Error('Bitwarden CLI (bw) not found. Install it: https://bitwarden.com/help/cli/');
        }
        // bw sometimes writes errors to stderr but exits with non-zero even on success — include both
        const detail = err.stderr?.trim() || err.stdout?.trim() || err.message;
        throw new Error(`bw ${args[0]} failed: ${detail}`);
      });

      void stderr; // intentionally ignored — bw writes progress to stderr
      return stdout.trim();
    }
  }

  /** Single bw invocation that takes the lock itself — for standalone, one-shot commands. */
  private async bw(args: string[], extraEnv?: Record<string, string>): Promise<string> {
    return this.withLock(() => this.bwRaw(args, extraEnv));
  }

  private async resolveMasterPassword(): Promise<string> {
    // Priority: cmd → plaintext config → prompted (cached in RAM) → trigger prompt
    if (this.cfg.masterPasswordCmd) {
      const { stdout } = await execAsync(this.cfg.masterPasswordCmd);
      const pw = stdout.trim();
      if (!pw) throw new Error(`masterPasswordCmd returned empty output for vault "${this.instanceName}"`);
      return pw;
    }
    if (this.cfg.masterPassword) return this.cfg.masterPassword;

    if (this.cfg.masterPasswordPrompt) {
      if (this.promptedPassword) return this.promptedPassword;
      const pw = await promptMasterPassword(this.instanceName);
      this.promptedPassword = pw; // cache in RAM for session lifetime
      return pw;
    }

    throw new Error(
      `Vault "${this.instanceName}" has no master password configured. ` +
      `Set masterPassword, masterPasswordCmd, or masterPasswordPrompt=true.`,
    );
  }

  /** Trigger the password prompt explicitly (e.g. from vault_prompt_password tool). */
  async promptAndCachePassword(): Promise<void> {
    this.promptedPassword = await promptMasterPassword(this.instanceName);
    // Invalidate session so the new password is used on next unlock
    this.sessionToken = null;
    this.sessionExpiry = 0;
  }

  /** Read the persisted session token, if any. Best-effort — never throws. */
  private readPersistedToken(): string | null {
    try {
      const { token } = JSON.parse(readFileSync(this.sessionFile, 'utf-8')) as { token?: string };
      return token && token.length > 0 ? token : null;
    } catch {
      return null;
    }
  }

  /** Persist the unlocked session token (mode 600) for reuse by other processes. */
  private persistToken(token: string): void {
    try {
      if (!existsSync(this.dataDir)) mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
      writeFileSync(this.sessionFile, JSON.stringify({ token }), { mode: 0o600 });
    } catch {
      // Best-effort: a failed persist just means the next cold start may re-prompt.
    }
  }

  /** Query `bw status` with a candidate token; returns parsed status or null on failure. */
  private async statusWithToken(token: string): Promise<{ status: string; serverUrl?: string } | null> {
    try {
      const out = await this.bwRaw(['status'], { BW_SESSION: token });
      const m = out.match(/\{[\s\S]*\}/);
      return m ? (JSON.parse(m[0]) as { status: string; serverUrl?: string }) : null;
    } catch {
      return null;
    }
  }

  async ensureSession(): Promise<void> {
    if (this.sessionToken && Date.now() < this.sessionExpiry) return;
    return this.withLock(() => this.ensureSessionLocked());
  }

  /**
   * Session setup, lock already held. Must never be called without the lock: the
   * status → logout → config → login → unlock sequence is only safe if no other
   * process can change the appdata dir between its steps.
   */
  private async ensureSessionLocked(): Promise<void> {
    if (this.sessionToken && Date.now() < this.sessionExpiry) return;

    // Reuse a session unlocked by another vault-mcp process (server or launcher),
    // so the password prompt only appears when the vault is genuinely locked.
    const persisted = this.readPersistedToken();
    if (persisted) {
      const st = await this.statusWithToken(persisted);
      if (st?.status === 'unlocked' &&
          (!st.serverUrl || normalizeUrl(st.serverUrl) === normalizeUrl(this.cfg.url))) {
        this.sessionToken = persisted;
        this.sessionExpiry = Date.now() + SESSION_TTL_MS;
        return;
      }
    }

    let statusJson: string;
    try {
      statusJson = await this.bwRaw(['status']);
    } catch {
      statusJson = '{"status":"unauthenticated"}';
    }

    // bw status can return a message prefix before the JSON on some versions — extract JSON
    const jsonMatch = statusJson.match(/\{[\s\S]*\}/);
    const parsed = jsonMatch
      ? (JSON.parse(jsonMatch[0]) as { status: string; serverUrl?: string })
      : { status: 'unauthenticated', serverUrl: undefined };

    let { status } = parsed;
    const serverUrl: string | undefined = parsed.serverUrl;

    const needsReconfigure = !serverUrl ||
      normalizeUrl(serverUrl) !== normalizeUrl(this.cfg.url);

    if (needsReconfigure) {
      if (status !== 'unauthenticated') {
        await this.bwRaw(['logout']).catch(() => { /* ignore if not logged in */ });
        status = 'unauthenticated';
      }
      await this.bwRaw(['config', 'server', this.cfg.url]);
    }

    if (status === 'unauthenticated') {
      await this.bwRaw(['login', '--apikey'], {
        BW_CLIENTID: this.cfg.clientId,
        BW_CLIENTSECRET: this.cfg.clientSecret,
      });
    }

    const password = await this.resolveMasterPassword();
    const token = await this.bwRaw(['unlock', '--passwordenv', 'BW_PASSWORD', '--raw'], {
      BW_PASSWORD: password,
    });

    if (!token) throw new Error(`bw unlock returned empty session token for vault "${this.instanceName}".`);

    this.sessionToken = token;
    this.sessionExpiry = Date.now() + SESSION_TTL_MS;
    this.persistToken(token);
  }

  /**
   * Session-authenticated bw call: takes the lock once and runs session setup *and* the
   * command under it, so no other process can log out, reconfigure or re-sync the appdata
   * dir in between (which is what turned existing items into "Not found").
   */
  private async bws(args: string[]): Promise<string> {
    return this.withLock(async () => {
      await this.ensureSessionLocked();
      return this.bwRaw(args, { BW_SESSION: this.sessionToken! });
    });
  }

  async sync(): Promise<void> {
    await this.bws(['sync']);
  }

  async listFolders(): Promise<BwFolder[]> {
    return JSON.parse(await this.bws(['list', 'folders', '--raw']));
  }

  async listItems(folderId?: string): Promise<BwItemMeta[]> {
    const args = ['list', 'items', '--raw'];
    if (folderId) args.push('--folderid', folderId);
    // Sync and list under one lock — otherwise another process can log out or resync
    // between the two and the list comes back empty.
    const raw = await this.withLock(async () => {
      await this.ensureSessionLocked();
      await this.bwRaw(['sync'], { BW_SESSION: this.sessionToken! });
      return this.bwRaw(args, { BW_SESSION: this.sessionToken! });
    });
    const items: BwItemFull[] = JSON.parse(raw);
    return items.map(toItemMeta);
  }

  async searchItems(query: string): Promise<BwItemMeta[]> {
    const items: BwItemFull[] = JSON.parse(
      await this.bws(['list', 'items', '--search', query, '--raw']),
    );
    return items.map(toItemMeta);
  }

  /**
   * `bw get item` resolves against bw's local on-disk vault cache, not the server —
   * unlike `list`/`search`, it never syncs that cache itself. If the cache is stale or was
   * emptied by another process re-authenticating (or our cached session token was
   * invalidated by that), a genuinely existing item comes back "Not found". Recover once:
   * drop the cached session, re-establish it and sync — all inside the same lock, so the
   * recovery can't race the very processes that caused the problem.
   */
  private async getRawItem(itemId: string): Promise<BwItemFull> {
    return this.withLock(async () => {
      await this.ensureSessionLocked();
      const get = () => this.bwRaw(['get', 'item', itemId, '--raw'], { BW_SESSION: this.sessionToken! });
      try {
        return JSON.parse(await get());
      } catch (err) {
        if (!isRecoverableLookupError(err as Error)) throw err;
        this.sessionToken = null;
        this.sessionExpiry = 0;
        await this.ensureSessionLocked();
        await this.bwRaw(['sync'], { BW_SESSION: this.sessionToken! });
        return JSON.parse(await get());
      }
    });
  }

  async getItemMeta(itemId: string): Promise<BwItemMeta> {
    const item = await this.getRawItem(itemId);
    return toItemMeta(item);
  }

  /** Returns all sensitive values for one item — call only for vault_reveal_password. */
  async getItemSensitive(itemId: string): Promise<BwItemSensitive> {
    const item = await this.getRawItem(itemId);
    return {
      id: item.id,
      name: item.name,
      type: item.type,
      password: item.login?.password ?? null,
      notes: item.notes ?? null,
      hiddenFields: (item.fields ?? []).filter(f => f.type === 1).map(f => ({
        name: f.name,
        value: f.value,
      })),
      totp: item.login?.totp ?? null,
    };
  }

  /** Returns the full raw item for storage in the favorites vault. */
  async getItemForFavorites(itemId: string): Promise<BwItemFull> {
    return this.getRawItem(itemId);
  }

  /**
   * Resolves a secret reference to a string value.
   *
   * Supported formats:
   *   "Item Name"            → primary value (password for login, content for note)
   *   "Item Name:username"   → login username
   *   "Item Name:password"   → login password (explicit)
   *   "Item Name:notes"      → notes field
   *   "Item Name:totp"       → TOTP seed
   *   "Item Name:My Field"   → custom field named "My Field" (any type)
   *
   * If the item name itself contains a colon, use the item's UUID instead.
   */
  async resolveValue(ref: string): Promise<string> {
    const colonIdx = ref.indexOf(':');
    if (colonIdx > 0) {
      const itemRef = ref.slice(0, colonIdx);
      const fieldName = ref.slice(colonIdx + 1).trim();
      try {
        const item = await this.getRawItem(itemRef);
        return extractField(item, fieldName);
      } catch (err) {
        // If item lookup itself failed, the item name might contain a colon — fall through
        if ((err as Error).message?.includes('Not found')) {
          const item = await this.getRawItem(ref);
          return extractValue(item);
        }
        throw err;
      }
    }
    const item = await this.getRawItem(ref);
    return extractValue(item);
  }

  async createItem(params: {
    name: string;
    value: string;
    username?: string;
    type: 'login' | 'note';
    folderId?: string | null;
    notes?: string;
  }): Promise<{ id: string; name: string }> {
    const isNote = params.type === 'note';
    const payload = {
      type: isNote ? 2 : 1,
      name: params.name,
      folderId: params.folderId ?? null,
      notes: isNote ? params.value : (params.notes ?? null),
      login: isNote ? null : {
        username: params.username ?? null,
        password: params.value,
        uris: [],
        totp: null,
      },
      secureNote: isNote ? { type: 0 } : null,
      fields: [],
      favorite: false,
      reprompt: 0,
    };

    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
    const created: BwItemFull = JSON.parse(await this.bws(['create', 'item', encoded]));
    return { id: created.id, name: created.name };
  }

  async updateItemValue(itemId: string, value: string, username?: string): Promise<void> {
    const item = await this.getRawItem(itemId);

    if (item.type === 1 && item.login) {
      item.login.password = value;
      if (username !== undefined) item.login.username = username;
    } else if (item.type === 2) {
      item.notes = value;
    } else {
      throw new Error(`Item type ${item.type} is not supported for value updates.`);
    }

    const encoded = Buffer.from(JSON.stringify(item)).toString('base64');
    await this.bws(['edit', 'item', itemId, encoded]);
  }

  async deleteItem(itemId: string): Promise<void> {
    await this.bws(['delete', 'item', itemId]);
  }

  async createFolder(name: string): Promise<BwFolder> {
    const encoded = Buffer.from(JSON.stringify({ name })).toString('base64');
    return JSON.parse(await this.bws(['create', 'folder', encoded]));
  }

  async findFolderByName(name: string): Promise<BwFolder | undefined> {
    const folders = await this.listFolders();
    return folders.find(f => f.name === name);
  }
}

/**
 * Errors that mean "our view of the local vault/session went stale", not "this item does
 * not exist" — all of them are fixed by re-unlocking and syncing, so a lookup hitting one
 * is worth exactly one retry.
 */
function isRecoverableLookupError(err: Error): boolean {
  return /not found|not logged in|vault is locked|mac failed|invalid master password/i.test(err.message ?? '');
}

function toItemMeta(item: BwItemFull): BwItemMeta {
  return {
    id: item.id,
    name: item.name,
    type: item.type,
    folderId: item.folderId,
    revisionDate: item.revisionDate,
    favorite: item.favorite ?? false,
    reprompt: item.reprompt ?? 0,
    login: item.login != null ? {
      username: item.login.username,
      uris: (item.login.uris ?? []).map(u => u.uri).filter(Boolean),
      hasTotp: Boolean(item.login.totp),
    } : undefined,
    // Include text (type=0) and boolean (type=2) fields — never hidden fields (type=1)
    fields: item.fields?.filter(f => f.type !== 1).map(f => ({
      name: f.name,
      type: f.type,
      value: f.value,
    })),
  };
}

function extractValue(item: BwItemFull): string {
  if (item.type === 1 && item.login?.password) return item.login.password;
  if (item.type === 2 && item.notes) return item.notes;
  const hidden = item.fields?.find(f => f.type === 1 || f.name.toLowerCase() === 'value');
  if (hidden?.value) return hidden.value;
  throw new Error(`Cannot extract a value from item "${item.name}" (type ${item.type}).`);
}

function extractField(item: BwItemFull, fieldName: string): string {
  const lower = fieldName.toLowerCase();

  if (lower === 'username') {
    if (!item.login?.username) throw new Error(`Item "${item.name}" has no username.`);
    return item.login.username;
  }
  if (lower === 'password') {
    if (!item.login?.password) throw new Error(`Item "${item.name}" has no password.`);
    return item.login.password;
  }
  if (lower === 'notes') {
    if (!item.notes) throw new Error(`Item "${item.name}" has no notes.`);
    return item.notes;
  }
  if (lower === 'totp') {
    if (!item.login?.totp) throw new Error(`Item "${item.name}" has no TOTP seed.`);
    return item.login.totp;
  }

  // Custom field — case-insensitive name match, then exact match as fallback
  const field =
    item.fields?.find(f => f.name.toLowerCase() === lower) ??
    item.fields?.find(f => f.name === fieldName);
  if (!field) {
    const available = item.fields?.map(f => `"${f.name}"`).join(', ') ?? 'none';
    throw new Error(`Field "${fieldName}" not found in item "${item.name}". Available: ${available}`);
  }
  if (field.value === null) throw new Error(`Field "${fieldName}" in item "${item.name}" has no value.`);
  return field.value;
}
