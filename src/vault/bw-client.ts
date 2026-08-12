import { execFile, exec } from 'child_process';
import { promisify } from 'util';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
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

  private async bw(args: string[], extraEnv?: Record<string, string>): Promise<string> {
    if (!existsSync(this.dataDir)) mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });

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
      const out = await this.bw(['status'], { BW_SESSION: token });
      const m = out.match(/\{[\s\S]*\}/);
      return m ? (JSON.parse(m[0]) as { status: string; serverUrl?: string }) : null;
    } catch {
      return null;
    }
  }

  async ensureSession(): Promise<void> {
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
      statusJson = await this.bw(['status']);
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
        await this.bw(['logout']).catch(() => { /* ignore if not logged in */ });
        status = 'unauthenticated';
      }
      await this.bw(['config', 'server', this.cfg.url]);
    }

    if (status === 'unauthenticated') {
      await this.bw(['login', '--apikey'], {
        BW_CLIENTID: this.cfg.clientId,
        BW_CLIENTSECRET: this.cfg.clientSecret,
      });
    }

    const password = await this.resolveMasterPassword();
    const token = await this.bw(['unlock', '--passwordenv', 'BW_PASSWORD', '--raw'], {
      BW_PASSWORD: password,
    });

    if (!token) throw new Error(`bw unlock returned empty session token for vault "${this.instanceName}".`);

    this.sessionToken = token;
    this.sessionExpiry = Date.now() + SESSION_TTL_MS;
    this.persistToken(token);
  }

  private async bws(args: string[]): Promise<string> {
    await this.ensureSession();
    return this.bw(args, { BW_SESSION: this.sessionToken! });
  }

  async sync(): Promise<void> {
    await this.bws(['sync']);
  }

  async listFolders(): Promise<BwFolder[]> {
    return JSON.parse(await this.bws(['list', 'folders', '--raw']));
  }

  async listItems(folderId?: string): Promise<BwItemMeta[]> {
    await this.sync();
    const args = ['list', 'items', '--raw'];
    if (folderId) args.push('--folderid', folderId);
    const items: BwItemFull[] = JSON.parse(await this.bws(args));
    return items.map(toItemMeta);
  }

  async searchItems(query: string): Promise<BwItemMeta[]> {
    const items: BwItemFull[] = JSON.parse(
      await this.bws(['list', 'items', '--search', query, '--raw']),
    );
    return items.map(toItemMeta);
  }

  async getItemMeta(itemId: string): Promise<BwItemMeta> {
    const item: BwItemFull = JSON.parse(await this.bws(['get', 'item', itemId, '--raw']));
    return toItemMeta(item);
  }

  /** Returns all sensitive values for one item — call only for vault_reveal_password. */
  async getItemSensitive(itemId: string): Promise<BwItemSensitive> {
    const item: BwItemFull = JSON.parse(await this.bws(['get', 'item', itemId, '--raw']));
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
    return JSON.parse(await this.bws(['get', 'item', itemId, '--raw']));
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
        const item: BwItemFull = JSON.parse(await this.bws(['get', 'item', itemRef, '--raw']));
        return extractField(item, fieldName);
      } catch (err) {
        // If item lookup itself failed, the item name might contain a colon — fall through
        if ((err as Error).message?.includes('Not found')) {
          const item: BwItemFull = JSON.parse(await this.bws(['get', 'item', ref, '--raw']));
          return extractValue(item);
        }
        throw err;
      }
    }
    const item: BwItemFull = JSON.parse(await this.bws(['get', 'item', ref, '--raw']));
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
    const item: BwItemFull = JSON.parse(await this.bws(['get', 'item', itemId, '--raw']));

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
