#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { loadConfig, saveConfig } from './config/loader.js';
import { BitwardenClient } from './vault/bw-client.js';
import * as pv from './vault/project-vault.js';
import * as fv from './vault/favorites-vault.js';
import * as inject from './tools/inject.js';
import * as browser from './tools/browser.js';
import * as cache from './db/search-cache.js';
import * as secretScan from './tools/secret-scan.js';
import { auditLog } from './audit.js';

// ─── Client cache (one per vault instance, reuses session) ────────────────────

const clientCache = new Map<string, BitwardenClient>();

function getClient(vaultName: string): BitwardenClient {
  const cfg = loadConfig();
  const instanceCfg = cfg.vaults[vaultName];
  if (!instanceCfg) throw new Error(`Vault instance "${vaultName}" is not configured.`);
  if (!clientCache.has(vaultName)) {
    clientCache.set(vaultName, new BitwardenClient(vaultName, instanceCfg));
  }
  return clientCache.get(vaultName)!;
}

// ─── Tool definitions ─────────────────────────────────────────────────────────

const TOOLS: Tool[] = [
  // ── Instance management ──────────────────────────────────────────────────────
  {
    name: 'vault_list_instances',
    description: 'List all configured Vaultwarden/Bitwarden instances (names and URLs only — no credentials).',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'vault_add_instance',
    description: 'Add a new Vaultwarden/Bitwarden instance. Credentials are stored in ~/.config/vault-mcp/config.json (mode 600).',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Short identifier, e.g. "volantic" or "nak"' },
        url: { type: 'string', description: 'Vault server URL, e.g. "https://vault.example.com"' },
        clientId: { type: 'string', description: 'Bitwarden API client_id (user.xxxxx)' },
        clientSecret: { type: 'string', description: 'Bitwarden API client_secret' },
        masterPassword: { type: 'string', description: 'Master password in plaintext. Avoid — use masterPasswordCmd or masterPasswordPrompt instead.' },
        masterPasswordCmd: { type: 'string', description: 'Shell command whose stdout is the master password, e.g. "secret-tool lookup service vault-mcp account volantic"' },
        masterPasswordPrompt: { type: 'boolean', description: 'If true, a GUI dialog (zenity/kdialog) or browser form will prompt the user for the password. Never stored on disk.' },
        email: { type: 'string', description: 'Account email address' },
        description: { type: 'string', description: 'Optional human-readable description' },
        setAsDefault: { type: 'boolean', description: 'Set as default vault' },
      },
      required: ['name', 'url', 'clientId', 'clientSecret', 'email'],
    },
  },
  {
    name: 'vault_remove_instance',
    description: 'Remove a configured vault instance. Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['name', 'confirmed'],
    },
  },

  // ── Password prompt ───────────────────────────────────────────────────────────
  {
    name: 'vault_prompt_password',
    description:
      'Show a GUI password dialog (zenity/kdialog) or a local browser form to the user. ' +
      'The entered password unlocks the vault and is cached in RAM for the session — ' +
      'it is NEVER returned to Claude or written to disk. ' +
      'Use this before any vault operation when masterPasswordPrompt=true is configured.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Vault instance name. Omit to use default.' },
      },
      required: [],
    },
  },

  // ── Connection check ─────────────────────────────────────────────────────────
  {
    name: 'vault_check_connection',
    description: 'Test the connection to a vault instance: verifies server reachability, API key login, and master-password unlock. Returns status details without exposing any secrets.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Vault instance name. Omit to check the default vault.' },
      },
      required: [],
    },
  },

  // ── Local search cache ────────────────────────────────────────────────────────
  {
    name: 'vault_sync_cache',
    description:
      'Sync vault item metadata to the local SQLite search cache. ' +
      'Stores ONLY: id, name, type, folder, username, URIs, field names — NO secret values. ' +
      'Run this once after adding a vault, and whenever items change. ' +
      'After syncing, use vault_search for fast fuzzy search without hitting Vaultwarden.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: {
          type: 'string',
          description: 'Vault instance to sync. Omit to sync ALL configured vaults.',
        },
      },
      required: [],
    },
  },
  {
    name: 'vault_search',
    description:
      'Fuzzy search across the local metadata cache — fast, no Vaultwarden round-trip. ' +
      'Searches item name, username, URIs, folder, and field names. ' +
      'Typo-tolerant: "porkbun" finds "Porkbun API Key", "githb" finds "GitHub Token". ' +
      'Run vault_sync_cache first if the cache is empty or stale.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query (fuzzy, typo-tolerant).' },
        vault: { type: 'string', description: 'Limit search to one vault instance.' },
        limit: { type: 'number', description: 'Max results to return. Default: 10.' },
        threshold: {
          type: 'number',
          description: 'Match strictness 0.0–1.0 (lower = stricter). Default: 0.45.',
        },
      },
      required: ['query'],
    },
  },
  {
    name: 'vault_cache_status',
    description: 'Show when each vault was last synced and how many items are cached.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },

  // ── Remote vault discovery (no values returned) ───────────────────────────────
  {
    name: 'vault_list_items',
    description: 'List items in a remote vault. Returns metadata only (id, name, type, username, URIs, non-hidden fields) — no passwords or sensitive values.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Vault instance name. Omit to use default.' },
        folder: { type: 'string', description: 'Filter by folder name (optional).' },
      },
      required: [],
    },
  },
  {
    name: 'vault_search_items',
    description: 'Search items by name in a remote vault. Returns metadata only — no passwords.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' },
        vault: { type: 'string' },
      },
      required: ['query'],
    },
  },
  {
    name: 'vault_list_folders',
    description: 'List folders in a remote vault.',
    inputSchema: {
      type: 'object',
      properties: { vault: { type: 'string' } },
      required: [],
    },
  },
  {
    name: 'vault_get_item',
    description: 'Get full metadata for a single vault item by ID or name. Returns username, URIs, non-hidden custom fields — no passwords or sensitive values.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Vault instance name. Omit to use default.' },
        itemId: { type: 'string', description: 'Item ID or exact name.' },
      },
      required: ['itemId'],
    },
  },

  // ── Password reveal (double confirmation required) ────────────────────────────
  {
    name: 'vault_reveal_password',
    description:
      'Retrieve the sensitive values (password, notes, hidden fields) for a vault item. ' +
      'DOUBLE CONFIRMATION required: both confirmed=true AND exposedToAI=true must be set. ' +
      'Use only when the user explicitly requests to see the password — never proactively.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Vault instance name. Omit to use default.' },
        itemId: { type: 'string', description: 'Item ID or exact name.' },
        confirmed: {
          type: 'boolean',
          description: 'First confirmation — must be true.',
        },
        exposedToAI: {
          type: 'boolean',
          description: 'Second confirmation — explicitly acknowledge that the AI will see the secret value in plaintext.',
        },
      },
      required: ['itemId', 'confirmed', 'exposedToAI'],
    },
  },

  // ── Remote vault CRUD (Claude sees values on create/update) ──────────────────
  {
    name: 'vault_create_item',
    description: 'Create a new secret item in a remote vault. Claude must provide the value here. Requires confirmed=true because Claude will see the secret value.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string' },
        name: { type: 'string', description: 'Item name' },
        value: { type: 'string', description: 'The secret value (password, token, key, etc.)' },
        username: { type: 'string', description: 'Optional username (for login items)' },
        type: { type: 'string', enum: ['login', 'note'], description: 'Item type.' },
        folder: { type: 'string', description: 'Target folder name (created if it does not exist)' },
        notes: { type: 'string', description: 'Optional notes (for login items)' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['name', 'value', 'confirmed'],
    },
  },
  {
    name: 'vault_update_item',
    description: 'Update the value of an existing item. Claude must provide the new value. Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string' },
        itemId: { type: 'string', description: 'Item ID or exact name' },
        value: { type: 'string', description: 'New secret value' },
        username: { type: 'string', description: 'New username (optional, login items only)' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['itemId', 'value', 'confirmed'],
    },
  },
  {
    name: 'vault_delete_item',
    description: 'Delete an item from a remote vault. Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string' },
        itemId: { type: 'string' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['itemId', 'confirmed'],
    },
  },

  // ── Remote vault proxy (secrets injected, never returned) ────────────────────
  {
    name: 'vault_run_command',
    description:
      'Run a shell command with vault secrets injected. Three injection modes — combine as needed:\n' +
      '1. envMappings: inject as ENV_VAR (safest — preferred when the tool supports it)\n' +
      '2. argRefs: substitute placeholders into command args (e.g. ["curl", "--user", "admin:{{PASS}}"]). Note: args briefly visible in process list.\n' +
      '3. stdinSecret: pipe one secret to stdin (for tools like sudo -S, gpg, openssl that read passwords from stdin)\n' +
      'Secrets are never returned — only stdout/stderr.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string' },
        command: {
          type: 'array',
          items: { type: 'string' },
          description: 'Command as array, e.g. ["curl", "-H", "Authorization: Bearer {{TOKEN}}", "https://api.example.com"]. No shell interpolation.',
        },
        envMappings: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'ENV_VAR_NAME → vault item name or ID. Safest option — prefer this when the tool supports env vars.',
        },
        argRefs: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'Placeholder string → vault item name or ID. Substituted into command args before spawning. E.g. {"{{TOKEN}}": "My API Token"}.',
        },
        stdinSecret: {
          type: 'string',
          description: 'Vault item name or ID whose value is written to stdin. Use for tools that read credentials from stdin (sudo -S, gpg, etc.).',
        },
        cwd: { type: 'string', description: 'Working directory (optional).' },
      },
      required: ['command'],
    },
  },
  {
    name: 'vault_write_file',
    description: 'Write a file with secrets from a remote vault substituted into the content. The file is written with mode 600. Secrets are never returned.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string' },
        outputPath: { type: 'string', description: 'Absolute path of the file to write.' },
        content: { type: 'string', description: 'File content / template with placeholder strings.' },
        secretRefs: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'Map of placeholder string → vault item name or ID.',
        },
      },
      required: ['outputPath', 'content', 'secretRefs'],
    },
  },
  {
    name: 'vault_http_request',
    description: 'Make an HTTP request with secrets from a remote vault injected into headers or body. Response is returned; secrets are never exposed.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string' },
        url: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
        body: { type: 'string' },
        secretRefs: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['url', 'secretRefs'],
    },
  },

  // ── Secret scanning ───────────────────────────────────────────────────────────
  {
    name: 'vault_scan_secrets',
    description:
      'Scan a project directory for hardcoded secrets (API keys, tokens, private keys, passwords) BEFORE committing or pushing. ' +
      'Scans git-tracked, staged, and untracked-but-not-ignored files (or all files if not a git repo); matched values are redacted, never returned in full.\n\n' +
      'If findings are returned: do NOT push. For each finding, move the real value into a project vault instead — ' +
      '(1) vault_init_project if this project has no project vault yet, ' +
      '(2) vault_project_create_item to store the actual secret, ' +
      '(3) replace the hardcoded value in the file with a {{placeholder}} referencing that item, and use vault_project_run_command / ' +
      'vault_project_write_file / vault_project_http_request to inject it at runtime instead of committing it. ' +
      'Re-run vault_scan_secrets afterwards to confirm the tree is clean before pushing.',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Absolute path to the directory to scan (usually the project/repo root).' },
      },
      required: ['path'],
    },
  },

  // ── Browser automation ───────────────────────────────────────────────────────
  {
    name: 'vault_browser_fill',
    description:
      'Open a real browser (Chromium/headless), navigate to a URL, and fill form fields with ' +
      'vault credentials — for websites that have no API. Secrets are injected directly and never returned.\n\n' +
      'Field refs support the "Item:field" syntax:\n' +
      '  "My Login"           → primary value (password)\n' +
      '  "My Login:username"  → username\n' +
      '  "My Login:API Key"   → custom field named "API Key"\n\n' +
      'Example: log into a web panel at https://admin.example.com:\n' +
      '  fields: { "#email": "Admin Login:username", "#password": "Admin Login" }\n' +
      '  submitSelector: "button[type=submit]"\n' +
      '  waitForSelector: ".dashboard"',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Vault instance name. Omit to use default.' },
        url: { type: 'string', description: 'URL to navigate to.' },
        fields: {
          type: 'object',
          additionalProperties: { type: 'string' },
          description: 'CSS selector → vault item ref (supports "Item:field" syntax). Fields are filled in key order.',
        },
        submitSelector: { type: 'string', description: 'CSS selector of the submit button to click after filling.' },
        waitForSelector: { type: 'string', description: 'CSS selector to wait for after submission (confirms the action succeeded).' },
        extractSelector: { type: 'string', description: 'CSS selector whose text content is extracted and returned (e.g. a token or confirmation message).' },
        screenshot: { type: 'boolean', description: 'Return a base64 PNG screenshot after the action. Default: false.' },
        headless: { type: 'boolean', description: 'Run headless (no visible window). Default: true.' },
        timeout: { type: 'number', description: 'Navigation + action timeout in ms. Default: 30000.' },
        extraHeaders: { type: 'object', additionalProperties: { type: 'string' }, description: 'Extra HTTP headers.' },
      },
      required: ['url', 'fields'],
    },
  },
  // ── Favorites vault ───────────────────────────────────────────────────────────
  {
    name: 'vault_favorites_add',
    description:
      'Save a vault item (including its password) as a favorite in the local encrypted favorites vault. ' +
      'The favorites vault is encrypted with AES-256-GCM using a key derived from the passphrase via scrypt — ' +
      'the passphrase and derived key are NEVER written to disk. ' +
      'Requires confirmed=true because the password will be read from the remote vault and stored locally.',
    inputSchema: {
      type: 'object',
      properties: {
        vault: { type: 'string', description: 'Source vault instance name. Omit to use default.' },
        itemId: { type: 'string', description: 'Item ID or exact name in the source vault.' },
        passphrase: { type: 'string', description: 'Passphrase for the favorites vault. Never stored on disk.' },
        alias: { type: 'string', description: 'Optional display name override for the favorite.' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['itemId', 'passphrase', 'confirmed'],
    },
  },
  {
    name: 'vault_favorites_list',
    description:
      'List all favorites in the local encrypted vault. Returns metadata only (name, username, URIs, etc.) — no passwords. ' +
      'Requires the passphrase to decrypt the vault.',
    inputSchema: {
      type: 'object',
      properties: {
        passphrase: { type: 'string', description: 'Passphrase for the favorites vault.' },
      },
      required: ['passphrase'],
    },
  },
  {
    name: 'vault_favorites_get',
    description:
      'Retrieve a favorite including its password. ' +
      'DOUBLE CONFIRMATION required: both confirmed=true AND exposedToAI=true must be set. ' +
      'Use only when the user explicitly requests to see the password — never proactively.',
    inputSchema: {
      type: 'object',
      properties: {
        passphrase: { type: 'string', description: 'Passphrase for the favorites vault.' },
        nameOrId: { type: 'string', description: 'Favorite name or ID.' },
        confirmed: { type: 'boolean', description: 'First confirmation — must be true.' },
        exposedToAI: { type: 'boolean', description: 'Second confirmation — acknowledge AI will see the password.' },
      },
      required: ['passphrase', 'nameOrId', 'confirmed', 'exposedToAI'],
    },
  },
  {
    name: 'vault_favorites_remove',
    description: 'Remove a favorite from the local encrypted vault. Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        passphrase: { type: 'string', description: 'Passphrase for the favorites vault.' },
        nameOrId: { type: 'string', description: 'Favorite name or ID.' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['passphrase', 'nameOrId', 'confirmed'],
    },
  },
  {
    name: 'vault_favorites_update',
    description: 'Refresh a favorite by re-fetching the current values from the source vault (e.g. after a password change). Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        passphrase: { type: 'string', description: 'Passphrase for the favorites vault.' },
        nameOrId: { type: 'string', description: 'Favorite name or ID.' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['passphrase', 'nameOrId', 'confirmed'],
    },
  },

  // ── Project vault setup ───────────────────────────────────────────────────────
  {
    name: 'vault_init_project',
    description:
      'Initialise a project vault for a Git repository — a small LOCAL secret store meant to hold ONLY the ' +
      'handful of secrets this specific repo actually needs at runtime. This is NOT a copy of, sync of, or ' +
      'export from any Bitwarden/Vaultwarden vault — a full Bitwarden/Vaultwarden vault (personal or org) must ' +
      'NEVER be committed or pushed. Add items one at a time via vault_project_create_item, only ones this repo ' +
      'genuinely uses.\n\n' +
      'Creates a .vault-project marker file (safe to commit) and an AES-256-GCM encrypted vault.\n\n' +
      'By default (commit: false) the encrypted vault is stored OUTSIDE the repo, under this machine\'s ' +
      'vault-mcp config dir — nothing but the marker is ever committed.\n\n' +
      'Pass commit: true to store the encrypted vault file itself inside the repo (as .vault-project.enc) so it ' +
      'can be committed and pushed alongside the code. This forces TOTP protection on, AND mints a dedicated, ' +
      'single-purpose 512-bit vault key — both stored only locally, never in the repo, and both required together ' +
      'to decrypt. Deliberately independent of this machine\'s shared master key: leaking the master key (shared ' +
      'across every vault on this machine) has zero effect on a committed vault. Every machine that needs to use ' +
      'the vault needs its own local copy of BOTH files. The response includes the vault key and TOTP seed ONCE — ' +
      'back both up immediately as separate items (e.g. two notes in a Bitwarden vault, never in this repo) or the ' +
      'committed vault becomes permanently unrecoverable if this machine is lost.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string', description: 'Absolute path to the project root.' },
        name: { type: 'string', description: 'Human-readable project name.' },
        commit: {
          type: 'boolean',
          description: 'Store the encrypted vault inside the repo (committable) instead of in local machine config. Forces TOTP + a dedicated vault key on. Default: false.',
        },
      },
      required: ['projectDir', 'name'],
    },
  },
  {
    name: 'vault_project_info',
    description: 'Get info about a project vault (name, ID, item count, storage mode, TOTP status). No values returned.',
    inputSchema: {
      type: 'object',
      properties: { projectDir: { type: 'string' } },
      required: ['projectDir'],
    },
  },
  {
    name: 'vault_project_totp_enable',
    description:
      'Enable TOTP protection on an existing project vault that was created without it. Re-encrypts the vault ' +
      'under a key derived from both the master key and a newly generated local TOTP seed. Required before ' +
      'vault_project_enable_commit_storage. Returns the TOTP seed and otpauth:// URI ONCE — back it up immediately.',
    inputSchema: {
      type: 'object',
      properties: { projectDir: { type: 'string' } },
      required: ['projectDir'],
    },
  },
  {
    name: 'vault_project_enable_commit_storage',
    description:
      'Move an existing project vault\'s encrypted file from local machine config into the repo (as ' +
      '.vault-project.enc) so it can be committed and pushed. Requires TOTP to already be enabled ' +
      '(run vault_project_totp_enable first) — refuses otherwise. Mints a brand-new dedicated 512-bit vault key ' +
      'and re-encrypts everything under it plus the TOTP seed, independent of the shared master key. Returns the ' +
      'new vault key ONCE — back it up immediately (e.g. as a note in a Bitwarden vault, never in this repo).',
    inputSchema: {
      type: 'object',
      properties: { projectDir: { type: 'string' } },
      required: ['projectDir'],
    },
  },

  // ── Project vault item management ─────────────────────────────────────────────
  {
    name: 'vault_project_list_items',
    description: 'List items in a project vault. Returns metadata only — no values.',
    inputSchema: {
      type: 'object',
      properties: { projectDir: { type: 'string' } },
      required: ['projectDir'],
    },
  },
  {
    name: 'vault_project_create_item',
    description:
      'Create a new item in a project vault. Claude must provide the value. Requires confirmed=true. ' +
      'Add items ONE AT A TIME, and only ones this repo genuinely needs at runtime — never bulk-import or mirror ' +
      'an entire Bitwarden/Vaultwarden vault into a project vault.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string' },
        name: { type: 'string' },
        value: { type: 'string' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['projectDir', 'name', 'value', 'confirmed'],
    },
  },
  {
    name: 'vault_project_update_item',
    description: 'Update an item in a project vault. Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string' },
        nameOrId: { type: 'string', description: 'Item name or UUID.' },
        value: { type: 'string' },
        confirmed: { type: 'boolean', description: 'Must be true to execute.' },
      },
      required: ['projectDir', 'nameOrId', 'value', 'confirmed'],
    },
  },
  {
    name: 'vault_project_delete_item',
    description: 'Delete an item from a project vault. Requires confirmed=true.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string' },
        nameOrId: { type: 'string' },
        confirmed: { type: 'boolean' },
      },
      required: ['projectDir', 'nameOrId', 'confirmed'],
    },
  },

  // ── Project vault proxy ───────────────────────────────────────────────────────
  {
    name: 'vault_project_run_command',
    description: 'Run a command with project vault secrets injected (env vars, arg substitution, or stdin). Same injection modes as vault_run_command. Secrets never returned.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string' },
        command: { type: 'array', items: { type: 'string' } },
        envMappings: { type: 'object', additionalProperties: { type: 'string' }, description: 'ENV_VAR_NAME → item name/ID' },
        argRefs: { type: 'object', additionalProperties: { type: 'string' }, description: 'Placeholder → item name/ID, substituted into args.' },
        stdinSecret: { type: 'string', description: 'Item name/ID written to stdin.' },
        cwd: { type: 'string' },
      },
      required: ['projectDir', 'command'],
    },
  },
  {
    name: 'vault_project_write_file',
    description: 'Write a file with project vault secrets substituted. Output written with mode 600.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string' },
        outputPath: { type: 'string' },
        content: { type: 'string' },
        secretRefs: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['projectDir', 'outputPath', 'content', 'secretRefs'],
    },
  },
  {
    name: 'vault_project_http_request',
    description: 'HTTP request with project vault secrets injected. Response returned; secrets never exposed.',
    inputSchema: {
      type: 'object',
      properties: {
        projectDir: { type: 'string' },
        url: { type: 'string' },
        method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
        headers: { type: 'object', additionalProperties: { type: 'string' } },
        body: { type: 'string' },
        secretRefs: { type: 'object', additionalProperties: { type: 'string' } },
      },
      required: ['projectDir', 'url', 'secretRefs'],
    },
  },
];

// ─── Server ───────────────────────────────────────────────────────────────────

const server = new Server(
  { name: 'vault-mcp', version: '1.1.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    const result = await handleTool(name, args ?? {});
    return {
      content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }],
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { content: [{ type: 'text', text: `Error: ${msg}` }], isError: true };
  }
});

// ─── Handlers ─────────────────────────────────────────────────────────────────

async function handleTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const cfg = loadConfig();

  function resolveVault(vaultArg: unknown): string {
    const v = (vaultArg as string | undefined) ?? cfg.defaultVault;
    if (!v) throw new Error('No vault specified and no default vault configured.');
    return v;
  }

  switch (name) {

    // ── Instance management ──────────────────────────────────────────────────

    case 'vault_list_instances': {
      const instances = Object.entries(cfg.vaults).map(([k, v]) => ({
        name: k,
        url: v.url,
        email: v.email,
        description: v.description ?? '',
        isDefault: k === cfg.defaultVault,
      }));
      return instances.length ? instances : 'No vault instances configured yet.';
    }

    case 'vault_add_instance': {
      const a = args as {
        name: string; url: string; clientId: string; clientSecret: string;
        masterPassword?: string; masterPasswordCmd?: string; masterPasswordPrompt?: boolean;
        email: string; description?: string; setAsDefault?: boolean;
      };
      if (!a.masterPassword && !a.masterPasswordCmd && !a.masterPasswordPrompt) {
        throw new Error('Provide one of: masterPassword, masterPasswordCmd, or masterPasswordPrompt=true.');
      }
      if (cfg.vaults[a.name]) throw new Error(`Instance "${a.name}" already exists. Remove it first.`);
      cfg.vaults[a.name] = {
        url: a.url, clientId: a.clientId, clientSecret: a.clientSecret,
        ...(a.masterPassword       ? { masterPassword:       a.masterPassword       } : {}),
        ...(a.masterPasswordCmd    ? { masterPasswordCmd:    a.masterPasswordCmd    } : {}),
        ...(a.masterPasswordPrompt ? { masterPasswordPrompt: a.masterPasswordPrompt } : {}),
        email: a.email, description: a.description,
      };
      if (a.setAsDefault || !cfg.defaultVault) cfg.defaultVault = a.name;
      saveConfig(cfg);
      auditLog('add_instance', a.name);
      return `Vault instance "${a.name}" added successfully.`;
    }

    case 'vault_remove_instance': {
      const { name: vName, confirmed } = args as { name: string; confirmed: boolean };
      if (!confirmed) return 'Set confirmed=true to remove the instance.';
      if (!cfg.vaults[vName]) throw new Error(`Instance "${vName}" not found.`);
      delete cfg.vaults[vName];
      if (cfg.defaultVault === vName) cfg.defaultVault = Object.keys(cfg.vaults)[0];
      clientCache.delete(vName);
      saveConfig(cfg);
      auditLog('remove_instance', vName);
      return `Vault instance "${vName}" removed.`;
    }

    // ── Password prompt ──────────────────────────────────────────────────────

    case 'vault_prompt_password': {
      const vaultName = resolveVault((args as { vault?: string }).vault);
      const client = getClient(vaultName);
      await client.promptAndCachePassword();
      auditLog('prompt_password', vaultName);
      return {
        status: 'ok',
        vault: vaultName,
        message: 'Password entered and cached in RAM. Vault will unlock on next operation.',
      };
    }

    // ── Connection check ─────────────────────────────────────────────────────

    case 'vault_check_connection': {
      const vaultName = resolveVault((args as { vault?: string }).vault);
      const instanceCfg = cfg.vaults[vaultName];
      const steps: Array<{ step: string; status: 'ok' | 'error'; detail?: string }> = [];

      // Step 1: bw CLI available
      try {
        const { execFile } = await import('child_process');
        const { promisify } = await import('util');
        const execFileAsync = promisify(execFile);
        const { stdout } = await execFileAsync('bw', ['--version']);
        steps.push({ step: 'bw CLI', status: 'ok', detail: `v${stdout.trim()}` });
      } catch {
        steps.push({ step: 'bw CLI', status: 'error', detail: 'Not found — install from https://bitwarden.com/help/cli/' });
        return { vault: vaultName, url: instanceCfg.url, steps, overall: 'error' };
      }

      // Step 2: Server reachable (HTTP HEAD)
      try {
        const res = await fetch(instanceCfg.url, { method: 'HEAD', signal: AbortSignal.timeout(8000) });
        steps.push({ step: 'server reachable', status: 'ok', detail: `HTTP ${res.status}` });
      } catch (err) {
        steps.push({ step: 'server reachable', status: 'error', detail: (err as Error).message });
        return { vault: vaultName, url: instanceCfg.url, steps, overall: 'error' };
      }

      // Step 3: Authenticate + unlock (ensureSession)
      try {
        const client = getClient(vaultName);
        await client.ensureSession();
        steps.push({ step: 'auth + unlock', status: 'ok' });
      } catch (err) {
        steps.push({ step: 'auth + unlock', status: 'error', detail: (err as Error).message });
        return { vault: vaultName, url: instanceCfg.url, steps, overall: 'error' };
      }

      // Step 4: Smoke-test list (1 item)
      try {
        const client = getClient(vaultName);
        const items = await client.listItems();
        steps.push({ step: 'list items', status: 'ok', detail: `${items.length} item(s) accessible` });
      } catch (err) {
        steps.push({ step: 'list items', status: 'error', detail: (err as Error).message });
        return { vault: vaultName, url: instanceCfg.url, steps, overall: 'error' };
      }

      auditLog('check_connection', vaultName);
      return { vault: vaultName, url: instanceCfg.url, steps, overall: 'ok' };
    }

    // ── Remote vault discovery ───────────────────────────────────────────────

    case 'vault_list_items': {
      const { vault, folder } = args as { vault?: string; folder?: string };
      const vaultName = resolveVault(vault);
      const client = getClient(vaultName);

      let folderId: string | undefined;
      if (folder) {
        const found = await client.findFolderByName(folder);
        folderId = found?.id;
      }

      const items = await client.listItems(folderId);
      auditLog('list_items', vaultName, undefined, folder ? { folder } : undefined);
      return items.length ? items : `No items found${folder ? ` in folder "${folder}"` : ''}.`;
    }

    case 'vault_search_items': {
      const { vault, query } = args as { vault?: string; query: string };
      const vaultName = resolveVault(vault);
      const items = await getClient(vaultName).searchItems(query);
      auditLog('search_items', vaultName, undefined, { query });
      return items.length ? items : `No items matching "${query}".`;
    }

    case 'vault_list_folders': {
      const vaultName = resolveVault((args as { vault?: string }).vault);
      return await getClient(vaultName).listFolders();
    }

    // ── Local search cache ───────────────────────────────────────────────────

    case 'vault_sync_cache': {
      const { vault } = args as { vault?: string };
      const vaultsToSync = vault
        ? [vault]
        : Object.keys(cfg.vaults);

      if (vaultsToSync.length === 0) return 'No vault instances configured.';

      const results = [];
      for (const vaultName of vaultsToSync) {
        const client = getClient(vaultName);
        await client.sync();
        const [items, folders] = await Promise.all([
          client.listItems(),
          client.listFolders(),
        ]);
        const folderMap = new Map(folders.map(f => [f.id, f.name]));
        const stats = cache.syncVault(vaultName, items, folderMap);
        auditLog('sync_cache', vaultName, undefined, {
          upserted: String(stats.upserted),
          removed: String(stats.removed),
        });
        results.push(stats);
      }
      return results;
    }

    case 'vault_search': {
      const { query, vault, limit, threshold } = args as {
        query: string; vault?: string; limit?: number; threshold?: number;
      };
      const totalCached = cache.getCachedItemCount(vault);
      if (totalCached === 0) {
        return vault
          ? `Cache is empty for vault "${vault}". Run vault_sync_cache first.`
          : 'Cache is empty. Run vault_sync_cache first.';
      }
      const results = cache.fuzzySearch(query, { vault, limit, threshold });
      auditLog('search_cache', vault ?? 'all', undefined, { query, hits: String(results.length) });
      if (results.length === 0) return `No results for "${query}". Try a shorter query or run vault_sync_cache to refresh.`;
      return results.map(r => ({
        id: r.id,
        vault: r.vault,
        name: r.name,
        type: r.type,
        folder: r.folderName,
        username: r.username,
        uris: r.uris,
        fieldNames: r.fieldNames,
        favorite: r.favorite,
        score: Math.round((1 - r.score) * 100) + '%',
      }));
    }

    case 'vault_cache_status': {
      const status = cache.getSyncStatus();
      if (status.length === 0) return 'Cache is empty. Run vault_sync_cache to populate it.';
      return status;
    }

    case 'vault_get_item': {
      const { vault, itemId } = args as { vault?: string; itemId: string };
      const vaultName = resolveVault(vault);
      const meta = await getClient(vaultName).getItemMeta(itemId);
      auditLog('get_item_meta', vaultName, itemId);
      return meta;
    }

    // ── Password reveal ──────────────────────────────────────────────────────

    case 'vault_reveal_password': {
      const { vault, itemId, confirmed, exposedToAI } = args as {
        vault?: string; itemId: string; confirmed: boolean; exposedToAI: boolean;
      };
      if (!confirmed) return 'Set confirmed=true as first confirmation.';
      if (!exposedToAI) {
        return 'Set exposedToAI=true as second confirmation, explicitly acknowledging that the AI will see the secret value in plaintext.';
      }
      const vaultName = resolveVault(vault);
      const sensitive = await getClient(vaultName).getItemSensitive(itemId);
      auditLog('reveal_password', vaultName, itemId);
      return sensitive;
    }

    // ── Remote vault CRUD ────────────────────────────────────────────────────

    case 'vault_create_item': {
      const a = args as {
        vault?: string; name: string; value: string; username?: string;
        type?: 'login' | 'note'; folder?: string; notes?: string; confirmed: boolean;
      };
      if (!a.confirmed) return 'Set confirmed=true to create the item.';
      const vaultName = resolveVault(a.vault);
      const client = getClient(vaultName);

      let folderId: string | null = null;
      if (a.folder) {
        const existing = await client.findFolderByName(a.folder);
        folderId = existing ? existing.id : (await client.createFolder(a.folder)).id;
      }

      const result = await client.createItem({
        name: a.name, value: a.value, username: a.username,
        type: a.type ?? 'login', folderId, notes: a.notes,
      });
      auditLog('create_item', vaultName, result.name);
      return { message: 'Item created.', id: result.id, name: result.name };
    }

    case 'vault_update_item': {
      const { vault, itemId, value, username, confirmed } = args as {
        vault?: string; itemId: string; value: string; username?: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to update the item.';
      const vaultName = resolveVault(vault);
      await getClient(vaultName).updateItemValue(itemId, value, username);
      auditLog('update_item', vaultName, itemId);
      return `Item "${itemId}" updated.`;
    }

    case 'vault_delete_item': {
      const { vault, itemId, confirmed } = args as {
        vault?: string; itemId: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to delete the item.';
      const vaultName = resolveVault(vault);
      await getClient(vaultName).deleteItem(itemId);
      auditLog('delete_item', vaultName, itemId);
      return `Item "${itemId}" deleted.`;
    }

    // ── Remote vault proxy ───────────────────────────────────────────────────

    case 'vault_run_command': {
      const { vault, command, envMappings, argRefs, stdinSecret, cwd } = args as {
        vault?: string; command: string[];
        envMappings?: Record<string, string>;
        argRefs?: Record<string, string>;
        stdinSecret?: string;
        cwd?: string;
      };
      const vaultName = resolveVault(vault);
      const client = getClient(vaultName);
      auditLog('run_command', vaultName, undefined, {
        cmd: command[0],
        vars: Object.keys(envMappings ?? {}).join(','),
        argRefs: Object.keys(argRefs ?? {}).join(','),
        stdin: stdinSecret ?? '',
      });
      return await inject.runCommandWithSecrets(
        n => client.resolveValue(n), command,
        { envMappings, argRefs, stdinSecret, cwd },
      );
    }

    case 'vault_write_file': {
      const { vault, outputPath, content, secretRefs } = args as {
        vault?: string; outputPath: string; content: string; secretRefs: Record<string, string>;
      };
      const vaultName = resolveVault(vault);
      const client = getClient(vaultName);
      auditLog('write_file', vaultName, undefined, {
        path: outputPath, items: Object.values(secretRefs).join(','),
      });
      await inject.writeFileWithSecrets(n => client.resolveValue(n), outputPath, content, secretRefs);
      return `File written to ${outputPath} with secrets injected (mode 600).`;
    }

    case 'vault_http_request': {
      const { vault, url, method, headers, body, secretRefs } = args as {
        vault?: string; url: string; method?: string;
        headers?: Record<string, string>; body?: string;
        secretRefs: Record<string, string>;
      };
      const vaultName = resolveVault(vault);
      const client = getClient(vaultName);
      auditLog('http_request', vaultName, undefined, {
        url, method: method ?? 'GET', items: Object.values(secretRefs).join(','),
      });
      return await inject.httpRequestWithSecrets(
        n => client.resolveValue(n), url, method ?? 'GET',
        { headers, body, secretRefs },
      );
    }

    // ── Secret scanning ───────────────────────────────────────────────────────

    case 'vault_scan_secrets': {
      const { path: dir } = args as { path: string };
      const result = secretScan.scanForSecrets(dir);
      auditLog('scan_secrets', 'local', undefined, { path: dir, findings: String(result.findings.length) });
      if (result.findings.length === 0) {
        return {
          scanned: result.scanned, usedGit: result.usedGit, findings: [],
          message: 'No likely hardcoded secrets found. Note: this is a heuristic scan, not a guarantee — still review manually before pushing anything sensitive.',
        };
      }
      return {
        scanned: result.scanned, usedGit: result.usedGit, findings: result.findings,
        action_required:
          'Do NOT push yet. For each finding: move the real value into the project vault ' +
          '(vault_init_project if needed, then vault_project_create_item), replace the hardcoded value in the ' +
          'file with a {{placeholder}}, and inject it at runtime via vault_project_run_command / ' +
          'vault_project_write_file / vault_project_http_request instead. Re-run vault_scan_secrets to confirm ' +
          'the tree is clean before pushing.',
      };
    }

    // ── Browser automation ───────────────────────────────────────────────────

    case 'vault_browser_fill': {
      const {
        vault, url, fields, submitSelector, waitForSelector,
        extractSelector, screenshot, headless, timeout, extraHeaders,
      } = args as {
        vault?: string; url: string; fields: Record<string, string>;
        submitSelector?: string; waitForSelector?: string; extractSelector?: string;
        screenshot?: boolean; headless?: boolean; timeout?: number;
        extraHeaders?: Record<string, string>;
      };
      const vaultName = resolveVault(vault);
      const client = getClient(vaultName);
      auditLog('browser_fill', vaultName, undefined, { url, selectors: Object.keys(fields).join(',') });
      return await browser.browserFillForm(
        n => client.resolveValue(n),
        url,
        { fields, submitSelector, waitForSelector, extractSelector, screenshot, headless, timeout, extraHeaders },
      );
    }

    // ── Favorites vault ──────────────────────────────────────────────────────

    case 'vault_favorites_add': {
      const { vault, itemId, passphrase, alias, confirmed } = args as {
        vault?: string; itemId: string; passphrase: string; alias?: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to add the item to favorites.';
      if (!passphrase?.trim()) throw new Error('passphrase must not be empty.');

      const vaultName = resolveVault(vault);
      const client = getClient(vaultName);

      // Fetch the full item (including sensitive data) from the remote vault
      const raw = await client.getItemForFavorites(itemId);

      const meta = await fv.addFavorite(passphrase, {
        name: alias ?? raw.name,
        sourceVault: vaultName,
        sourceItemId: raw.id,
        sourceType: raw.type,
        username: raw.login?.username ?? null,
        password: raw.login?.password ?? null,
        notes: raw.notes ?? null,
        uris: (raw.login?.uris ?? []).map(u => u.uri).filter(Boolean),
        fields: (raw.fields ?? []).map(f => ({ name: f.name, value: f.value, type: f.type })),
      });

      auditLog('favorites_add', vaultName, raw.id, { alias: alias ?? raw.name });
      return { message: `"${meta.name}" added to favorites.`, ...meta };
    }

    case 'vault_favorites_list': {
      const { passphrase } = args as { passphrase: string };
      if (!passphrase?.trim()) throw new Error('passphrase must not be empty.');
      const items = fv.listFavorites(passphrase);
      auditLog('favorites_list', 'local');
      return items.length ? items : 'No favorites saved yet.';
    }

    case 'vault_favorites_get': {
      const { passphrase, nameOrId, confirmed, exposedToAI } = args as {
        passphrase: string; nameOrId: string; confirmed: boolean; exposedToAI: boolean;
      };
      if (!confirmed) return 'Set confirmed=true as first confirmation.';
      if (!exposedToAI) {
        return 'Set exposedToAI=true as second confirmation, explicitly acknowledging that the AI will see the password.';
      }
      if (!passphrase?.trim()) throw new Error('passphrase must not be empty.');
      const item = fv.getFavoriteSensitive(passphrase, nameOrId);
      auditLog('favorites_get_sensitive', 'local', item.id);
      return item;
    }

    case 'vault_favorites_remove': {
      const { passphrase, nameOrId, confirmed } = args as {
        passphrase: string; nameOrId: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to remove the favorite.';
      if (!passphrase?.trim()) throw new Error('passphrase must not be empty.');
      fv.removeFavorite(passphrase, nameOrId);
      auditLog('favorites_remove', 'local', nameOrId);
      return `Favorite "${nameOrId}" removed.`;
    }

    case 'vault_favorites_update': {
      const { passphrase, nameOrId, confirmed } = args as {
        passphrase: string; nameOrId: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to refresh the favorite.';
      if (!passphrase?.trim()) throw new Error('passphrase must not be empty.');

      // Find the existing favorite to get source vault info
      const existing = fv.getFavoriteSensitive(passphrase, nameOrId);
      const vaultName = existing.sourceVault;
      const client = getClient(vaultName);
      const raw = await client.getItemForFavorites(existing.sourceItemId);

      const updated = fv.updateFavorite(passphrase, nameOrId, {
        username: raw.login?.username ?? null,
        password: raw.login?.password ?? null,
        notes: raw.notes ?? null,
        uris: (raw.login?.uris ?? []).map(u => u.uri).filter(Boolean),
        fields: (raw.fields ?? []).map(f => ({ name: f.name, value: f.value, type: f.type })),
      });

      auditLog('favorites_update', vaultName, existing.sourceItemId);
      return { message: `Favorite "${updated.name}" refreshed from source vault.`, ...updated };
    }

    // ── Project vault setup ──────────────────────────────────────────────────

    case 'vault_init_project': {
      const { projectDir, name: projectName, commit } = args as { projectDir: string; name: string; commit?: boolean };
      const { marker, totpSeedBase32, totpUri, vaultKeyHex } = pv.initProjectVault(cfg.masterKey, projectDir, projectName, { commit });
      auditLog('init_project', 'project', marker.id, { dir: projectDir, storage: marker.storage });
      return {
        message: 'Project vault initialised.',
        id: marker.id,
        name: marker.name,
        storage: marker.storage,
        totpEnabled: marker.totpEnabled,
        markerFile: `${projectDir}/.vault-project`,
        vaultFile: marker.storage === 'committed' ? `${projectDir}/.vault-project.enc` : undefined,
        note: marker.storage === 'committed'
          ? '.vault-project and .vault-project.enc are both safe to commit — decryption requires the dedicated ' +
            'vault key AND the TOTP seed below, both local to this machine. This machine\'s shared master key plays ' +
            'no role for committed vaults at all.'
          : '.vault-project is safe to commit — it contains only a UUID. The encrypted vault itself stays local to this machine.',
        ...(totpSeedBase32 && vaultKeyHex ? {
          totpSeedBase32,
          totpUri,
          vaultKeyHex,
          backupWarning: 'BACK BOTH totpSeedBase32 AND vaultKeyHex UP NOW as two separate secrets (e.g. as two note ' +
            'items in a Bitwarden vault — never commit them to this repo). Both are shown only once. Either one ' +
            'alone is insufficient; losing either one on every machine makes this committed vault permanently ' +
            'undecryptable.',
        } : {}),
      };
    }

    case 'vault_project_info': {
      const { projectDir } = args as { projectDir: string };
      const info = pv.getProjectInfo(projectDir);
      if (!info) return `No project vault at "${projectDir}".`;
      const items = pv.listProjectItems(cfg.masterKey, projectDir);
      return { ...info, itemCount: items.length };
    }

    case 'vault_project_totp_enable': {
      const { projectDir } = args as { projectDir: string };
      const { totpSeedBase32, totpUri } = pv.enableTotp(cfg.masterKey, projectDir);
      const info = pv.getProjectInfo(projectDir)!;
      auditLog('project_totp_enable', 'project', info.id);
      return {
        message: `TOTP enabled for project vault "${info.name}".`,
        totpSeedBase32,
        totpUri,
        totpWarning: 'BACK THIS SEED UP NOW (e.g. as a note item in a Bitwarden vault). It is shown only once. ' +
          'Without it, this vault becomes permanently undecryptable if this machine is lost.',
      };
    }

    case 'vault_project_enable_commit_storage': {
      const { projectDir } = args as { projectDir: string };
      const { vaultKeyHex } = pv.enableCommitStorage(cfg.masterKey, projectDir);
      const info = pv.getProjectInfo(projectDir)!;
      auditLog('project_enable_commit_storage', 'project', info.id);
      return {
        message: `Project vault "${info.name}" moved to committable storage.`,
        vaultFile: `${projectDir}/.vault-project.enc`,
        vaultKeyHex,
        backupWarning: 'BACK vaultKeyHex UP NOW (e.g. as a note item in a Bitwarden vault — never commit it to ' +
          'this repo). It is shown only once. Decryption now requires this dedicated vault key AND the TOTP seed ' +
          '— this machine\'s shared master key is no longer used for this vault at all.',
        note: 'Both .vault-project and .vault-project.enc are now safe to commit and push.',
      };
    }

    // ── Project vault item management ────────────────────────────────────────

    case 'vault_project_list_items': {
      const { projectDir } = args as { projectDir: string };
      const items = pv.listProjectItems(cfg.masterKey, projectDir);
      auditLog('project_list', 'project', projectDir);
      return items.length ? items : 'No items in project vault.';
    }

    case 'vault_project_create_item': {
      const { projectDir, name: itemName, value, confirmed } = args as {
        projectDir: string; name: string; value: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to create the item.';
      const meta = pv.createProjectItem(cfg.masterKey, projectDir, itemName, value);
      auditLog('project_create', 'project', itemName, { dir: projectDir });
      return { message: 'Item created.', ...meta };
    }

    case 'vault_project_update_item': {
      const { projectDir, nameOrId, value, confirmed } = args as {
        projectDir: string; nameOrId: string; value: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to update the item.';
      pv.updateProjectItem(cfg.masterKey, projectDir, nameOrId, value);
      auditLog('project_update', 'project', nameOrId, { dir: projectDir });
      return `Item "${nameOrId}" updated.`;
    }

    case 'vault_project_delete_item': {
      const { projectDir, nameOrId, confirmed } = args as {
        projectDir: string; nameOrId: string; confirmed: boolean;
      };
      if (!confirmed) return 'Set confirmed=true to delete.';
      pv.deleteProjectItem(cfg.masterKey, projectDir, nameOrId);
      auditLog('project_delete', 'project', nameOrId, { dir: projectDir });
      return `Item "${nameOrId}" deleted.`;
    }

    // ── Project vault proxy ──────────────────────────────────────────────────

    case 'vault_project_run_command': {
      const { projectDir, command, envMappings, argRefs, stdinSecret, cwd } = args as {
        projectDir: string; command: string[];
        envMappings?: Record<string, string>;
        argRefs?: Record<string, string>;
        stdinSecret?: string;
        cwd?: string;
      };
      auditLog('project_run', 'project', undefined, {
        dir: projectDir, cmd: command[0], vars: Object.keys(envMappings ?? {}).join(','),
      });
      return await inject.runCommandWithSecrets(
        n => Promise.resolve(pv.resolveProjectValue(cfg.masterKey, projectDir, n)),
        command, { envMappings, argRefs, stdinSecret, cwd },
      );
    }

    case 'vault_project_write_file': {
      const { projectDir, outputPath, content, secretRefs } = args as {
        projectDir: string; outputPath: string; content: string; secretRefs: Record<string, string>;
      };
      auditLog('project_write_file', 'project', undefined, { dir: projectDir, path: outputPath });
      await inject.writeFileWithSecrets(
        n => Promise.resolve(pv.resolveProjectValue(cfg.masterKey, projectDir, n)),
        outputPath, content, secretRefs,
      );
      return `File written to ${outputPath} with project secrets injected.`;
    }

    case 'vault_project_http_request': {
      const { projectDir, url, method, headers, body, secretRefs } = args as {
        projectDir: string; url: string; method?: string;
        headers?: Record<string, string>; body?: string; secretRefs: Record<string, string>;
      };
      auditLog('project_http', 'project', undefined, { dir: projectDir, url });
      return await inject.httpRequestWithSecrets(
        n => Promise.resolve(pv.resolveProjectValue(cfg.masterKey, projectDir, n)),
        url, method ?? 'GET', { headers, body, secretRefs },
      );
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);

// Background sync on startup — non-blocking, MCP is immediately ready.
// Runs once per process lifetime; errors are logged but never crash the server.
(async () => {
  const cfg = loadConfig();
  const vaultNames = Object.keys(cfg.vaults);
  if (vaultNames.length === 0) return;

  for (const vaultName of vaultNames) {
    try {
      const client = getClient(vaultName);
      await client.sync();
      const [items, folders] = await Promise.all([
        client.listItems(),
        client.listFolders(),
      ]);
      const folderMap = new Map(folders.map(f => [f.id, f.name]));
      const stats = cache.syncVault(vaultName, items, folderMap);
      auditLog('auto_sync_cache', vaultName, undefined, {
        upserted: String(stats.upserted),
        removed: String(stats.removed),
      });
    } catch {
      // Vault unreachable or not yet configured — silently skip
    }
  }
})();
