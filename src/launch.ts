#!/usr/bin/env node
/**
 * vault-launch — a secret-injecting launcher for *other* MCP servers (or any
 * long-running command), modelled on `op run --` / `aws-vault exec --`.
 *
 * Instead of letting Claude Code spawn a downstream MCP directly, point Claude
 * Code at this launcher. It resolves secrets from a vault, spawns the real MCP
 * as a child with those secrets injected as environment variables, and wires the
 * child's stdio straight through (`stdio: 'inherit'`). The child speaks the MCP
 * protocol directly to Claude Code; the launcher never touches the byte stream
 * and the secret never crosses the model's context window.
 *
 * Because injection happens at the environment boundary — exactly how the vast
 * majority of MCP servers already accept credentials — the wrapped MCP needs no
 * code changes whatsoever. Any MCP you install later works the same way.
 *
 * Claude Code mcpServers entry:
 *   {
 *     "cis": {
 *       "command": "node",
 *       "args": [
 *         "/abs/path/vault-mcp/dist/launch.js",
 *         "--vault", "nak",
 *         "--env", "CIS_USER=nordakademie.de:username",
 *         "--env", "CIS_PASS=nordakademie.de:password",
 *         "--", "/abs/path/cis-api/cis", "mcp"
 *       ]
 *     }
 *   }
 *
 * Flags (everything after `--` is the child command + its args):
 *   --vault <name>         Vault instance to unlock. Omit to use the default vault.
 *   --env  VAR=ItemRef     Inject secret as env var VAR. Repeatable.
 *   --arg  PH=ItemRef      Substitute placeholder PH in the child args. Repeatable.
 *
 * ItemRef uses the same syntax as the rest of vault-mcp:
 *   "Item"            → primary value (password)
 *   "Item:username"   → login username
 *   "Item:My Field"   → custom field
 *
 * IMPORTANT: nothing is ever written to stdout — that fd belongs to the child's
 * MCP JSON-RPC stream. All launcher diagnostics go to stderr.
 */
import { spawn } from 'child_process';
import { realpathSync } from 'fs';
import { fileURLToPath } from 'url';
import { loadConfig } from './config/loader.js';
import { BitwardenClient } from './vault/bw-client.js';
import { prepareInjection } from './tools/inject.js';

export interface ParsedLaunchArgs {
  vault?: string;
  envMappings: Record<string, string>;
  argRefs: Record<string, string>;
  /** Child command + args (command[0] is the executable). */
  command: string[];
}

/**
 * Parse launcher argv (excluding `node launch.js`). Everything before `--` is a
 * launcher flag; everything after `--` is the child command verbatim. Values may
 * contain `=` (only the first `=` separates VAR from the ref).
 */
export function parseLaunchArgs(argv: string[]): ParsedLaunchArgs {
  const envMappings: Record<string, string> = {};
  const argRefs: Record<string, string> = {};
  let vault: string | undefined;

  const splitPair = (raw: string | undefined, flag: string): [string, string] => {
    if (raw === undefined) throw new Error(`${flag} requires an argument of the form NAME=ItemRef.`);
    const eq = raw.indexOf('=');
    if (eq <= 0) throw new Error(`${flag} argument "${raw}" must be of the form NAME=ItemRef.`);
    return [raw.slice(0, eq), raw.slice(eq + 1)];
  };

  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { i++; break; }
    if (a === '--vault') {
      vault = argv[++i];
      if (vault === undefined) throw new Error('--vault requires a value.');
    } else if (a === '--env') {
      const [k, v] = splitPair(argv[++i], '--env');
      envMappings[k] = v;
    } else if (a === '--arg') {
      const [k, v] = splitPair(argv[++i], '--arg');
      argRefs[k] = v;
    } else {
      throw new Error(`Unknown launch flag "${a}". Put the child command after a "--" separator.`);
    }
  }

  const command = argv.slice(i);
  if (command.length === 0) {
    throw new Error('No child command given. Usage: vault-launch [--vault N] [--env VAR=Ref]... -- <command> [args...]');
  }
  return { vault, envMappings, argRefs, command };
}

async function main(): Promise<void> {
  const parsed = parseLaunchArgs(process.argv.slice(2));

  const cfg = loadConfig();
  const vaultName = parsed.vault ?? cfg.defaultVault;
  if (!vaultName) throw new Error('No vault specified and no default vault configured.');
  const instanceCfg = cfg.vaults[vaultName];
  if (!instanceCfg) throw new Error(`Vault instance "${vaultName}" is not configured.`);

  const client = new BitwardenClient(vaultName, instanceCfg);

  const { env, args } = await prepareInjection(
    (ref) => client.resolveValue(ref),
    parsed.command,
    { envMappings: parsed.envMappings, argRefs: parsed.argRefs },
  );

  const child = spawn(parsed.command[0], args, {
    stdio: 'inherit',
    env: { ...process.env, ...env },
  });

  // Forward termination signals so the child shuts down cleanly with the launcher.
  const forward = (sig: NodeJS.Signals) => () => { if (child.exitCode === null) child.kill(sig); };
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  for (const sig of signals) process.on(sig, forward(sig));

  child.on('error', (err) => {
    process.stderr.write(`vault-launch: failed to start child "${parsed.command[0]}": ${err.message}\n`);
    process.exit(127);
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      // Re-raise the signal so our exit status mirrors the child's.
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 0);
  });
}

/** True only when this file is the process entrypoint (not imported by a test). */
function isMainModule(): boolean {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMainModule()) {
  main().catch((err) => {
    process.stderr.write(`vault-launch: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
