/**
 * Shared injection logic for both remote and project vaults.
 * Secrets are fetched, used in-memory, and never returned to the caller.
 */

import { spawn } from 'child_process';
import { writeFileSync, readFileSync, existsSync } from 'fs';
import { dirname } from 'path';
import { mkdirSync } from 'fs';

export type Resolver = (nameOrId: string) => Promise<string>;

/**
 * Replace a single placeholder in `template` with `value`.
 * Prefers the delimited forms `{{name}}` / `${name}` over the bare name, so a
 * placeholder wrapped in braces is consumed whole instead of leaving the braces
 * behind (which would silently corrupt the injected secret). Returns whether any
 * occurrence was replaced so callers can fail loudly on an unused ref.
 */
function applyRef(template: string, placeholder: string, value: string): { out: string; replaced: boolean } {
  const candidates = [`{{${placeholder}}}`, '${' + placeholder + '}', placeholder];
  for (const token of candidates) {
    if (template.includes(token)) {
      return { out: template.replaceAll(token, value), replaced: true };
    }
  }
  return { out: template, replaced: false };
}

function injectRefs(template: string, refs: Record<string, string>, resolved: Map<string, string>): string {
  let out = template;
  for (const [placeholder, nameOrId] of Object.entries(refs)) {
    const val = resolved.get(nameOrId);
    if (val === undefined) throw new Error(`Could not resolve secret ref "${nameOrId}".`);
    const r = applyRef(out, placeholder, val);
    if (!r.replaced) {
      throw new Error(`Placeholder for secret ref "${placeholder}" not found in template. Reference it as {{${placeholder}}} in your request.`);
    }
    out = r.out;
  }
  return out;
}

/**
 * Same substitution as `injectRefs`, but spread across several independent string
 * fields (e.g. one per header, plus the body) instead of a single template. A
 * placeholder only has to appear in *one* of the fields — an HTTP request commonly
 * has some fields that carry no secret at all (a `Content-Type` header) and others
 * that do, so requiring every ref in every field would reject perfectly valid
 * requests. Still throws loudly if a ref never appears anywhere, so an unused ref
 * can't silently leak the intent to inject.
 */
function injectRefsAcrossFields(
  fields: (string | undefined)[],
  refs: Record<string, string>,
  resolved: Map<string, string>,
): (string | undefined)[] {
  let outs = fields;
  for (const [placeholder, nameOrId] of Object.entries(refs)) {
    const val = resolved.get(nameOrId);
    if (val === undefined) throw new Error(`Could not resolve secret ref "${nameOrId}".`);
    let anyReplaced = false;
    outs = outs.map(field => {
      if (field === undefined) return field;
      const r = applyRef(field, placeholder, val);
      if (r.replaced) anyReplaced = true;
      return r.out;
    });
    if (!anyReplaced) {
      throw new Error(`Placeholder for secret ref "${placeholder}" not found in any header or body value. Reference it as {{${placeholder}}} in your request.`);
    }
  }
  return outs;
}

async function resolveAll(
  resolver: Resolver,
  refs: Record<string, string>,
): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  const uniqueItems = [...new Set(Object.values(refs))];
  await Promise.all(uniqueItems.map(async (nameOrId) => {
    map.set(nameOrId, await resolver(nameOrId));
  }));
  return map;
}

export interface RunCommandOptions {
  /** ENV_VAR_NAME → vault item name/ID — injected as environment variables. */
  envMappings?: Record<string, string>;
  /**
   * Placeholder → vault item name/ID — substituted into command args before spawning.
   * NOTE: args are visible in /proc/<pid>/cmdline. Use envMappings when the tool supports it.
   */
  argRefs?: Record<string, string>;
  /** Vault item name/ID whose value is written to the process's stdin, then stdin is closed. */
  stdinSecret?: string;
  cwd?: string;
}

/** What to spawn after secrets are resolved — secret values live only in here, never returned. */
export interface InjectionPlan {
  /** Env vars (ENV_VAR → secret value) to merge into the child environment. */
  env: Record<string, string>;
  /** Child argv (command[1..]) with arg placeholders substituted. */
  args: string[];
  /** Value to pipe to stdin, or null if no stdinSecret was given. */
  stdinValue: string | null;
}

/**
 * Resolve every secret ref and build the concrete env / args / stdin for a child
 * process. Pure orchestration over the resolver — no process is spawned here, so
 * both the capturing runner and the stdio-inherit launcher can share one code path.
 * Throws loudly on an arg placeholder that never appears, so an unused ref can't
 * silently leak the intent to inject.
 */
export async function prepareInjection(
  resolver: Resolver,
  command: string[],
  opts: Pick<RunCommandOptions, 'envMappings' | 'argRefs' | 'stdinSecret'>,
): Promise<InjectionPlan> {
  if (command.length === 0) throw new Error('command must not be empty.');

  const allRefs: Record<string, string> = {
    ...(opts.envMappings ?? {}),
    ...(opts.argRefs ?? {}),
    ...(opts.stdinSecret ? { __stdin__: opts.stdinSecret } : {}),
  };
  const resolved = await resolveAll(resolver, allRefs);

  // Build env
  const env: Record<string, string> = {};
  for (const [envVar, nameOrId] of Object.entries(opts.envMappings ?? {})) {
    env[envVar] = resolved.get(nameOrId)!;
  }

  // Substitute argRefs into command args. A placeholder may live in only one of
  // several args, so we require it to appear in at least one arg overall.
  let args = command.slice(1);
  if (opts.argRefs && Object.keys(opts.argRefs).length > 0) {
    for (const [placeholder, nameOrId] of Object.entries(opts.argRefs)) {
      const val = resolved.get(nameOrId)!;
      let anyReplaced = false;
      args = args.map(arg => {
        const r = applyRef(arg, placeholder, val);
        if (r.replaced) anyReplaced = true;
        return r.out;
      });
      if (!anyReplaced) {
        throw new Error(`Placeholder for arg ref "${placeholder}" not found in command args. Reference it as {{${placeholder}}}.`);
      }
    }
  }

  const stdinValue = opts.stdinSecret ? resolved.get(opts.stdinSecret) ?? null : null;
  return { env, args, stdinValue };
}

export async function runCommandWithSecrets(
  resolver: Resolver,
  command: string[],
  options: RunCommandOptions | Record<string, string>, // backwards-compat: plain envMappings object
  cwd?: string,
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  if (command.length === 0) throw new Error('command must not be empty.');

  // Backwards-compatibility: old callers pass envMappings directly as third arg
  let opts: RunCommandOptions;
  if (typeof options === 'object' && !('envMappings' in options) && !('argRefs' in options) && !('stdinSecret' in options)) {
    opts = { envMappings: options as Record<string, string>, cwd };
  } else {
    opts = options as RunCommandOptions;
    if (cwd && !opts.cwd) opts = { ...opts, cwd };
  }

  const { env: injectedEnv, args: finalArgs, stdinValue } = await prepareInjection(resolver, command, opts);

  return new Promise((res, rej) => {
    const proc = spawn(command[0], finalArgs, {
      env: { ...process.env, ...injectedEnv },
      cwd: opts.cwd ?? process.cwd(),
      stdio: [stdinValue !== null ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    });

    if (stdinValue !== null && proc.stdin) {
      proc.stdin.write(stdinValue);
      proc.stdin.end();
    }

    let stdout = '';
    let stderr = '';
    proc.stdout?.on('data', (d: Buffer) => { stdout += d.toString(); });
    proc.stderr?.on('data', (d: Buffer) => { stderr += d.toString(); });
    proc.on('close', code => res({ stdout, stderr, exitCode: code ?? 0 }));
    proc.on('error', rej);
  });
}

export async function writeFileWithSecrets(
  resolver: Resolver,
  outputPath: string,
  content: string,
  secretRefs: Record<string, string>,
): Promise<void> {
  const resolved = await resolveAll(resolver, secretRefs);
  const filled = injectRefs(content, secretRefs, resolved);

  const dir = dirname(outputPath);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  writeFileSync(outputPath, filled, { mode: 0o600 });
}

export async function httpRequestWithSecrets(
  resolver: Resolver,
  url: string,
  method: string,
  options: {
    headers?: Record<string, string>;
    body?: string;
    secretRefs: Record<string, string>;
  },
): Promise<{ status: number; statusText: string; headers: Record<string, string>; body: string }> {
  const resolved = await resolveAll(resolver, options.secretRefs);

  const headerEntries = Object.entries(options.headers ?? {});
  const fields: (string | undefined)[] = [...headerEntries.map(([, v]) => v), options.body];
  const outFields = injectRefsAcrossFields(fields, options.secretRefs, resolved);

  const finalHeaders: Record<string, string> = {};
  headerEntries.forEach(([k], i) => { finalHeaders[k] = outFields[i]!; });

  const finalBody = outFields[outFields.length - 1];

  const response = await fetch(url, { method, headers: finalHeaders, body: finalBody });
  const body = await response.text();

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((v, k) => { responseHeaders[k] = v; });

  return { status: response.status, statusText: response.statusText, headers: responseHeaders, body };
}
