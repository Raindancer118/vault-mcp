/**
 * Secure master-password prompt — shows a native GUI dialog or a local browser form.
 * The password is returned to the caller and never written to disk or passed through Claude.
 *
 * Priority:
 *   1. zenity  (GTK/GNOME, X11 + Wayland)
 *   2. kdialog (Qt/KDE)
 *   3. Local HTTP form  (universal fallback — opens browser via xdg-open)
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { createServer, type IncomingMessage, type ServerResponse } from 'http';
import { randomBytes } from 'crypto';

const execAsync = promisify(exec);

const PROMPT_TITLE = 'Vault MCP — Master Password';
const HTTP_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// ─── GUI dialogs ──────────────────────────────────────────────────────────────

async function tryZenity(vaultName: string): Promise<string | null> {
  try {
    const { stdout } = await execAsync(
      `zenity --password --title="${PROMPT_TITLE}" --text="Enter master password for vault <b>${vaultName}</b>:"`,
      { timeout: HTTP_TIMEOUT_MS },
    );
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

async function tryKdialog(vaultName: string): Promise<string | null> {
  try {
    const { stdout } = await execAsync(
      `kdialog --password "Enter master password for vault '${vaultName}':" --title "${PROMPT_TITLE}"`,
      { timeout: HTTP_TIMEOUT_MS },
    );
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

// ─── HTTP fallback ────────────────────────────────────────────────────────────

function buildHtml(vaultName: string, token: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${PROMPT_TITLE}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, sans-serif;
      background: #0f1117;
      color: #e2e8f0;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #1a1d27;
      border: 1px solid #2d3148;
      border-radius: 12px;
      padding: 2rem;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .icon { font-size: 2rem; margin-bottom: 1rem; text-align: center; }
    h1 { font-size: 1.1rem; font-weight: 600; margin-bottom: 0.4rem; }
    .vault-name {
      color: #7c83ff;
      font-size: 0.9rem;
      margin-bottom: 1.5rem;
      word-break: break-all;
    }
    label { font-size: 0.8rem; color: #94a3b8; display: block; margin-bottom: 0.4rem; }
    input[type=password] {
      width: 100%;
      padding: 0.65rem 0.9rem;
      background: #0f1117;
      border: 1px solid #2d3148;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 1rem;
      outline: none;
      transition: border-color 0.15s;
    }
    input[type=password]:focus { border-color: #7c83ff; }
    button {
      width: 100%;
      margin-top: 1.2rem;
      padding: 0.7rem;
      background: #7c83ff;
      border: none;
      border-radius: 8px;
      color: #fff;
      font-size: 0.95rem;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s;
    }
    button:hover { background: #6670ee; }
    .note {
      margin-top: 1.2rem;
      font-size: 0.75rem;
      color: #64748b;
      text-align: center;
      line-height: 1.5;
    }
    .success { text-align: center; padding: 1rem 0; }
    .success p { color: #4ade80; font-weight: 600; margin-bottom: 0.5rem; }
    .success small { color: #64748b; font-size: 0.8rem; }
  </style>
</head>
<body>
  <div class="card" id="form-card">
    <div class="icon">🔐</div>
    <h1>${PROMPT_TITLE}</h1>
    <div class="vault-name">${vaultName}</div>
    <form method="POST" action="/${token}" id="form">
      <label for="pw">Master Password</label>
      <input type="password" id="pw" name="password" autofocus autocomplete="current-password" required>
      <button type="submit">Unlock Vault</button>
    </form>
    <p class="note">
      This password is sent only to the local vault-mcp process on your machine.<br>
      It is never stored on disk or shared with Claude.
    </p>
  </div>
  <script>
    document.getElementById('form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      await fetch('/${token}', { method: 'POST', body: new URLSearchParams(fd) });
      document.getElementById('form-card').innerHTML =
        '<div class="success"><p>✓ Password submitted</p><small>You can close this tab.</small></div>';
    });
  </script>
</body>
</html>`;
}

async function findFreePort(): Promise<number> {
  return new Promise((res, rej) => {
    const srv = createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === 'object') res(addr.port);
        else rej(new Error('Could not bind port'));
      });
    });
  });
}

async function httpPrompt(vaultName: string): Promise<string | null> {
  const token = randomBytes(20).toString('hex');
  const port = await findFreePort();
  const url = `http://127.0.0.1:${port}/${token}`;

  return new Promise((resolve) => {
    let resolved = false;

    const server = createServer((req: IncomingMessage, res: ServerResponse) => {
      if (req.method === 'GET' && req.url === `/${token}`) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(buildHtml(vaultName, token));
        return;
      }

      if (req.method === 'POST' && req.url === `/${token}`) {
        let body = '';
        req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        req.on('end', () => {
          const password = new URLSearchParams(body).get('password') ?? '';
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('ok');
          if (!resolved) {
            resolved = true;
            server.close();
            resolve(password || null);
          }
        });
        return;
      }

      res.writeHead(404).end();
    });

    server.listen(port, '127.0.0.1', () => {
      // Try to open browser; also log URL to stderr so it's visible in Claude Code's MCP logs
      execAsync(`xdg-open "${url}"`).catch(() => {
        execAsync(`open "${url}"`).catch(() => {}); // macOS fallback
      });
      process.stderr.write(`[vault-mcp] Password prompt: ${url}\n`);
    });

    setTimeout(() => {
      if (!resolved) {
        resolved = true;
        server.close();
        resolve(null);
      }
    }, HTTP_TIMEOUT_MS);
  });
}

// ─── Public API ───────────────────────────────────────────────────────────────

const hasDisplay = Boolean(process.env.DISPLAY || process.env.WAYLAND_DISPLAY);

/**
 * Prompt the user for a master password via the best available method.
 * Returns the password string, or throws if the user cancels or times out.
 */
export async function promptMasterPassword(vaultName: string): Promise<string> {
  let password: string | null = null;

  if (hasDisplay) {
    password = await tryKdialog(vaultName);
    if (!password) password = await tryZenity(vaultName);
  }

  if (!password) {
    password = await httpPrompt(vaultName);
  }

  if (!password) {
    throw new Error(
      `Master password prompt cancelled or timed out for vault "${vaultName}".`,
    );
  }

  return password;
}
