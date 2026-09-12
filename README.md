# vault-mcp

MCP-Server für sicheres Secrets-Management. Claude kann Secrets suchen, verwalten und
in Kommandos/Dateien/HTTP-Requests injizieren — sieht die eigentlichen Werte dabei aber
so selten wie möglich, und nur wenn es doppelt bestätigt wurde.

## Warum

Ein LLM-Agent, der direkt mit `.env`-Dateien oder einem Passwortmanager im Klartext
arbeitet, sieht jeden Wert, den er anfasst — und jeder gesehene Wert landet im
Modell-Kontext (Logs, Konversationsverlauf). `vault-mcp` schiebt eine Proxy-Schicht
dazwischen: die meisten Tools injizieren Secrets direkt in Env-Variablen, Dateien oder
HTTP-Requests, ohne sie zurückzugeben. Wo ein Wert wirklich offengelegt werden muss
(`vault_reveal_password` u.ä.), ist das ein expliziter, doppelt bestätigter Sonderfall.

## Architektur

### Remote Vaults (Vaultwarden / Bitwarden)
- Wrapper um die `bw`-CLI — handhabt Ende-zu-Ende-Verschlüsselung transparent
- Jede Instanz bekommt ein isoliertes Datenverzeichnis: `~/.cache/vault-mcp/bw-data/<name>/`
- Session-Token bleibt im RAM (TTL 18 min) und wird für Wiederverwendung über mehrere
  vault-mcp-Prozesse hinweg zusätzlich mode-600 auf Disk gespiegelt
- Konfiguration: `~/.config/vault-mcp/config.json` (mode 600)
- Master-Passwort: entweder als Klartext in der Config (nicht empfohlen), per Shell-Command
  (`masterPasswordCmd`, z.B. `secret-tool lookup ...`) oder per GUI-/Browser-Prompt
  (`masterPasswordPrompt`) — landet in letzterem Fall nur im RAM, nie auf Disk

### Project Vaults (lokal, pro Git-Repo)
- Kleiner, lokaler Secret-Store für genau die Handvoll Secrets, die ein einzelnes Repo
  zur Laufzeit braucht — **kein** Sync/Export eines vollständigen Bitwarden-Vaults
- AES-256-GCM-verschlüsselte Datei, standardmäßig außerhalb des Repos unter
  `~/.config/vault-mcp/projects/<uuid>.vault`
- Key: HKDF(SHA-256, masterKey, projectId, `"vault-mcp-project-v1"`, 32 Bytes)
- MasterKey: 32 zufällige Bytes, einmalig in `config.json` generiert
- `.vault-project`-Markerdatei im Repo-Root (nur UUID + Name) — sicher commitbar
- Optional **committable**: `vault_init_project(..., commit: true)` bzw.
  `vault_project_enable_commit_storage` legt die verschlüsselte Datei selbst
  (`.vault-project.enc`) im Repo ab. Das erzwingt TOTP-Schutz und einen dedizierten,
  vom geteilten Master-Key unabhängigen 512-Bit-Vault-Key — beide nur lokal, automatisch
  gespiegelt unter `~/.claude/vault-mcp-backups/`, niemals im Repo. Ein Leak des
  geteilten Master-Keys hat damit keine Auswirkung auf eine committete Vault-Datei.

### Favorites Vault (lokal, passphrasengeschützt)
- AES-256-GCM-verschlüsselte Datei: `~/.config/vault-mcp/favorites.vault`
- Key: `scrypt(passphrase, salt, N=65536, r=8, p=1)` — Passphrase/Key niemals auf Disk
- Salt (32 Bytes) im File-Header, öffentlich, kein Secret
- File-Layout: `[salt 32B | IV 12B | ciphertext | auth-tag 16B]`
- Passphrase muss bei jedem Zugriff neu angegeben werden

### Security-Prinzipien
- Proxy-Architektur: `run_command`, `write_file`, `http_request` injizieren Secrets,
  ohne sie zurückzugeben
- Klartext-Passwörter sehen erfordert doppelte Bestätigung:
  `confirmed=true` **und** `exposedToAI=true`
- Audit-Log ohne Werte: `~/.cache/vault-mcp/audit.log`
- Kein Shell-Injection-Risiko: Commands laufen über `execFile`/`spawn` mit Array-Args,
  nie über `exec` mit interpolierten Strings
- URL-Normalisierung beim Vault-Server-Vergleich (trailing slash etc.)
- `vault_scan_secrets` scannt ein Projektverzeichnis vor dem Commit/Push auf
  hardcodierte Secrets (Git-tracked, staged, untracked-aber-nicht-ignoriert)

## Tools

### Instance Management
- `vault_list_instances` — konfigurierte Instanzen auflisten
- `vault_add_instance` — neue Instanz hinzufügen
- `vault_remove_instance` — Instanz entfernen (`confirmed=true`)
- `vault_prompt_password` — GUI-/Browser-Passwortdialog auslösen (für
  `masterPasswordPrompt`-Instanzen)
- `vault_check_connection` — CLI, Server-Erreichbarkeit, Auth+Unlock, Item-Listing prüfen

### Lokaler Such-Cache (SQLite, keine Secret-Inhalte)
- `vault_sync_cache` — Metadaten eines oder aller Vaults in `~/.cache/vault-mcp/search.db` laden
- `vault_search` — Fuzzy-Suche über den Cache (typo-tolerant, gewichtete Felder:
  Name > Username > URI > Folder > Feldnamen), liefert `matchedOn` zur Einordnung
- `vault_cache_status` — letzte Sync-Zeiten und Item-Anzahl pro Vault
- DB-Schema: `id, vault, name, type, folder_id, folder_name, favorite, uris, username,
  field_names, revision_date` — **keine Werte/Passwörter**

### Remote Vault (Vaultwarden)
- `vault_list_items` / `vault_search_items` / `vault_list_folders` — Metadaten
  (inkl. URIs, nicht-versteckte Custom Fields), keine Passwörter
- `vault_get_item` — vollständige Metadaten eines einzelnen Items, keine Passwörter
- `vault_reveal_password` — Passwort/Notes/Hidden Fields abrufen
  (`confirmed=true` + `exposedToAI=true`)
- `vault_create_item` / `vault_update_item` — Claude sieht den Wert (er wird ja übergeben)
- `vault_delete_item` — `confirmed=true` erforderlich
- `vault_run_command` / `vault_write_file` / `vault_http_request` — Proxy-Tools, Secrets
  werden injiziert, nie zurückgegeben
- `vault_browser_fill` — Formular in einem echten Browser (Playwright/Chromium) mit
  Vault-Credentials ausfüllen, für Web-Oberflächen ohne API

### Placeholder-Syntax (Injection-Tools: `http_request` / `write_file` / `run_command` argRefs)
Der Map-**Key** ist der Placeholder, der Map-**Wert** das Vault-Item. Im Template/den
Args wird der Placeholder in dieser Prioritätsreihenfolge aufgelöst:
1. `{{NAME}}` (empfohlen) — komplett inkl. Klammern ersetzt
2. `${NAME}`
3. `NAME` (bare, Teilstring-Ersetzung — Fallback)

Kommt ein Placeholder nicht im Template/in den Args vor, wirft das Tool einen Fehler,
statt still ein korruptes Secret zu senden (`applyRef`/`injectRefs` in `src/tools/inject.ts`).

### Multi-Field-Syntax (alle Injection- und Reveal-Tools)
Alle `secretRefs`, `envMappings`, `argRefs`, `fields`-Parameter unterstützen:
- `"Item Name"` → primärer Wert (Passwort bei Login, Inhalt bei Note)
- `"Item Name:username"` → Benutzername
- `"Item Name:password"` → Passwort (explizit)
- `"Item Name:notes"` → Notes
- `"Item Name:API Key"` → Custom Field namens „API Key"
- `"Item Name:totp"` → TOTP-Seed

Bei Item-Namen mit Doppelpunkt: stattdessen die Item-UUID verwenden.

### Favorites Vault
- `vault_favorites_add` — Item aus einem Remote-Vault als Favorit speichern
  (`passphrase` + `confirmed=true`)
- `vault_favorites_list` — Favoriten auflisten (`passphrase`, keine Passwörter)
- `vault_favorites_get` — Favorit inkl. Passwort abrufen
  (`passphrase` + `confirmed` + `exposedToAI`)
- `vault_favorites_remove` — Favorit löschen (`passphrase` + `confirmed=true`)
- `vault_favorites_update` — Favorit aus dem Quell-Vault aktualisieren
  (`passphrase` + `confirmed=true`)

### Project Vault
- `vault_init_project` — Vault für ein Repo initialisieren (`commit: true` für
  committable Variante)
- `vault_project_info` — Metadaten (Name, ID, Item-Anzahl, Storage-Modus, TOTP-Status)
- `vault_project_totp_enable` — TOTP auf einer bestehenden lokalen Vault nachrüsten
  (Voraussetzung für `vault_project_enable_commit_storage`)
- `vault_project_enable_commit_storage` — bestehende Vault von lokalem Storage in eine
  committable `.vault-project.enc` im Repo umziehen
- `vault_project_list_items` — Metadaten, keine Werte
- `vault_project_create_item` / `vault_project_update_item` — Claude sieht den Wert
- `vault_project_delete_item` — `confirmed=true` erforderlich
- `vault_project_run_command` / `vault_project_write_file` / `vault_project_http_request`
  — Proxy-Tools, gleiche Injection-Modi wie bei Remote Vaults

### Secret Scanning
- `vault_scan_secrets` — Projektverzeichnis vor Commit/Push auf hardcodierte Secrets
  scannen; Treffer werden redigiert zurückgegeben, nie im Klartext

## vault-launch — Secret-Injektion für andere MCP-Server

`vault-launch` (`dist/launch.js`) ist ein separater Einstiegspunkt, der *andere*
MCP-Server startet und ihnen Secrets als Umgebungsvariablen injiziert, bevor Claude Code
sie erreicht — Vorbild sind `op run --` / `aws-vault exec --`. Der gewrappte MCP-Server
braucht dafür keinerlei Code-Änderung; das Secret durchquert nie den Modell-Kontext.

```json
{
  "cis": {
    "command": "node",
    "args": [
      "/abs/pfad/vault-mcp/dist/launch.js",
      "--vault", "nak",
      "--env", "CIS_USER=nordakademie.de:username",
      "--env", "CIS_PASS=nordakademie.de:password",
      "--", "/abs/pfad/cis-api/cis", "mcp"
    ]
  }
}
```

Flags: `--vault <name>` (Instanz, sonst Default), `--env VAR=ItemRef` (wiederholbar),
`--arg PLACEHOLDER=ItemRef` (wiederholbar, ersetzt in den Kind-Args). `ItemRef` folgt
derselben Multi-Field-Syntax wie oben.

## Setup

### Voraussetzungen
- Node.js 22+
- Bitwarden CLI (`bw`) installiert und im PATH: https://bitwarden.com/help/cli/

### Build
```bash
npm install
npm run build
```

### MCP-Eintrag in `~/.claude.json`
```json
"vault-mcp": {
  "type": "stdio",
  "command": "node",
  "args": ["/absoluter/pfad/vault-mcp/dist/index.js"]
}
```

### Entwicklung
```bash
npm run dev         # tsx watch, direkt gegen src/
npm run typecheck   # tsc --noEmit
npm test            # vitest run
```

## Dateipfade
- Config: `~/.config/vault-mcp/config.json` (600)
- Project Vaults (lokal): `~/.config/vault-mcp/projects/<uuid>.vault` (600)
- Favorites Vault: `~/.config/vault-mcp/favorites.vault` (600)
- bw-Sessiondaten: `~/.cache/vault-mcp/bw-data/<name>/` (700)
- Lokaler Such-Cache: `~/.cache/vault-mcp/search.db`
- Audit-Log: `~/.cache/vault-mcp/audit.log`
- Backups für committable Project Vaults: `~/.claude/vault-mcp-backups/`

## Lizenz

Privates Projekt, kein öffentlicher Lizenztext hinterlegt.
