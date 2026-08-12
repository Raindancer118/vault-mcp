# vault-mcp

MCP-Server für sicheres Secrets-Management. Claude kann Secrets verwalten und injizieren, sieht Werte aber so wenig wie möglich.

## Architektur

### Remote Vaults (Vaultwarden / Bitwarden)
- Wrapper um `bw` CLI — handhabt E2E-Crypto transparent
- Jede Instanz bekommt ein isoliertes Datenverzeichnis: `~/.cache/vault-mcp/bw-data/<name>/`
- Session-Token bleibt im RAM (TTL 18 min), niemals auf Disk
- Konfiguration: `~/.config/vault-mcp/config.json` (mode 600)

### Project Vaults (lokal, für Git-Repos)
- AES-256-GCM-verschlüsselte Datei in `~/.config/vault-mcp/projects/<uuid>.vault`
- Key: HKDF(SHA-256, masterKey, projectId, "vault-mcp-project-v1", 32 bytes)
- MasterKey: 32 zufällige Bytes in `config.json` generiert beim ersten Start
- `.vault-project` Marker-Datei im Repo-Root: enthält nur UUID + Name — sicher commitbar

### Favorites Vault (lokal, passwortgeschützt)
- AES-256-GCM-verschlüsselte Datei: `~/.config/vault-mcp/favorites.vault`
- Key: scrypt(passphrase, salt, N=65536, r=8, p=1) — NIEMALS auf Disk gespeichert
- Salt: 32 Bytes, im File-Header gespeichert (Öffentliche Info, kein Secret)
- File-Layout: `[salt 32B | IV 12B | ciphertext | auth-tag 16B]`
- Passphrase muss bei jedem Zugriff angegeben werden

### Security-Prinzipien
- Proxy-Architektur: `run_command`, `write_file`, `http_request` injizieren Secrets ohne sie zurückzugeben
- Passwörter sehen: Doppelbestätigung `confirmed=true` + `exposedToAI=true` erforderlich
- Audit-Log: `~/.cache/vault-mcp/audit.log` — Aktionen ohne Werte
- Shell-Injection verhindert: `spawn()` mit Array-Args, kein `exec` mit String
- URL-Normalisierung beim Vault-Server-Vergleich (trailing slash safe)

## Tools

### Instance Management
- `vault_list_instances` — Konfigurierte Instanzen auflisten
- `vault_add_instance` — Neue Instanz hinzufügen
- `vault_remove_instance` — Instanz entfernen (confirmed=true)

### Local Search Cache (SQLite, kein Secret-Inhalt)
- `vault_sync_cache` — Metadaten von einem oder allen Vaults in lokale SQLite-DB laden (`~/.cache/vault-mcp/search.db`)
- `vault_search` — Fuzzy-Suche auf Cache (typo-tolerant, gewichtete Felder: Name > Username > URI > Folder > FieldNames)
- `vault_cache_status` — Letzte Sync-Zeiten und Item-Anzahl pro Vault
- DB-Schema: `id, vault, name, type, folder_id, folder_name, favorite, uris, username, field_names, revision_date` — **keine Werte/Passwörter**

### Remote Vault (Vaultwarden)
- `vault_list_items` / `vault_search_items` / `vault_list_folders` — Metadaten (inkl. URIs, nicht-versteckte Custom Fields), keine Passwörter
- `vault_get_item` — Vollständige Metadaten eines einzelnen Items (keine Passwörter)
- `vault_reveal_password` — Passwort/Notes/Hidden Fields abrufen (confirmed=true + exposedToAI=true)
- `vault_create_item` / `vault_update_item` — Claude sieht Wert
- `vault_delete_item` — confirmed=true erforderlich
- `vault_run_command` / `vault_write_file` / `vault_http_request` — Proxy-Tools
- `vault_browser_fill` — Browser-Formular mit Vault-Credentials ausfüllen (Playwright/Chromium)
- `vault_browser_close` — Persistente Browser-Instanz schließen

### Placeholder-Syntax (Injection-Tools: http_request / write_file / run_command argRefs)
Der Map-**Key** ist der Placeholder, der Map-**Wert** das Vault-Item. Im Template kann der Placeholder so referenziert werden (in dieser Prioritätsreihenfolge):
- `{{NAME}}` (empfohlen) → wird komplett inkl. Klammern ersetzt
- `${NAME}`
- `NAME` (bare, Teilstring-Ersetzung — Fallback)
Kommt ein Placeholder gar nicht im Template/in den Args vor, wirft das Tool einen Fehler, statt still ein korruptes Secret zu senden (`applyRef`/`injectRefs` in `src/tools/inject.ts`).

### Multi-Field-Syntax (alle Injection-Tools)
Alle `secretRefs`, `envMappings`, `argRefs`, `fields` Parameter unterstützen:
- `"Item Name"` → primärer Wert (Passwort bei Login, Inhalt bei Note)
- `"Item Name:username"` → Benutzername
- `"Item Name:password"` → Passwort (explizit)
- `"Item Name:notes"` → Notes
- `"Item Name:API Key"` → Custom Field namens "API Key"
- `"Item Name:totp"` → TOTP-Seed
Bei Item-Namen mit Doppelpunkt: Item-UUID verwenden.

### Favorites Vault
- `vault_favorites_add` — Item aus Remote-Vault in Favorites speichern (passphrase + confirmed=true)
- `vault_favorites_list` — Favorites auflisten (passphrase, keine Passwörter)
- `vault_favorites_get` — Favorite mit Passwort abrufen (passphrase + confirmed + exposedToAI)
- `vault_favorites_remove` — Favorite löschen (passphrase + confirmed=true)
- `vault_favorites_update` — Favorite aus Source-Vault aktualisieren (passphrase + confirmed=true)

### Project Vault
- `vault_init_project` — Vault für Repo initialisieren
- `vault_project_info` / `vault_project_list_items` — Metadaten
- `vault_project_create_item` / `vault_project_update_item` — Claude sieht Wert
- `vault_project_delete_item` — confirmed=true erforderlich
- `vault_project_run_command` / `vault_project_write_file` / `vault_project_http_request` — Proxy-Tools

## Setup

### Voraussetzungen
- Node.js 22+
- Bitwarden CLI (`bw`) installiert und im PATH: https://bitwarden.com/help/cli/

### Build
```bash
npm install
npm run build
```

### MCP-Eintrag in ~/.claude.json
```json
"vault-mcp": {
  "type": "stdio",
  "command": "node",
  "args": ["/home/tom/Projekte/SE Projects/vault-mcp/dist/index.js"]
}
```

## Dateipfade
- Config: `~/.config/vault-mcp/config.json` (600)
- Project Vaults: `~/.config/vault-mcp/projects/<uuid>.vault` (600)
- Favorites Vault: `~/.config/vault-mcp/favorites.vault` (600)
- bw-Sessiondata: `~/.cache/vault-mcp/bw-data/<name>/` (700)
- Audit-Log: `~/.cache/vault-mcp/audit.log`

## Bekannte Bugfixes (v1.1.1)
- Injection-Footgun behoben: `injectRefs` ersetzte den Map-Key nur als rohen Teilstring (`replaceAll`). Ein Placeholder wie `{{GROQ_KEY}}` im Template mit Map-Key `GROQ_KEY` führte zu `Bearer {{<secret>}}` — Klammern blieben stehen → korruptes Secret, stiller 401. Jetzt: `applyRef` bevorzugt `{{NAME}}`/`${NAME}` und ersetzt sie komplett; unbenutzte Placeholder werfen einen Fehler. Gilt auch für `argRefs` in `runCommandWithSecrets`.
- Tests: `src/tools/inject.test.ts` (vitest, fetch-Mock) deckt alle Placeholder-Formen + Fehlerfälle ab.

## Bekannte Bugfixes (v1.1.0)
- Falscher MCP-Pfad in ~/.claude.json behoben (zeigte auf nicht existierendes Verzeichnis)
- URL-Vergleich bei `ensureSession()` normalisiert (trailing slashes)
- `bw status` ohne `--raw` Flag (konsistenter auf allen bw-Versionen)
- Besseres Error-Handling: bw stderr in Fehlermeldungen enthalten
- `stripSensitive` gibt jetzt URIs und nicht-versteckte Custom Fields zurück

## Offene Punkte
- Tests schreiben (vitest, Mock für bw-CLI)
- GitHub Repo anlegen + Push
