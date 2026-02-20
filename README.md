# ARQON (MVP)

Local-first Windows security agent focused on user safety, privacy, and controllable automation.

## Implemented now

- Realtime process and downloads monitoring.
- File + URL risk scoring engine.
- Archive inspection for `.zip` (nested high-risk/blocked files).
- Script and LOLBin behavior heuristics (encoded commands, download/execution chains).
- Local and optional remote reputation adapter.
- Local reputation TTL cache for repeated checks.
- Authenticode signature inspection for PE/scripts (best effort).
- Local API for browser and UI integrations.
- Dashboard web UI (`/dashboard/`) with scan/actions/events/quarantine/incident export.
- Signed policy packs (Ed25519), replay protection, and background policy updater.
- Runtime watchdog with self-healing module restarts.
- Incident export in JSON/CSV (CLI + API).
- Hardened Windows startup automation and tray launcher.
- Secure install/update flow with backup rollback and health-check.
- Signed update-pack verification before applying updates.
- Diagnostics bundle export for incident response and support.
- Secret store abstraction (DPAPI on Windows).
- Retention cleanup manager (logs/backups/quarantine pruning).
- MVP validation script for pre-release quality gates.

## Boundaries

- Not a kernel antivirus.
- No HTTPS interception / MITM.
- No VPN in this stage (planned later).

## Project layout

- `src/arqon_guardian/` core agent modules
- `config/default.yml` runtime config
- `dashboard/` local web dashboard assets
- `browser-extension/chromium/` Chrome/Edge extension
- `scripts/` startup, install/update, release helpers
- `tests/` unit tests

## Quick start

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -e .

# create missing API keys in secure store + write refs into config
arqon-agent --config config/default.yml config ensure-keys --config-mode refs

# run agent
arqon-agent --config config/default.yml run
```

Open dashboard:

- `http://127.0.0.1:8765/dashboard/`

## User mode (simple launch, no admin panel)

For non-technical users use the user-mode launcher.
It performs first-run setup, starts protection, and shows a simple terminal status view.
Local API/dashboard access is disabled in this mode.

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON
powershell -ExecutionPolicy Bypass -File .\scripts\run_user_console.ps1
```

Or double-click:

- `START_ARQON_PROTECTION.cmd`
- `START_ARQON_USER_MODE.cmd`

Stop all ARQON runtime processes:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop_arqon_runtime.ps1
```

Or double-click:

- `STOP_ARQON_PROTECTION.cmd`

## Mode switch (one command)

Switch between user-only mode and browser-guard mode from one script.

```powershell
# USER: API/dashboard disabled
powershell -ExecutionPolicy Bypass -File .\scripts\switch_mode.ps1 -Mode USER

# BROWSER_GUARD: API enabled for extension, admin key stays separate
powershell -ExecutionPolicy Bypass -File .\scripts\switch_mode.ps1 -Mode BROWSER_GUARD
```

`BROWSER_GUARD` start prints ready-to-use `api_user_key` in terminal.

Quick launchers:

- `START_ARQON_USER_MODE.cmd`
- `START_ARQON_BROWSER_GUARD.cmd`

## Build variants

Create distributable user/admin archives:

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\build_variants.ps1
```

Output:

- `release\ARQON_USER_BUILD.zip` (no admin panel/API, one-click user launcher)
- `release\ARQON_ADMIN_BUILD.zip` (full functionality + dashboard)

## Core CLI

Run CLI commands from project root (`C:\Users\cvrsxd\Desktop\ARQON`) or pass an absolute `--config` path.

```powershell
# Run full agent
arqon-agent --config config/default.yml run

# Run API only
arqon-agent --config config/default.yml api-run

# Preflight / post-update health check
arqon-agent --config config/default.yml self-check
arqon-agent --config config/default.yml self-check --strict

# Diagnostics bundle (ZIP)
arqon-agent --config config/default.yml diagnostics bundle --output .\state\diagnostics.zip

# Scan URL
arqon-agent --config config/default.yml scan-url "https://example.com/login?token=1"

# Scan file
arqon-agent --config config/default.yml scan-file "C:\Users\you\Downloads\sample.exe" --quarantine

# Export incidents (JSON/CSV)
arqon-agent --config config/default.yml incidents export --format json --output .\state\incidents.json
arqon-agent --config config/default.yml incidents export --format csv --output .\state\incidents.csv --min-level warning

# API keys (secret refs recommended)
arqon-agent --config config/default.yml config ensure-keys --config-mode refs
arqon-agent --config config/default.yml config rotate-keys --config-mode refs

# Secret store commands
arqon-agent --config config/default.yml config secret-store set --name api_user_key --value "..."
arqon-agent --config config/default.yml config secret-store get --name api_user_key --masked
arqon-agent --config config/default.yml config secret-store list

# Privacy hardening
arqon-agent --config config/default.yml privacy list
arqon-agent --config config/default.yml privacy apply telemetry_off
arqon-agent --config config/default.yml privacy rollback

# Firewall sync
arqon-agent --config config/default.yml firewall-sync

# Retention cleanup (manual one-shot)
arqon-agent --config config/default.yml maintenance cleanup --print-config
```

## Local API contract

- `GET /health`
- `GET /dashboard/`
- `GET /v1/events?limit=60` (admin auth)
- `GET /v1/incidents?limit=1000&min_level=warning` (admin auth)
- `GET /v1/incidents/export?format=json|csv&limit=1000&min_level=warning` (admin auth)
- `GET /v1/quarantine?limit=60` (admin auth)
- `GET /v1/summary` (admin auth)
- `GET /v1/audit?limit=60` (admin auth)
- `GET /v1/self-check?skip_bind_check=true` (admin auth)
- `POST /v1/url/evaluate` body `{ "url": "https://..." }` (user auth)
- `POST /v1/file/evaluate` body `{ "path": "C:\\...\\file.exe", "quarantine": true }` (user auth)

Header for auth endpoints:

- `X-ARQON-Key: <resolved api.auth_key or api.auth_key_ref>`
- `X-ARQON-Admin-Key: <resolved api.admin_key or api.admin_key_ref or user key fallback>`

API includes built-in rate limiting (`config.api.rate_limit_*`).

## Signed policy packs (Ed25519)

`policy` commands sign and verify packs with Ed25519 key material.

```powershell
# 1) Generate signing keypair
arqon-agent --config config/default.yml crypto keygen `
  --private-out .\config\policy-signing-private.pem `
  --public-out .\config\policy-signing-public.pem `
  --key-id default `
  --keyring-out .\config\policy-signing-public.keys.json

# 2) Prepare policy patch file (json/yaml), example:
# { "rules": { "blocked_extensions": [".ps1", ".vbs"] }, "risk": { "block_threshold": 75, "warn_threshold": 45 } }

# 3) Sign
arqon-agent --config config/default.yml policy sign `
  --input .\policy.patch.json `
  --output .\policy.pack.json `
  --issuer local-admin `
  --key-id default `
  --secret-file .\config\policy-signing-private.pem

# 4) Verify
arqon-agent --config config/default.yml policy verify `
  --pack .\policy.pack.json `
  --keyring-file .\config\policy-signing-public.keys.json

# 5) Apply
arqon-agent --config config/default.yml policy apply `
  --pack .\policy.pack.json `
  --keyring-file .\config\policy-signing-public.keys.json

# 6) Pull from URL and apply
arqon-agent --config config/default.yml policy pull `
  --url "https://example.com/arqon/latest-pack.json" `
  --keyring-file .\config\policy-signing-public.keys.json
```

By default `apply/pull` reject same or older policy versions (anti-replay).
Use `--allow-replay` only for explicit rollback/manual override.

Notes:

- CLI flag names keep backward compatibility (`--secret-file`), but for Ed25519 this should point to PEM key material (private for signing, public or keyring for verify/apply).
- Legacy HMAC verification path remains for old packs.

## Policy update channel (optional)

In `config/default.yml`:

```yaml
policy_updates:
  enabled: false
  url: ""
  interval_sec: 1800
  apply_on_startup: true
  private_key_file: "./config/policy-signing-private.pem"
  public_keyring_file: "./config/policy-signing-public.keys.json"
  secret_file: ""
  keyring_file: ""
```

If enabled, updater periodically fetches signed pack from `url` and applies only newer versions.

## Browser extension (Chromium)

Folder: `browser-extension/chromium/`

Run ARQON in `BROWSER_GUARD` mode first:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\switch_mode.ps1 -Mode BROWSER_GUARD
```

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select `C:\Users\cvrsxd\Desktop\ARQON\workspace\repos\dev\browser-extension\chromium`.
5. Open extension settings and set API endpoint/key if changed.

## Tray launcher (Windows)

Run tray + auto-start agent:

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\start_tray.ps1
```

Install startup tasks:

```powershell
# Agent startup
.\install_startup_task.ps1

# Tray startup
.\install_tray_startup_task.ps1
```

## MVP validation gate

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\validate_mvp.ps1 -SkipBindCheck
.\validate_mvp.ps1 -SkipBindCheck -StrictHealth
```

## Secure install and update

Scripts:

- `scripts/install_arqon.ps1` bootstrap venv/dependencies, ensure API keys, run self-check, install startup tasks
- `scripts/update_arqon.ps1` backup snapshot, apply update, run installer+health-check, rollback on failure
- `scripts/rollback_arqon.ps1` restore from backup snapshot and re-run installer checks

Install/repair current project:

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\install_arqon.ps1
```

Update from another project snapshot/folder:

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\update_arqon.ps1 -SourceRoot "C:\Temp\ARQON-Update"
```

Manual rollback (latest backup):

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\rollback_arqon.ps1
```

Build release artifacts:

```powershell
cd C:\Users\cvrsxd\Desktop\ARQON\scripts
.\build_release.ps1
```

`build_release.ps1` auto-generates missing signing keys in `config/` by default.
Use `-SkipSigningKeyInit` only when you provide your own `-SigningKeyFile`.

## Tests

```powershell
python -m compileall src tests
python -m ruff check src tests --select F
python -m pytest -q
```

Current status: unit tests passing.
