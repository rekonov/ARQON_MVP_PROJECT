# ARQON CI/CD Handoff

Use this file to pass ARQON changes from development to CI/CD.

## Roles

- Developer: code changes, local verification, handoff entry.
- CI/CD engineer: CI checks, artifact build, GitHub push.

## Repositories

- Private admin repo (`dev`):
  - Local path: `C:\Users\cvrsxd\Desktop\ARQON\workspace\repos\dev`
  - Remote: `https://github.com/rekonov/arqon-admin-private.git`
- Public user repo (`public`):
  - Local path: `C:\Users\cvrsxd\Desktop\ARQON\workspace\repos\public`
  - Remote: `https://github.com/rekonov/arqon-user-public.git`

## Sync Policy

1. All development starts in `dev`.
2. After validation, mirror relevant files to `public`.
3. Keep `dev` and `public` aligned unless change is explicitly private/admin-only.
4. Handoff entry must list any intentionally non-mirrored files.

## Required CI Checks

Run in each repo root (`dev` and `public`):

```powershell
$env:PYTHONPATH='src'
.\.venv\Scripts\python.exe -m compileall src
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m arqon_guardian.cli --config config\default.yml self-check --skip-bind-check
```

Optional extra check:

```powershell
.\.venv\Scripts\python.exe -m ruff check --select I src tests
```

## Build Checks (When Release Is Planned)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_variants.ps1
```

Expected output:

- `release\ARQON_USER_BUILD.zip`
- `release\ARQON_ADMIN_BUILD.zip`

## Security Gates

Never commit secrets/private materials, including:

- `policy-signing-private.pem`
- `secure-secrets.json`
- any API tokens, passwords, or private keys

Quick staged-file check:

```powershell
git diff --name-only --cached
```

## Handoff Entry Template

Copy this block for each delivery:

```md
## YYYY-MM-DD HH:MM (local)

Author: @username
Status: ready-for-check | in-progress | blocked
Target branch: main
Repo scope: dev-only | public-only | both
Type: feat | fix | refactor | docs | chore

Summary:
- short change 1
- short change 2

Changed files:
- path/to/file1
- path/to/file2

Checks required:
- compileall
- pytest
- self-check

Notes/Risks:
- known caveat or migration note

Commit message (preferred):
- type(scope): short message
```

## Handoff Log

Start adding entries below this line.

## 2026-02-22 22:09 (local)

Author: @codex
Status: ready-for-check
Target branch: main
Repo scope: both
Type: chore

Summary:
- cleaned repository hygiene by removing runtime-generated files mistakenly tracked in `dev` (`config/state/agent.log`, `config/state/firewall-rules.json`)
- tightened ignore rules in both repos to block OS junk and runtime state in `config/state/`
- revalidated baseline checks in both repos (`compileall`, `pytest`, `self-check --skip-bind-check`)

Changed files:
- .gitignore (dev)
- .gitignore (public)
- config/state/agent.log (dev, deleted)
- config/state/firewall-rules.json (dev, deleted)
- CI_HANDOFF.md (dev)

Checks required:
- compileall
- pytest
- self-check

Notes/Risks:
- intentionally non-mirrored file: `CI_HANDOFF.md` exists only in `dev` by process rule
- no runtime logic or API behavior changes in this batch

Commit message (preferred):
- chore(repo): clean tracked runtime artifacts and harden ignore rules
