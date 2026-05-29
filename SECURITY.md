# Security Policy

## Supported Versions

PyTangle is pre-1.0. Security fixes are applied to the latest released version
on PyPI and the `main` branch.

## Reporting a Vulnerability

Please **do not** open a public issue for security reports. Instead, use
GitHub's private vulnerability reporting:

> Repository → **Security** tab → **Report a vulnerability**

Or email **premsolanki2503@gmail.com** with the subject `PyTangle Security`.
We aim to acknowledge reports within 72 hours.

## Security Design Principles

PyTangle inspects untrusted inputs (lockfiles, package metadata, remote API
responses) and shells out to `uv`. The codebase is built around these rules:

### 1. No arbitrary code execution
- Lockfiles are parsed as **data only** (`tomllib`/`json`). PyTangle never
  imports, `eval`s, or executes package code or lockfile content.
- `setup.py`-style dynamic metadata is never invoked.

### 2. Hardened subprocess use
- All subprocess calls go through `pytangle._safety.run_command`, which:
  - **never** uses `shell=True`,
  - passes arguments as a **list** (no string interpolation into a shell),
  - resolves the executable via `shutil.which` and refuses relative paths,
  - enforces a wall-clock **timeout**,
  - runs with a scrubbed, minimal environment.

### 3. Hardened network access (SSRF-resistant)
- All HTTP goes through `pytangle._safety.SafeSession`, which:
  - allows **HTTPS only** to an explicit **host allowlist**
    (`pypi.org`, `api.osv.dev`),
  - **disables redirects** by default (prevents redirect-to-internal SSRF),
  - enforces connect/read **timeouts** and a **response size cap**,
  - rejects URLs with embedded credentials, non-default ports, or IP literals.

### 4. Output-injection safe
- Package names and versions are validated against PEP 508 / PEP 440 before
  being rendered into the interactive HTML graph; values are HTML-escaped so a
  malicious lockfile entry cannot inject script into the generated page.
- The Pyvis graph is generated with JavaScript assets served **locally**
  (`cdn_resources="local"`) rather than from a remote CDN.

### 5. No secret handling
- PyTangle reads no credentials and writes none to disk or logs.
