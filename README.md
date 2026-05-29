# 🧶 PyTangle

> The lightning-fast, visual dependency detective that **untangles** and **fixes** your Python environments.

[![CI](https://github.com/Solanki-Prem/pytangle/actions/workflows/ci.yml/badge.svg)](https://github.com/Solanki-Prem/pytangle/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org)

PyTangle is a modern CLI that diagnoses **"dependency hell"** for Python
developers. It maps your dependency graph, scans for known CVEs via
[OSV](https://osv.dev), flags outdated and yanked packages, and uses a
constraint solver to suggest the **exact commands** to fix conflicts — powered
by [`uv`](https://github.com/astral-sh/uv) for speed.

---

## ✨ Features

| | Feature | Command |
|---|---|---|
| 🩺 | **Environment diagnostics** — pinpoint the active interpreter & venv | `pytangle status` |
| 🗺️ | **Interactive dependency graph** — health-coloured HTML network | `pytangle map` |
| 🔒 | **Security scanning** — known CVEs via the OSV database | `pytangle check` |
| ♻️ | **Outdated / yanked detection** — via the PyPI JSON API | `pytangle check` |
| 🛠️ | **Auto-fix suggestions** — constraint-solved upgrade/downgrade paths | `pytangle suggest` |
| 📦 | **Lockfile support** — `uv.lock`, `poetry.lock`, `Pipfile.lock` | all commands |

---

## 🚀 Install

```bash
# with uv (recommended)
uv tool install deptangle

# or with pip
pip install deptangle
```

> Installs the `pytangle` command. (The PyPI distribution is named
> `deptangle` because `pytangle` was already taken.)

## 🧪 Usage

```bash
# 1. Diagnose your environment
pytangle status

# 2. Visualise the dependency graph (writes an interactive HTML file)
pytangle map -o graph.html

# 3. Check for conflicts, outdated packages, and CVEs
pytangle check
pytangle check --only-issues          # show only problems
pytangle check --offline              # no network calls

# 4. Get actionable fix commands
pytangle suggest

# Work from a lockfile instead of the live environment
pytangle check --lockfile uv.lock
```

Color legend in the graph and tables:
🟢 healthy · 🟡 outdated · 🟠 deprecated/yanked · 🔴 conflict · 🔴 **vulnerable**

---

## 🔐 Security by design

PyTangle reads untrusted inputs (lockfiles, package metadata, remote APIs) and
shells out to `uv`, so it is hardened from the ground up. See [`SECURITY.md`](SECURITY.md).

- **No code execution** — lockfiles are parsed as data (`tomllib`/`json`); package code is never imported or `eval`'d.
- **Hardened subprocess** — `shell=False`, list-args only, resolved executables, timeouts, scrubbed environment.
- **SSRF-resistant networking** — HTTPS-only to an explicit host allowlist (`pypi.org`, `api.osv.dev`), redirects disabled, IP literals rejected, response size capped, timeouts enforced.
- **Injection-safe output** — package names/versions validated (PEP 508/440) and HTML-escaped before entering the graph; Pyvis JS served locally, not from a CDN.
- **PyTangle never modifies your environment** — `suggest` only *prints* commands for you to review and run.

---

## 🏗️ Architecture

```
src/pytangle/
├── cli.py          # Typer commands: status, map, check, suggest
├── environment.py  # Phase 2 — interpreter & venv diagnostics
├── parser.py       # Phase 3 — dependency graph + lockfile parsing
├── visualizer.py   # Phase 3/4 — Pyvis interactive HTML graph
├── checker.py      # Phase 4 — PyPI health (outdated/yanked/deprecated)
├── security.py     # Phase 4 — OSV vulnerability scanning
├── resolver.py     # Phase 5 — constraint-solving auto-fix engine
├── report.py       # Rich table rendering
├── models.py       # typed data models
└── _safety.py      # 🔐 centralised security primitives
```

---

## 🧑‍💻 Development

```bash
git clone https://github.com/Solanki-Prem/pytangle
cd pytangle
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

ruff check src tests       # lint
mypy src                   # type check
pytest --cov=pytangle      # tests
```

---

## 🗺️ Roadmap

- `pytangle fix --apply` — execute suggested fixes automatically (with confirmation)
- A GitHub Action that fails CI when a new CVE is introduced

---

## 📄 License

MIT © Prem Solanki
