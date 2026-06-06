# wpforge — agent notes

CLI tool that mirrors every published version of a WordPress plugin and
cross-references it with the Wordfence Intelligence v3 vuln feed for
offline security research. See `README.md` for end-user docs.

## Project identity

- Distribution / import name: `wpforge` (CLI binary `wpforge`, module
  `wpforge`). Repo folder is `wpforge`.
- Python `>=3.10`, hatchling build backend, src-layout under `src/wpforge/`.
- Entrypoints: `wpforge.cli:main` (script), `python -m wpforge` (module).

## Setup & verification

```powershell
# Editable install with dev extras (only needed once)
pip install -e ".[dev]"

# Smoke test order an agent should follow after edits
python -m compileall -q src
ruff check src
pytest -q
python -m wpforge versions hello-dolly   # tiny plugin, fast network sanity check
```

`pytest` is configured via `pyproject.toml` (`asyncio_mode = "auto"`,
`testpaths = ["tests"]`). No conftest, no fixtures of note.

Ruff is configured in `pyproject.toml`: line-length 100, target py310,
rule selects `E, F, W, I, B, UP, SIM, RUF`. Run `ruff check src` before
committing. `mypy` is available (`mypy src`) but has no `[tool.mypy]`
config yet — expect some noise on first run.

## Module layout (and why)

- `api.py`            — async `httpx` client for `api.wordpress.org/plugins/info/1.2/`.
- `downloader.py`     — concurrent streamed downloads, atomic `*.part` rename, SHA256.
- `catalog.py`        — sync SQLite store; schema defined in module-level `SCHEMA`.
- `extractor.py`      — zip-slip-guarded extraction.
- `differ.py`         — stdlib `filecmp` + `difflib`, no extra deps.
- `vulndb.py`         — Wordfence Intelligence v3 importer; bearer-auth.
- `cli.py`            — single click group with subcommands; auto-loads `.env`.
- `config.py`         — frozen `Config` dataclass; resolves `data/` paths.

Internal imports use relative form (`from .api import ...`). Keep it that
way; absolute imports of `wpforge.*` will desync if the package is ever
vendored.

## Cross-cutting conventions

- **Retry policy**: tenacity is used in `api.py`, `downloader.py`,
  `vulndb.py`. All three use a custom `_is_retryable` predicate that
  retries `httpx.TransportError` and 5xx only. Do **not** retry 4xx;
  404 (yanked plugin versions) and 401/403 (auth) must surface
  immediately. There was a regression here once — preserve this behaviour.
- **Idempotency**: `Downloader` skips a version if `Catalog.is_downloaded`
  returns true *and* the archive still exists on disk. Both checks are
  required.
- **Atomic writes**: zips stream to `<target>.zip.part` then `replace()`.
  Never write to the final path directly.
- **Wordfence API**: v2 endpoint returns 410 Gone permanently. Only v3
  works and requires a bearer token from
  https://www.wordfence.com/account/integrations. Feed shape can be
  either `{<uuid>: entry}` or `{"data": [entry, ...]}`; `VulnDB.import_for_slugs`
  normalises both — keep that branching when touching the parser.
- **Secrets**: `python-dotenv` auto-loads `.env` and `.env.local` from
  cwd at CLI startup (`cli._load_env_files`). Real env vars win
  (`override=False`). Never write tokens to disk.

## Data directory

`./data/` (gitignored, sub-paths in `.gitignore` line 21+):

```
data/catalog.db          SQLite metadata store
data/plugins/<slug>/     downloaded zip archives
data/extracted/<slug>/   unzipped sources
data/vulndb/             cached Wordfence feed (~140 MB)
```

`Config.ensure_dirs()` recreates these on demand; safe to wipe with
`wpforge clean --all`.

## CLI surface (current)

`versions`, `download`, `extract`, `vulns`, `diff`, `info`, `clean`.

Notable flags:
- `download --version / -v` (multiple): download only specific versions.
- `download --extract`: auto-extract after downloading.
- `download --include-trunk`: include the development snapshot.
- `clean` requires at least one of `--archives / --extracted / --vulndb /
  --catalog / --all`; with no flags it is a no-op by design (so users
  cannot wipe data accidentally).
- `clean --slug`: scope cleanup to one plugin (archives/extracted only).
- `clean --dry-run`: preview what would be deleted.

## Conventions for new code

- Match existing style: type hints, frozen dataclasses for value
  objects, `from __future__ import annotations` at top of modules.
- New subcommands go in `cli.py` under their own banner-comment header
  block; pass shared state via `ctx.obj["config"]` / `ctx.obj["catalog"]`.
- Add tests under `tests/` mirroring module names. Use `tmp_path` for
  filesystem isolation; do not write under `./data/` from tests.

## Operational gotchas

- The Wordfence feed is ~140 MB; tests must never download it. If a test
  needs the feed, fixture a tiny stub JSON.
- WordPress.org API uses query string `?action=plugin_information&slug=<x>`.
  Do **not** add `request[fields][...]` parameters — they cause 400.
- HTTP/2 is enabled in both clients (`http2=True`); `h2` is pulled in via
  `httpx[http2]` extra. Don't drop the extra without disabling HTTP/2.

## Git

Commit messages follow conventional-prose style (subject line + body).
Default branch is `master`. Remote is SSH
(`git@github.com:moritakaaz/wpforge.git`); the repo's local git config
sets `pushInsteadOf` so pushes go via SSH even when `git remote -v`
prints the HTTPS URL — this works around a global `insteadOf` rule.
