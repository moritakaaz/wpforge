# wpforge

Bulk-download every published version of WordPress plugins from the official
WordPress.org repository for offline security research, vulnerability triage,
and patch-diff analysis.

> Use only on plugins you are authorized to analyze. The downloader fetches
> public artefacts but you are responsible for how you use them.

## Features

- Pulls every historical version listed by the WordPress.org Plugin API.
- Concurrent, resumable downloads with SHA256 verification.
- SQLite catalog of plugins, versions, hashes, and Wordfence vuln records.
- Optional auto-extract with zip-slip protection.
- File-level diff between two extracted versions to surface silent patches.
- Cross-reference against the Wordfence Intelligence v3 feed (free API key).
- Cross-platform: works on Windows, macOS, and Linux.

## Requirements

- Python 3.10 or newer (3.11+ recommended).
- Git (to clone the repository).
- Roughly 200 MB of free disk space for the Wordfence feed cache plus
  whatever the plugin archives you download will need.

Check your Python version:

```bash
python --version    # macOS / Linux
py --version        # Windows (Python launcher)
```

## Install

The instructions below produce an isolated virtualenv and install the
package in editable mode so any local changes are picked up immediately.

### Windows (PowerShell)

```powershell
git clone https://github.com/moritakaaz/wpforge.git
cd wpforge

py -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -e ".[dev]"
```

> If activation is blocked by execution policy, run once per machine:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`.

### macOS / Linux (bash or zsh)

```bash
git clone https://github.com/moritakaaz/wpforge.git
cd wpforge

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -e ".[dev]"
```

After install, verify the CLI is on your PATH:

```bash
wpforge --help
```

## Configuration (`.env`)

Secrets are loaded from a `.env` file in the project root. A template is
provided:

```bash
# macOS / Linux
cp .env.example .env

# Windows PowerShell
Copy-Item .env.example .env
```

Open `.env` in your editor and fill in the values:

```dotenv
WORDFENCE_API_KEY=your-token-here
```

The CLI auto-loads `.env` (and `.env.local` if present) on every run. Real
shell environment variables always take precedence, so you can override on
a per-command basis without editing the file.

> `.env` is git-ignored. Only `.env.example` is committed.

### Getting a Wordfence API key

The `vulns` command uses the Wordfence Intelligence v3 API, which requires
a free API token.

1. Create or sign in to a Wordfence account.
2. Open the integrations page: <https://www.wordfence.com/account/integrations>
3. Generate an API key for **Wordfence Intelligence**.
4. Paste it into your local `.env` as `WORDFENCE_API_KEY=...`.

Alternative ways to provide the key (any of these works):

```bash
# Inline flag (one-off)
wpforge vulns contact-form-7 --api-key your-token-here
```

```bash
# Export for the current shell session (macOS / Linux)
export WORDFENCE_API_KEY=your-token-here
```

```powershell
# Set for the current PowerShell session
$env:WORDFENCE_API_KEY = "your-token-here"

# Persist for the current Windows user across sessions
[Environment]::SetEnvironmentVariable("WORDFENCE_API_KEY", "your-token-here", "User")
```

> Treat the token like a password. Do not commit it to git or paste it into
> shared logs. The downloader never writes it back to disk.

## Usage

List all versions of a plugin:

```bash
wpforge versions contact-form-7
```

Download every version (skipping already-downloaded ones) and auto-extract:

```bash
wpforge download contact-form-7 --extract
```

Download only a specific version:

```bash
wpforge download contact-form-7 --version 5.7.1
```

Download multiple specific versions:

```bash
wpforge download contact-form-7 -v 5.7 -v 5.7.1
```

Multiple plugins at once with higher concurrency:

```bash
wpforge -c 12 download contact-form-7 woocommerce elementor
```

Cross-reference against the Wordfence vuln feed:

```bash
wpforge vulns contact-form-7 woocommerce
```

Diff two versions:

```bash
wpforge diff contact-form-7 5.7 5.7.1
wpforge diff contact-form-7 5.7 5.7.1 --file contact-form-7.php
```

Inspect catalog state:

```bash
wpforge info contact-form-7
```

Free up disk space:

```bash
# See what would be removed without touching anything
wpforge clean --all --dry-run

# Wipe everything the tool produced (archives + extracted + vulndb + catalog)
wpforge clean --all -y

# Selective cleanup
wpforge clean --archives --extracted        # keep catalog and vuln cache
wpforge clean --vulndb                      # only refresh the Wordfence cache later
wpforge clean --archives --slug woocommerce # only one plugin
```

> `clean` requires at least one of `--archives`, `--extracted`, `--vulndb`,
> `--catalog`, or `--all`. Without a flag it does nothing, so you cannot
> wipe data by accident. Use `-y` to skip the confirmation prompt and
> `--dry-run` to preview the plan with byte counts.

## Layout

```
data/
  catalog.db              SQLite metadata
  plugins/<slug>/         downloaded zip archives
  extracted/<slug>/<ver>/ unzipped sources
  vulndb/                 cached Wordfence feed
src/wpforge/
  api.py        WordPress.org API client
  catalog.py    SQLite metadata store
  downloader.py concurrent + resumable downloader
  extractor.py  safe zip extraction
  differ.py     file-level diff helper
  vulndb.py     Wordfence cross-reference
  cli.py        click entrypoint (`wpforge`)
.env.example    secrets template -- copy to `.env` before first run
```

## Troubleshooting

- **`wpforge: command not found`** — the virtualenv is not activated. Re-run
  the activation step from the install section, or invoke the CLI as a
  module: `python -m wpforge ...`.
- **`Activate.ps1 cannot be loaded`** (Windows) — run
  `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`
  once and retry.
- **`No Wordfence API key configured`** — copy `.env.example` to `.env`
  and fill in `WORDFENCE_API_KEY`, or pass `--api-key`.
- **Some versions reported as missing (404)** — those releases were yanked
  from WordPress.org. The downloader records the gap and continues.

## Notes

- The Wordfence feed is large (~140 MB). It is cached under `data/vulndb/`
  and only refreshed when you pass `--refresh` (the default for `vulns`,
  flip with `--no-refresh` to reuse the cache).
- All downloads use streamed I/O with a `*.part` suffix and atomic rename,
  so an interrupted run never leaves a corrupt zip behind.

