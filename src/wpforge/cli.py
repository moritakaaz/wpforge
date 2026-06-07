"""Command-line interface for wpforge.

Subcommands
-----------
- versions <slug>            : list every version known to WordPress.org
- download <slug>...         : download all versions for one or more plugins
- extract  <slug> [version]  : extract one or all downloaded archives
- vulns    <slug>            : refresh Wordfence feed and print known vulns
- diff     <slug> <a> <b>    : summarise changes between two versions
- info     <slug>            : show catalog state for a plugin
- clean                      : remove cached/downloaded artefacts
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from .api import PluginNotFoundError, WordPressAPI
from .catalog import Catalog
from .config import Config
from .differ import Differ
from .downloader import Downloader, make_progress
from .extractor import Extractor
from .vulndb import VulnDB, VulnDBAuthError


def _load_env_files() -> None:
    """Load environment variables from `.env` files.

    Resolution order (later files override earlier ones, but real environment
    variables always win because we pass override=False):

    1. `<cwd>/.env`            -- project-local secrets
    2. `<cwd>/.env.local`      -- per-developer overrides

    Cross-platform: `python-dotenv` handles Windows, macOS, and Linux paths
    transparently. We deliberately keep this lightweight and never read from
    the user's home directory to avoid surprising behaviour.
    """
    cwd = Path.cwd()
    for candidate in (cwd / ".env", cwd / ".env.local"):
        if candidate.is_file():
            load_dotenv(candidate, override=False)


_load_env_files()

console = Console()


def _make_config(data_dir: str | None, concurrency: int) -> Config:
    base = Config()
    cfg = Config(
        data_dir=Path(data_dir).resolve() if data_dir else base.data_dir,
        user_agent=base.user_agent,
        concurrency=concurrency,
        request_timeout=base.request_timeout,
        max_retries=base.max_retries,
    )
    cfg.ensure_dirs()
    return cfg


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, path_type=str),
    default=None,
    help="Override storage location (default: ./data).",
)
@click.option(
    "-c",
    "--concurrency",
    type=int,
    default=6,
    show_default=True,
    help="Maximum parallel downloads.",
)
@click.pass_context
def main(ctx: click.Context, data_dir: str | None, concurrency: int) -> None:
    """WordPress plugin downloader for security research."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = _make_config(data_dir, concurrency)
    ctx.obj["catalog"] = Catalog(ctx.obj["config"].catalog_db)


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------


@main.command()
@click.argument("slug")
@click.pass_context
def versions(ctx: click.Context, slug: str) -> None:
    """List every published version of SLUG on WordPress.org."""
    cfg: Config = ctx.obj["config"]

    async def _run() -> None:
        async with WordPressAPI(user_agent=cfg.user_agent, timeout=cfg.request_timeout) as api:
            try:
                info = await api.fetch_plugin_info(slug)
            except PluginNotFoundError as exc:
                console.print(f"[red]{exc}[/red]")
                sys.exit(2)

        table = Table(title=f"{info.name} ({info.slug}) - {len(info.versions)} versions")
        table.add_column("Version")
        table.add_column("Download URL", overflow="fold")
        for pv in info.versions:
            table.add_row(pv.version, pv.download_url)
        console.print(table)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# download
# ---------------------------------------------------------------------------


@main.command()
@click.argument("slugs", nargs=-1, required=True)
@click.option(
    "--version", "-v",
    multiple=True,
    help="Download only specific version(s). Can be repeated.",
)
@click.option(
    "--extract/--no-extract",
    default=False,
    help="Extract zips after downloading.",
)
@click.option(
    "--include-trunk/--no-trunk",
    default=False,
    help="Include the 'trunk' pseudo-version (development snapshot).",
)
@click.pass_context
def download(
    ctx: click.Context,
    slugs: tuple[str, ...],
    version: tuple[str, ...],
    extract: bool,
    include_trunk: bool,
) -> None:
    """Download every version of each SLUG (or only --version if specified)."""
    cfg: Config = ctx.obj["config"]
    catalog: Catalog = ctx.obj["catalog"]

    async def _run() -> None:
        async with WordPressAPI(user_agent=cfg.user_agent, timeout=cfg.request_timeout) as api:
            all_versions = []
            for slug in slugs:
                try:
                    info = await api.fetch_plugin_info(slug)
                except PluginNotFoundError as exc:
                    console.print(f"[red]{exc}[/red]")
                    continue

                catalog.upsert_plugin(
                    slug=info.slug,
                    name=info.name,
                    homepage=info.homepage,
                    last_updated=info.last_updated,
                )
                for pv in info.versions:
                    if pv.version.lower() == "trunk" and not include_trunk:
                        continue
                    if version and pv.version not in version:
                        continue
                    catalog.register_version(
                        slug=pv.slug, version=pv.version, download_url=pv.download_url
                    )
                    all_versions.append(pv)

                queued = sum(
                    1 for pv in info.versions
                    if (pv.version.lower() != "trunk" or include_trunk)
                    and (not version or pv.version in version)
                )
                console.print(
                    f"[green]{info.slug}[/green]: queued {queued} versions"
                )

        if not all_versions:
            console.print("[yellow]Nothing to download.[/yellow]")
            return

        downloader = Downloader(config=cfg, catalog=catalog)
        with make_progress() as progress:
            results = await downloader.download_all(all_versions, progress=progress)

        ok = sum(1 for r in results if r.sha256 and not r.skipped)
        skipped = sum(1 for r in results if r.skipped)
        missing = sum(1 for r in results if r.missing)
        console.print(
            f"[bold]Done[/bold]: {ok} downloaded, {skipped} skipped, {missing} missing (404)."
        )

        if extract:
            extractor = Extractor(config=cfg, catalog=catalog)
            for r in results:
                if r.missing or not r.sha256:
                    continue
                extractor.extract(r.slug, r.version, r.path)
            console.print("[bold]Extraction complete.[/bold]")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------


@main.command()
@click.argument("slug")
@click.argument("version", required=False)
@click.pass_context
def extract(ctx: click.Context, slug: str, version: str | None) -> None:
    """Extract one or all downloaded archives for SLUG."""
    cfg: Config = ctx.obj["config"]
    catalog: Catalog = ctx.obj["catalog"]
    extractor = Extractor(config=cfg, catalog=catalog)

    records = (
        [catalog.get_version(slug, version)] if version else catalog.list_versions(slug)
    )
    records = [r for r in records if r and r.archive_path]
    if not records:
        console.print("[yellow]No downloaded archives in catalog.[/yellow]")
        return

    for rec in records:
        assert rec is not None and rec.archive_path
        path = Path(rec.archive_path)
        if not path.exists():
            console.print(f"[red]missing on disk:[/red] {path}")
            continue
        dest = extractor.extract(rec.slug, rec.version, path)
        console.print(f"[green]extracted[/green] {rec.slug} {rec.version} -> {dest}")


# ---------------------------------------------------------------------------
# vulns
# ---------------------------------------------------------------------------


@main.command()
@click.argument("slugs", nargs=-1, required=True)
@click.option("--refresh/--no-refresh", default=True, help="Refresh Wordfence feed.")
@click.option(
    "--api-key",
    default=None,
    help="Wordfence API key (overrides WORDFENCE_API_KEY env var).",
)
@click.pass_context
def vulns(
    ctx: click.Context,
    slugs: tuple[str, ...],
    refresh: bool,
    api_key: str | None,
) -> None:
    """Cross-reference SLUGS against the Wordfence Intelligence feed.

    Requires a Wordfence Intelligence API key. Set WORDFENCE_API_KEY in your
    environment, or pass --api-key. Generate one at
    https://www.wordfence.com/account/integrations
    """
    cfg: Config = ctx.obj["config"]
    catalog: Catalog = ctx.obj["catalog"]
    db = VulnDB(config=cfg, catalog=catalog, api_key=api_key)

    if refresh or not db.cache_path.exists():
        if not db.has_credentials():
            console.print(
                "[red]No Wordfence API key configured.[/red] "
                "Set [bold]WORDFENCE_API_KEY[/bold] or pass --api-key. "
                "Generate one at https://www.wordfence.com/account/integrations"
            )
            sys.exit(2)
        try:
            with console.status("Refreshing Wordfence feed..."):
                db.refresh(force=refresh)
        except VulnDBAuthError as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(2)

    touched = db.import_for_slugs(slugs)
    console.print(f"[green]imported {touched} vulnerability records[/green]")

    for slug in slugs:
        rows = catalog.vulnerabilities_for(slug)
        if not rows:
            console.print(f"[dim]{slug}: no known vulnerabilities[/dim]")
            continue
        table = Table(title=f"Vulnerabilities for {slug}")
        table.add_column("CVE")
        table.add_column("Severity")
        table.add_column("Fixed in")
        table.add_column("Title", overflow="fold")
        for row in rows:
            table.add_row(
                row["cve"] or "-",
                row["severity"] or "-",
                row["fixed_in"] or "-",
                row["title"] or "-",
            )
        console.print(table)


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


@main.command()
@click.argument("slug")
@click.argument("version_a")
@click.argument("version_b")
@click.option(
    "--file",
    "file_path",
    default=None,
    help="Print a unified diff of a single file across the two versions.",
)
@click.option(
    "--full",
    is_flag=True,
    default=False,
    help="Show full unified diff for all changed files (can be very long).",
)
@click.option(
    "--vulns",
    is_flag=True,
    default=False,
    help="Cross-reference changed files with Wordfence vulnerability data.",
)
@click.pass_context
def diff(
    ctx: click.Context,
    slug: str,
    version_a: str,
    version_b: str,
    file_path: str | None,
    full: bool,
    vulns: bool,
) -> None:
    """Diff two extracted versions of SLUG.

    By default shows a summary table of changed files.
    Use --full for a git-style colored unified diff of all files,
    or --file for a single file. Use --vulns to cross-reference changes
    with Wordfence Intelligence vulnerability data.
    """
    cfg: Config = ctx.obj["config"]
    differ = Differ(cfg)

    if file_path:
        _print_colored_diff(differ.unified(slug, version_a, version_b, file_path))
        return

    summary = differ.summarise(slug, version_a, version_b)

    # --- Vulnerability cross-reference ---
    vuln_labels: list[str] = []
    vuln_file_map: dict[str, list[str]] = {}  # path -> list of vuln labels
    # Store per-CVE file+line refs for snippet display.
    vuln_snippets: list[tuple[str, str, list[tuple[str, int | None]]]] = []
    if vulns:
        catalog: Catalog = ctx.obj["catalog"]
        vdb = VulnDB(config=cfg, catalog=catalog)
        try:
            vdb.refresh()
            vdb.import_for_slugs([slug])
        except VulnDBAuthError as exc:
            console.print(f"[yellow]Warning: {exc}[/yellow]")
        vuln_rows = catalog.vulnerabilities_for(slug)
        all_changed = set(summary.added + summary.removed + summary.modified)
        for row in vuln_rows:
            # Check if either diffed version falls in the affected range.
            affected_json = row["affected"] or "{}"
            if not _version_in_affected(version_a, version_b, affected_json):
                continue
            title = row["title"] or "Unknown vulnerability"
            severity = row["severity"] or "unknown"
            cve = row["cve"] or ""
            fixed_in = row["fixed_in"] or ""
            label = f"{severity.upper()}: {title}"
            if cve:
                label += f" ({cve})"
            if fixed_in:
                label += f" [fixed in {fixed_in}]"
            vuln_labels.append(label)

            # Fetch per-file references with line numbers from MITRE CVE API.
            if cve:
                refs_with_lines = _fetch_cve_file_refs_with_lines(cve, slug)
                vuln_snippets.append((label, cve, refs_with_lines))
                for ref_path, _line in refs_with_lines:
                    if ref_path in all_changed:
                        vuln_file_map.setdefault(ref_path, []).append(label)

    # --- Summary table ---
    table = Table(title=f"{slug}: {version_a} -> {version_b}")
    table.add_column("Change")
    table.add_column("Path", overflow="fold")
    if vulns:
        table.add_column("Vulns", overflow="fold")
    for path in summary.added:
        row = ["[green]+ added[/green]", path]
        if vulns:
            row.append(_vuln_badge(vuln_file_map.get(path)))
        table.add_row(*row)
    for path in summary.removed:
        row = ["[red]- removed[/red]", path]
        if vulns:
            row.append(_vuln_badge(vuln_file_map.get(path)))
        table.add_row(*row)
    for path in summary.modified:
        row = ["[yellow]~ modified[/yellow]", path]
        if vulns:
            row.append(_vuln_badge(vuln_file_map.get(path)))
        table.add_row(*row)
    console.print(table)
    console.print(
        f"[bold]{len(summary.added)} added, "
        f"{len(summary.removed)} removed, "
        f"{len(summary.modified)} modified[/bold]"
    )

    # --- Vuln summary with code snippets ---
    if vulns and vuln_labels:
        from rich.panel import Panel
        from rich.text import Text

        console.print()
        console.print(
            f"[bold red]{len(vuln_labels)} known vulnerability(ies) "
            f"affect this plugin in the diffed range:[/bold red]"
        )
        for label, _cve, refs_with_lines in vuln_snippets:
            console.print(f"\n  [red]* {label}[/red]")
            if refs_with_lines:
                for ref_path, line_no in refs_with_lines:
                    if line_no:
                        snippet = _read_snippet(
                            cfg, slug, version_a, ref_path, line_no
                        )
                        if snippet:
                            header = f"{ref_path}#L{line_no}"
                            console.print(Panel(
                                Text(snippet),
                                title=header,
                                border_style="red",
                                expand=False,
                            ))
    elif vulns:
        console.print()
        console.print("[green]No known vulnerabilities found for this plugin.[/green]")

    if not full:
        return

    # Show unified diff for all changed/added/removed files.
    console.print()
    all_paths = (
        [(p, "added") for p in summary.added]
        + [(p, "removed") for p in summary.removed]
        + [(p, "modified") for p in summary.modified]
    )
    for rel_path, _change_type in all_paths:
        diff_text = differ.unified(slug, version_a, version_b, rel_path)
        if diff_text:
            _print_colored_diff(diff_text)
            console.print()


def _fetch_cve_file_refs(cve_id: str, slug: str) -> set[str]:
    """Fetch file references from MITRE CVE API for a given CVE.

    Parses plugins.trac.wordpress.org/browser URLs and extracts relative
    file paths matching the plugin slug. Returns a set of relative paths.
    """
    import re

    import httpx as _httpx

    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        resp = _httpx.get(url, timeout=15, follow_redirects=True)
        if resp.status_code != 200:
            return set()
        data = resp.json()
    except Exception:
        return set()

    refs: set[str] = set()
    # Pattern: plugins.trac.wordpress.org/browser/<slug>/<tag_or_trunk>/<path>#L<line>
    pattern = re.compile(
        rf"plugins\.trac\.wordpress\.org/browser/{re.escape(slug)}"
        r"/(?:tags/[^/]+|trunk)/(.+?)(?:#L\d+)?$"
    )

    # Walk all references in the CNA container.
    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    for ref in cna.get("references", []):
        ref_url = ref.get("url", "")
        m = pattern.search(ref_url)
        if m:
            refs.add(m.group(1))

    return refs


def _fetch_cve_file_refs_with_lines(
    cve_id: str, slug: str
) -> list[tuple[str, int | None]]:
    """Fetch file references with line numbers from MITRE CVE API.

    Returns a list of (relative_path, line_number) tuples.
    line_number is None if the URL has no #L fragment.
    """
    import re

    import httpx as _httpx

    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        resp = _httpx.get(url, timeout=15, follow_redirects=True)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception:
        return []

    refs: list[tuple[str, int | None]] = []
    pattern = re.compile(
        rf"plugins\.trac\.wordpress\.org/browser/{re.escape(slug)}"
        r"/(?:tags/[^/]+|trunk)/(.+?)(?:#L(\d+))?$"
    )

    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    for ref in cna.get("references", []):
        ref_url = ref.get("url", "")
        m = pattern.search(ref_url)
        if m:
            path = m.group(1)
            line = int(m.group(2)) if m.group(2) else None
            refs.append((path, line))

    # Deduplicate while preserving order.
    seen: set[tuple[str, int | None]] = set()
    deduped: list[tuple[str, int | None]] = []
    for item in refs:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def _read_snippet(
    cfg: Config, slug: str, version: str, rel_path: str, line: int, context: int = 5
) -> str | None:
    """Read a code snippet from an extracted plugin file around the given line.

    Returns the snippet with line numbers, or None if the file can't be read.
    """
    file_path = cfg.extracted_dir / slug / version / rel_path
    if not file_path.is_file():
        return None
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None

    start = max(0, line - 1 - context)
    end = min(len(lines), line - 1 + context + 1)
    snippet_lines: list[str] = []
    for i in range(start, end):
        marker = ">>>" if i == line - 1 else "   "
        snippet_lines.append(f"{marker} {i + 1:4d} | {lines[i]}")
    return "\n".join(snippet_lines)


def _vuln_badge(labels: list[str] | None) -> str:
    """Return a short Rich-formatted badge for the vuln column."""
    if not labels:
        return ""
    return f"[bold red]{len(labels)} vuln(s)[/bold red]"


def _print_colored_diff(diff_text: str) -> None:
    """Print unified diff lines with git-style coloring.

    Uses Rich Text objects to avoid interpreting diff content as markup.
    """
    from rich.text import Text

    for line in diff_text.splitlines():
        if line.startswith("---") or line.startswith("+++"):
            console.print(Text(line, style="bold"))
        elif line.startswith("@@"):
            console.print(Text(line, style="cyan"))
        elif line.startswith("+"):
            console.print(Text(line, style="green"))
        elif line.startswith("-"):
            console.print(Text(line, style="red"))
        else:
            console.print(Text(line))


def _version_in_affected(
    version_a: str, version_b: str, affected_json: str
) -> bool:
    """Check if either diffed version falls within a vulnerability's affected range.

    The affected_json is a Wordfence-style dict like:
      {"from": "6.0.0", "to": "6.0.6", "from_inclusive": true, "to_inclusive": true}
    or a dict of such entries keyed by arbitrary strings.

    We use a simple tuple-based version comparison which works for most
    WordPress plugin versioning (dot-separated numeric segments).
    """
    import json as _json

    try:
        affected = _json.loads(affected_json)
    except (ValueError, TypeError):
        return True  # Can't parse — assume relevant to be safe.

    if not affected:
        return True  # No constraint data — assume relevant.

    def _parse_ver(v: str) -> tuple[int, ...]:
        parts: list[int] = []
        for seg in v.split("."):
            try:
                parts.append(int(seg))
            except ValueError:
                break
        return tuple(parts) if parts else (0,)

    def _check_range(constraint: dict) -> bool:
        """Return True if version_a or version_b is in the given range."""
        from_ver = constraint.get("from_version") or constraint.get("from") or ""
        to_ver = constraint.get("to_version") or constraint.get("to") or ""
        from_inc = constraint.get("from_inclusive", True)
        to_inc = constraint.get("to_inclusive", True)

        if not from_ver and not to_ver:
            return True  # No bounds — matches everything.

        for ver_str in (version_a, version_b):
            ver = _parse_ver(ver_str)
            low = _parse_ver(from_ver) if from_ver else (0,)
            high = _parse_ver(to_ver) if to_ver else (99999,)

            low_ok = (ver >= low) if from_inc else (ver > low)
            high_ok = (ver <= high) if to_inc else (ver < high)
            if low_ok and high_ok:
                return True
        return False

    # affected can be a single range dict or a dict of named ranges.
    if isinstance(affected, dict):
        # Check if it's a single range (has "from"/"to" keys).
        if "from" in affected or "from_version" in affected or "to" in affected:
            return _check_range(affected)
        # Otherwise it's a dict of ranges keyed by arbitrary IDs.
        for _key, constraint in affected.items():
            if isinstance(constraint, dict) and _check_range(constraint):
                return True
        return False
    elif isinstance(affected, list):
        for constraint in affected:
            if isinstance(constraint, dict) and _check_range(constraint):
                return True
        return False

    return True  # Unknown shape — assume relevant.


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


@main.command()
@click.argument("slug")
@click.pass_context
def info(ctx: click.Context, slug: str) -> None:
    """Show catalog state for SLUG."""
    catalog: Catalog = ctx.obj["catalog"]
    records = catalog.list_versions(slug)
    if not records:
        console.print(f"[yellow]No catalog entries for {slug}.[/yellow]")
        return

    table = Table(title=f"Catalog: {slug}")
    table.add_column("Version")
    table.add_column("Downloaded")
    table.add_column("Extracted")
    table.add_column("Size")
    table.add_column("SHA256", overflow="fold")
    for r in records:
        size = f"{r.size_bytes / 1024:.1f} KiB" if r.size_bytes else "-"
        table.add_row(
            r.version,
            r.downloaded_at or "-",
            r.extracted_at or "-",
            size,
            (r.sha256 or "-")[:16] + ("..." if r.sha256 else ""),
        )
    console.print(table)


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------


def _human_size(num_bytes: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def _dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    total = 0
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total


def _wipe_dir_contents(path: Path) -> None:
    """Delete everything inside `path` but keep the directory itself."""
    if not path.exists():
        return
    import shutil

    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=False)
        else:
            try:
                child.unlink()
            except FileNotFoundError:
                pass


@main.command()
@click.option(
    "--archives/--no-archives",
    default=False,
    help="Remove downloaded plugin .zip archives under data/plugins/.",
)
@click.option(
    "--extracted/--no-extracted",
    default=False,
    help="Remove extracted plugin sources under data/extracted/.",
)
@click.option(
    "--vulndb/--no-vulndb",
    default=False,
    help="Remove the cached Wordfence Intelligence feed under data/vulndb/.",
)
@click.option(
    "--catalog/--no-catalog",
    default=False,
    help="Remove the SQLite catalog (data/catalog.db). Plugin/vuln history is lost.",
)
@click.option(
    "--slug",
    "slug",
    default=None,
    help="Only clean artefacts for one plugin slug (applies to archives and extracted).",
)
@click.option(
    "--all",
    "clean_all",
    is_flag=True,
    default=False,
    help="Shortcut for --archives --extracted --vulndb --catalog.",
)
@click.option(
    "-y",
    "--yes",
    is_flag=True,
    default=False,
    help="Skip the confirmation prompt.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be deleted without touching anything.",
)
@click.pass_context
def clean(
    ctx: click.Context,
    archives: bool,
    extracted: bool,
    vulndb: bool,
    catalog: bool,
    slug: str | None,
    clean_all: bool,
    yes: bool,
    dry_run: bool,
) -> None:
    """Remove cached/downloaded artefacts so storage doesn't pile up.

    By default no flags are set and nothing is removed; pick what you want
    to clean explicitly. Use --all to wipe everything the tool produced.
    The directories themselves are preserved so future runs work without
    re-creating them manually.
    """
    cfg: Config = ctx.obj["config"]

    if clean_all:
        archives = extracted = vulndb = catalog = True

    if not any((archives, extracted, vulndb, catalog)):
        console.print(
            "[yellow]Nothing selected. Pass one of "
            "--archives / --extracted / --vulndb / --catalog / --all.[/yellow]"
        )
        return

    if slug and (vulndb or catalog):
        console.print(
            "[red]--slug only applies to --archives and --extracted.[/red]"
        )
        sys.exit(2)

    # Build a plan of (label, path, is_dir_contents_only) plus the byte total.
    plan: list[tuple[str, Path, bool]] = []
    if archives:
        target = cfg.plugins_dir / slug if slug else cfg.plugins_dir
        plan.append(("archives", target, slug is None))
    if extracted:
        target = cfg.extracted_dir / slug if slug else cfg.extracted_dir
        plan.append(("extracted", target, slug is None))
    if vulndb:
        plan.append(("vulndb cache", cfg.vulndb_dir, True))
    if catalog:
        plan.append(("catalog db", cfg.catalog_db, False))

    table = Table(title="Cleanup plan" + (f" (slug={slug})" if slug else ""))
    table.add_column("Target")
    table.add_column("Path", overflow="fold")
    table.add_column("Size", justify="right")
    total_bytes = 0
    for label, path, _ in plan:
        size = _dir_size(path) if path.is_dir() else (
            path.stat().st_size if path.exists() else 0
        )
        total_bytes += size
        exists_marker = "" if path.exists() else " [dim](missing)[/dim]"
        table.add_row(label, str(path) + exists_marker, _human_size(size))
    console.print(table)
    console.print(f"[bold]Total to free: {_human_size(total_bytes)}[/bold]")

    if dry_run:
        console.print("[dim]--dry-run set; no files removed.[/dim]")
        return

    if not yes:
        if not click.confirm("Proceed?", default=False):
            console.print("[yellow]Aborted.[/yellow]")
            return

    import shutil

    for label, path, contents_only in plan:
        if not path.exists():
            continue
        if path.is_dir():
            if contents_only:
                _wipe_dir_contents(path)
            else:
                shutil.rmtree(path, ignore_errors=False)
        else:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        console.print(f"[green]cleaned[/green] {label}: {path}")

    # Recreate the canonical directory layout so subsequent commands work.
    cfg.ensure_dirs()
    console.print("[bold]Done.[/bold]")


if __name__ == "__main__":
    main()
