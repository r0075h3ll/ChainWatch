#!/usr/bin/env python3
"""
Download dependency graph SBOMs for GitHub repositories using the `gh` CLI.

Usage:
    # Download SBOMs for specific repos:
    python download_sbom.py --org my-org --repos repo1 repo2 repo3

    # Download SBOMs for ALL repos in an org:
    python download_sbom.py --org my-org --repos all

    # Keep only npm and/or PyPI packages:
    python download_sbom.py --org my-org --repos all --keep npm pypi

    # Exclude npm and/or PyPI packages:
    python download_sbom.py --org my-org --repos all --exclude npm pypi

    # Search for a specific package across all repos (no files written):
    python download_sbom.py --org my-org --repos all --search lodash@4.17.21
    python download_sbom.py --org my-org --repos all --search "pkg:npm/lodash@4.17.21"
    python download_sbom.py --org my-org --repos all --search lodash@4.17.21 requests@2.28.0

    # Search using a text file of terms (one per line, # lines are comments):
    python download_sbom.py --org my-org --repos all --search-file packages.txt

    # Combine inline terms and a file:
    python download_sbom.py --org my-org --repos all --search "pkg:npm/lodash@4.17.21" --search-file more.txt

    # Specify a custom output directory:
    python download_sbom.py --org my-org --repos all --output-dir ./sboms

Prerequisites:
    - `gh` CLI installed and authenticated (`gh auth login`)
    - Sufficient permissions on the org/repos (read access + dependency graph enabled)
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, UTC
from pathlib import Path


# ─────────────────────────────────────────────
# Ecosystem helpers
# ─────────────────────────────────────────────

# Maps friendly CLI names → PURL namespace prefixes used in GitHub SBOMs.
# e.g. "pkg:npm/lodash@4.17.21"  →  namespace = "npm"
#      "pkg:pypi/requests@2.28.0" →  namespace = "pypi"
ECOSYSTEM_ALIASES: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "pip": "pypi",      # common alias
    "python": "pypi",   # common alias
}

SUPPORTED_ECOSYSTEMS = sorted({v for v in ECOSYSTEM_ALIASES.values()})


def resolve_ecosystems(names: list[str]) -> set[str]:
    """
    Convert user-supplied ecosystem names to canonical PURL namespaces.
    Exits with a helpful message on unknown names.
    """
    resolved: set[str] = set()
    unknown: list[str] = []
    for name in names:
        canonical = ECOSYSTEM_ALIASES.get(name.lower())
        if canonical:
            resolved.add(canonical)
        else:
            unknown.append(name)

    if unknown:
        print(f"✗ Unknown ecosystem(s): {', '.join(unknown)}")
        print(f"  Supported values: {', '.join(ECOSYSTEM_ALIASES)}")
        sys.exit(1)

    return resolved


def purl_namespace(purl: str) -> str | None:
    """
    Extract the PURL type/namespace from a package URL string.
    e.g. "pkg:npm/lodash@4.17.21" → "npm"
    Returns None if the string is not a recognisable PURL.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    # pkg:<type>/...
    rest = purl[4:]  # strip "pkg:"
    return rest.split("/")[0].lower()


def filter_packages(
    packages: list[dict],
    keep: set[str] | None,
    exclude: set[str] | None,
) -> tuple[list[dict], dict[str, int]]:
    """
    Apply --keep / --exclude filters to the list of SPDX packages.

    - keep:    retain only packages whose PURL namespace is in this set.
    - exclude: drop packages whose PURL namespace is in this set.
    - If both are None, the original list is returned unchanged.

    Also returns a breakdown dict of {namespace: count} for the kept packages.
    """
    if keep is None and exclude is None:
        breakdown = {}
        for pkg in packages:
            for ref in pkg.get("externalRefs", []):
                ns = purl_namespace(ref.get("referenceLocator", ""))
                if ns:
                    breakdown[ns] = breakdown.get(ns, 0) + 1
                    break
        return packages, breakdown

    filtered: list[dict] = []
    breakdown: dict[str, int] = {}

    for pkg in packages:
        # Find the PURL external reference (if any)
        ns = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                ns = purl_namespace(ref.get("referenceLocator", ""))
                break

        # Packages without a PURL (e.g. the root "DESCRIBES" package) are
        # always kept so the SBOM document structure stays valid.
        if ns is None:
            filtered.append(pkg)
            continue

        if keep is not None and ns not in keep:
            continue
        if exclude is not None and ns in exclude:
            continue

        filtered.append(pkg)
        breakdown[ns] = breakdown.get(ns, 0) + 1

    return filtered, breakdown


# ─────────────────────────────────────────────
# GitHub / gh CLI helpers
# ─────────────────────────────────────────────

def run_gh(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a `gh` command and return the result."""
    cmd = ["gh"] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def check_gh_auth() -> None:
    """Abort early if the user is not authenticated."""
    result = run_gh(["auth", "status"], check=False)
    if result.returncode != 0:
        print("✗ Not authenticated with GitHub CLI.")
        print("  Run: gh auth login")
        sys.exit(1)


def fetch_all_repos(org: str) -> list[str]:
    """Return a list of all repository names (slug only) in *org*."""
    print(f"→ Fetching repository list for org '{org}' …")

    result = run_gh([
        "api",
        f"/orgs/{org}/repos",
        "--paginate",
        "--jq", ".[].name",
    ], check=False)

    if result.returncode != 0:
        print(f"✗ Failed to list repositories for org '{org}':")
        print(f"  {result.stderr.strip()}")
        sys.exit(1)

    repos = [n.strip() for n in result.stdout.splitlines() if n.strip()]
    print(f"  Found {len(repos)} repositories.")
    return repos


def search_packages(raw_json: str, terms: list[str]) -> dict[str, bool]:
    """
    Do a plain substring search for each term in the raw SBOM JSON string.
    Returns {term: found} for every term supplied.
    """
    return {term: term in raw_json for term in terms}


RETRYABLE_ERRORS = ("timed out", "http 500", "http 502", "http 503", "http 504")
MAX_RETRIES = 3
RETRY_BACKOFF = [30, 60, 120]  # seconds between each retry attempt


def download_sbom(
    org: str,
    repo: str,
    output_dir: Path,
    keep: "set[str] | None",
    exclude: "set[str] | None",
    search_terms: "list[str] | None" = None,
) -> "tuple[bool, dict[str, bool]]":
    """
    Download the SBOM for *org*/*repo*, optionally filter packages, and save.
    Retries up to MAX_RETRIES times on transient GitHub errors (timeout, 5xx).
    Returns (success, {term: found}) — the hits dict is empty when not searching.
    """
    endpoint = f"/repos/{org}/{repo}/dependency-graph/sbom"
    no_hits: dict[str, bool] = {t: False for t in (search_terms or [])}

    result = None
    for attempt in range(1, MAX_RETRIES + 1):
        result = run_gh(["api", endpoint], check=False)
        if result.returncode == 0:
            break
        stderr = result.stderr.strip()
        is_retryable = any(e in stderr.lower() for e in RETRYABLE_ERRORS)
        if is_retryable and attempt < MAX_RETRIES:
            wait = RETRY_BACKOFF[attempt - 1]
            print(f"  ⚠ {repo}: transient error (attempt {attempt}/{MAX_RETRIES}), retrying in {wait}s — {stderr}")
            time.sleep(wait)
        else:
            break

    if result.returncode != 0:
        stderr = result.stderr.strip()
        if "dependency graph is disabled" in stderr.lower():
            reason = "dependency graph is disabled for this repo"
        elif "not found" in stderr.lower() or "404" in stderr:
            reason = "repo not found or no access"
        elif "403" in stderr:
            reason = "insufficient permissions"
        elif any(e in stderr.lower() for e in RETRYABLE_ERRORS):
            reason = f"timed out after {MAX_RETRIES} attempts — {stderr}"
        else:
            reason = stderr or "unknown error"
        print(f"  ✗ {repo}: {reason}")
        return False, no_hits

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"  ✗ {repo}: invalid JSON response — {exc}")
        return False, no_hits

    # ── Package search (substring match on raw JSON) ──
    hits: dict[str, bool] = {}
    if search_terms:
        hits = search_packages(result.stdout, search_terms)
        found = [t for t, ok in hits.items() if ok]
        missing = [t for t, ok in hits.items() if not ok]
        if found:
            print(f"  ✓ found     → {', '.join(found)}")
        if missing:
            print(f"  ✗ not found → {', '.join(missing)}")

    # ── Apply ecosystem filter ────────────────
    sbom = data.get("sbom", data)  # GitHub wraps the SPDX doc under "sbom"
    original_packages: list[dict] = sbom.get("packages", [])
    filtered_packages, breakdown = filter_packages(original_packages, keep, exclude)

    removed = len(original_packages) - len(filtered_packages)
    if keep or exclude:
        kept_total = sum(breakdown.values())
        breakdown_str = ", ".join(f"{ns}={n}" for ns, n in sorted(breakdown.items()))
        detail = f"{kept_total} kept ({breakdown_str}), {removed} removed"
    else:
        detail = f"{len(filtered_packages)} packages"

    # ── Build simplified output format ───────
    purl_list: list[str] = []
    for pkg in filtered_packages:
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                locator = ref.get("referenceLocator", "").strip()
                if locator:
                    purl_list.append(locator)
                break

    output = {
        "repo_name": repo,
        "packages": purl_list,
    }

    suffix = "_filtered" if (keep or exclude) else ""
    out_file = output_dir / f"{repo}_sbom{suffix}.json"
    out_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"  ✓ {repo} → {out_file}  [{detail}]")
    return True, hits


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download GitHub dependency-graph SBOMs via the gh CLI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--org", "-o",
        required=True,
        help="GitHub organisation name (e.g. my-org)",
    )
    parser.add_argument(
        "--repos", "-r",
        nargs="+",
        required=True,
        metavar="REPO",
        help="One or more repo names, or the special value 'all'",
    )
    parser.add_argument(
        "--output-dir", "-d",
        default="./sboms",
        help="Directory to write SBOM files into (default: ./sboms)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=15.0,
        metavar="SECONDS",
        help=(
            "Seconds to wait between API calls when processing more than 5 repos "
            "(default: 15). Use --delay to set a custom value, e.g. --delay 30."
        ),
    )

    # Mutually exclusive ecosystem filters
    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument(
        "--keep",
        nargs="+",
        metavar="ECOSYSTEM",
        help=(
            "Keep ONLY packages from these ecosystems. "
            f"Supported: {', '.join(ECOSYSTEM_ALIASES)}. "
            "Example: --keep npm pypi"
        ),
    )
    filter_group.add_argument(
        "--exclude",
        nargs="+",
        metavar="ECOSYSTEM",
        help=(
            "Exclude packages from these ecosystems. "
            f"Supported: {', '.join(ECOSYSTEM_ALIASES)}. "
            "Example: --exclude npm"
        ),
    )

    parser.add_argument(
        "--search", "-s",
        nargs="+",
        metavar="PKG",
        help=(
            "Search for one or more package substrings across all fetched SBOMs. "
            "Accepts 'name@version' (e.g. lodash@4.17.21) or full PURL "
            "(e.g. pkg:npm/lodash@4.17.21). Multiple terms are space-separated. "
            "Can be combined with --search-file."
        ),
    )
    parser.add_argument(
        "--search-file", "-S",
        metavar="FILE",
        help=(
            "Path to a plain-text file with one search term per line. "
            "Each term can be 'name@version' or a full PURL (pkg:npm/lodash@4.17.21). "
            "Blank lines and lines starting with '#' are ignored. "
            "Can be combined with --search."
        ),
    )

    args = parser.parse_args()

    # ── Resolve ecosystem filters ─────────────
    keep_ecosystems: set[str] | None = None
    exclude_ecosystems: set[str] | None = None

    if args.keep:
        keep_ecosystems = resolve_ecosystems(args.keep)
        print(f"→ Keeping only ecosystems: {', '.join(sorted(keep_ecosystems))}")
    elif args.exclude:
        exclude_ecosystems = resolve_ecosystems(args.exclude)
        print(f"→ Excluding ecosystems: {', '.join(sorted(exclude_ecosystems))}")

    # ── Resolve search terms (inline + file) ──
    raw_terms: list[str] = list(args.search or [])

    if args.search_file:
        search_file_path = Path(args.search_file)
        if not search_file_path.is_file():
            print(f"✗ --search-file: file not found: {search_file_path}")
            sys.exit(1)
        lines = search_file_path.read_text(encoding="utf-8").splitlines()
        file_terms = [
            ln.strip()
            for ln in lines
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if not file_terms:
            print(f"✗ --search-file: no valid search terms found in {search_file_path}")
            sys.exit(1)
        raw_terms.extend(file_terms)
        print(f"→ Loaded {len(file_terms)} term(s) from {search_file_path}")

    # Deduplicate while preserving order
    seen: set[str] = set()
    search_terms: list[str] | None = None
    if raw_terms:
        deduped = []
        for t in raw_terms:
            if t not in seen:
                seen.add(t)
                deduped.append(t)
        search_terms = deduped
        print(f"→ Searching for {len(search_terms)} unique term(s): {', '.join(search_terms)}")

    # ── Preflight ────────────────────────────
    check_gh_auth()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Resolve repository list ───────────────
    if len(args.repos) == 1 and args.repos[0].lower() == "all":
        repos = fetch_all_repos(args.org)
    else:
        repos = args.repos

    if not repos:
        print("No repositories to process. Exiting.")
        sys.exit(0)

    # ── Download SBOMs ────────────────────────
    print(f"\nDownloading SBOMs for {len(repos)} repo(s) into '{output_dir}/' …\n")
    start = datetime.now()

    succeeded, failed = [], []
    # {term: [repo, repo, ...]} — repos where the term was found
    search_hits: dict[str, list[str]] = {t: [] for t in (search_terms or [])}

    apply_delay = len(repos) > 5
    if apply_delay:
        print(f"  (rate-limit delay: {args.delay}s between requests — default 15s, override with --delay)\n")

    for i, repo in enumerate(repos, 1):
        print(f"[{i}/{len(repos)}] {repo}")
        ok, hits = download_sbom(args.org, repo, output_dir, keep_ecosystems, exclude_ecosystems, search_terms)
        (succeeded if ok else failed).append(repo)
        for term, found in hits.items():
            if found:
                search_hits[term].append(repo)

        if apply_delay and i < len(repos):
            time.sleep(args.delay)

    # ── Summary ───────────────────────────────
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n{'─' * 50}")
    print(f"Done in {elapsed:.1f}s — {len(succeeded)} succeeded, {len(failed)} failed.")

    if failed:
        print("\nFailed repositories:")
        for repo in failed:
            print(f"  • {repo}")

    if search_terms:
        print("\nSearch results:")
        for term in search_terms:
            matches = search_hits[term]
            if matches:
                print(f"  '{term}' found in {len(matches)} repo(s):")
                for r in matches:
                    print(f"      • {r}")
            else:
                print(f"  '{term}' — not found in any repo")

    summary = {
        "org": args.org,
        "timestamp": datetime.now(UTC).isoformat(),
        "total": len(repos),
        "filter": {
            "mode": "keep" if keep_ecosystems else ("exclude" if exclude_ecosystems else "none"),
            "ecosystems": sorted(keep_ecosystems or exclude_ecosystems or []),
        },
        "search": {
            "terms": search_terms or [],
            "hits": {term: search_hits[term] for term in (search_terms or [])},
        },
        "succeeded": succeeded,
        "failed": failed,
    }
    summary_file = output_dir / "_summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"\nSummary written to {summary_file}")

    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
