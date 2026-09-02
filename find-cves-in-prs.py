#!/usr/bin/env python3
"""
Find CVEs in PRs

Scans every mined PR under data/ for CVE ID mentions, then invokes
cve-downloader.py for each distinct CVE found so its metadata (and
history, unless skipped) gets downloaded.

Every file in a PR's directory is scanned as plain text (regardless of
its actual format - PR metadata, comments, reviews, timeline, commit
metadata are all JSON, but this searches text rather than parsing each
file's schema) except *.diff files, which are excluded: they include
unchanged surrounding context lines, so a CVE mentioned elsewhere in a
file would show up in a diff even when unrelated to that PR.

Usage:
    python find-cves-in-prs.py [--data-dir DIR] [--cve-data-dir DIR]
                                [--force] [--skip-history] [--verbose]
"""

import argparse
import logging
import re
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

DATA_ROOT = Path("data")
CVE_DATA_ROOT = Path("cves")
CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
DOWNLOADER_SCRIPT = Path(__file__).resolve().parent / "cve-downloader.py"


def find_cve_ids(data_dir: Path) -> set[str]:
    """Scan every non-.diff file under data_dir and return the set of distinct CVE IDs mentioned."""
    cve_ids: set[str] = set()
    files_scanned = 0
    files_skipped = 0

    for file_path in sorted(data_dir.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix == ".diff":
            files_skipped += 1
            continue

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("Could not read %s: %s", file_path, exc)
            continue

        files_scanned += 1
        cve_ids.update(match.upper() for match in CVE_ID_RE.findall(text))

    logger.info("Scanned %d files (%d .diff files skipped)", files_scanned, files_skipped)
    return cve_ids


def download_cve(cve_id: str, cve_data_dir: Path, force: bool, skip_history: bool) -> bool:
    """Invoke cve-downloader.py for cve_id. Returns True on success."""
    cmd = [sys.executable, str(DOWNLOADER_SCRIPT), cve_id, "--data-dir", str(cve_data_dir)]
    if force:
        cmd.append("--force")
    if skip_history:
        cmd.append("--skip-history")

    result = subprocess.run(cmd)
    if result.returncode != 0:
        logger.warning("%s: cve-downloader.py exited with code %d", cve_id, result.returncode)
        return False
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="Find CVE mentions across mined PRs and download their metadata.")
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"Root directory of mined PR data (default: {DATA_ROOT}).")
    parser.add_argument("--cve-data-dir", type=Path, default=CVE_DATA_ROOT, help=f"Root directory passed to cve-downloader.py for downloaded CVE data (default: {CVE_DATA_ROOT}).")
    parser.add_argument("--force", action="store_true", help="Pass --force through to cve-downloader.py to re-fetch and overwrite existing files.")
    parser.add_argument("--skip-history", action="store_true", help="Pass --skip-history through to cve-downloader.py.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    args = parser.parse_args(argv)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.data_dir.exists():
        logger.error("Data directory %s does not exist", args.data_dir)
        return 1

    if not DOWNLOADER_SCRIPT.exists():
        logger.error("cve-downloader.py not found at %s", DOWNLOADER_SCRIPT)
        return 1

    cve_ids = find_cve_ids(args.data_dir)
    logger.info("Found %d distinct CVEs", len(cve_ids))

    failures = 0
    for cve_id in sorted(cve_ids):
        if not download_cve(cve_id, args.cve_data_dir, args.force, args.skip_history):
            failures += 1

    succeeded = len(cve_ids) - failures
    logger.info("Done. %d/%d CVEs downloaded successfully", succeeded, len(cve_ids))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
