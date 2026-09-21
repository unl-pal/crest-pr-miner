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
import json
import logging
import re
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
import os

load_dotenv()

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

NVD_API_KEY = os.environ.get("NVD_API_KEY")
# NVD allows 5 req/30s without a key, 50 req/30s with one. Pace requests
# to stay under that rather than relying on 429 retries.
_MIN_REQUEST_INTERVAL = 0.7 if NVD_API_KEY else 6.5
_last_request_at = 0.0

def _rate_limit():
    global _last_request_at
    elapsed = time.monotonic() - _last_request_at
    if elapsed < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_at = time.monotonic()

def find_cve_ids(data_dir: Path) -> set[str]:
    """Scan every non-.diff file under data_dir and return the set of distinct CVE IDs mentioned."""
    cve_ids: set[str] = set()
    files_scanned = 0

    for file_path in data_dir.rglob("[0-9]*.json"):
        if not file_path.is_file():
            continue

        file_path = file_path.resolve()
        local_cves = []

        cvefile = file_path
        if '/reviews/' in str(file_path) or '/commits/' in str(file_path):
            cvefile = file_path.parent
        cvefile = cvefile.parent / "cves.json"

        if cvefile.exists():
            logger.info("Loaded cached results %s", cvefile)
            with open(cvefile, 'r') as f:
                cvedata = json.load(f)
            local_cves = cvedata['cves']

        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            logger.warning("Could not read %s: %s", file_path, exc)
            continue

        files_scanned += 1
        logger.info("Scanned file %s", file_path)
        local_cves.extend(match.upper() for match in CVE_ID_RE.findall(text))
        with cvefile.open("w", encoding="utf-8") as f:
            json.dump({ 'cves': local_cves }, f, indent=2)

        cve_ids.update(local_cves)

    logger.info("Scanned %d files", files_scanned)
    return cve_ids


def download_cve(cve_id: str, cve_data_dir: Path, force: bool, skip_history: bool) -> bool:
    """Invoke cve-downloader.py for cve_id. Returns True on success."""
    cmd = [sys.executable, str(DOWNLOADER_SCRIPT), cve_id, "--data-dir", str(cve_data_dir)]
    if force:
        cmd.append("--force")
    if skip_history:
        cmd.append("--skip-history")

    _rate_limit()
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
