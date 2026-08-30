#!/usr/bin/env python3
"""
CWE Catalog Miner

Downloads the full Common Weakness Enumeration (CWE) catalog from MITRE using public REST API.

Fetches one bulk "all" response per CWE type (weakness, category, view)
and splits it into one JSON file per entry.

Data is stored under cwes/ (or --data-dir):
    weakness/cwe-<id>.json   One file per CWE weakness entry
    category/cwe-<id>.json   One file per CWE category entry
    view/cwe-<id>.json       One file per CWE view entry

Usage:
    python cwe-miner.py [--start ID] [--end ID] [--types weakness category view] [--force] [--verbose]
"""

import argparse
import json
import logging
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

try:
    import certifi

    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _SSL_CONTEXT = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
API_BASE = "https://cwe-api.mitre.org/api/v1"
USER_AGENT = "CREST-CWE-Miner/1.0.0 (https://github.com/unl-pal/crest-pr-miner)"
DATA_ROOT = Path("cwes")

# Maps CLI/type name -> (API path segment, top-level JSON array key)
TYPES = {
    "weakness": "Weaknesses",
    "category": "Categories",
    "view": "Views",
}

RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 5


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _fetch_json(url: str):
    """GET url and return parsed JSON, retrying transient failures."""
    import time

    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    last_exc = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=60, context=_SSL_CONTEXT) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            last_exc = exc
            logger.warning("Request to %s failed (attempt %d/%d): %s", url, attempt, RETRY_ATTEMPTS, exc)
            if attempt < RETRY_ATTEMPTS:
                time.sleep(RETRY_BACKOFF_SECONDS)
    raise RuntimeError(f"Failed to fetch {url} after {RETRY_ATTEMPTS} attempts") from last_exc


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------
def fetch_all(type_name: str) -> list:
    """Return all entries for type_name from the bulk API endpoint."""
    array_key = TYPES[type_name]
    url = f"{API_BASE}/cwe/{type_name}/all"
    logger.info("Fetching %s", url)
    payload = _fetch_json(url)

    entries = payload.get(array_key, [])
    logger.info("%s: %d entries", type_name, len(entries))
    return entries


# ---------------------------------------------------------------------------
# Write per-entry files
# ---------------------------------------------------------------------------
def write_entries(type_name: str, entries: list, data_dir: Path, start: int | None, end: int | None, force: bool) -> tuple[int, int]:
    """Write one JSON file per entry in [start, end]. Returns (written, skipped)."""
    out_dir = data_dir / type_name
    out_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped = 0
    for entry in entries:
        try:
            cwe_id = int(entry["ID"])
        except (KeyError, TypeError, ValueError):
            logger.warning("Skipping %s entry with missing/invalid ID: %r", type_name, entry.get("ID"))
            continue

        if start is not None and cwe_id < start:
            continue
        if end is not None and cwe_id > end:
            continue

        entry_path = out_dir / f"cwe-{cwe_id}.json"
        if entry_path.exists() and not force:
            skipped += 1
            continue

        entry_path.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
        written += 1

    logger.info("%s: wrote %d, skipped %d (already present)", type_name, written, skipped)
    return written, skipped


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Download the CWE catalog via MITRE's REST API.")
    parser.add_argument("--start", type=int, default=None, help="Only write entries with CWE ID >= START.")
    parser.add_argument("--end", type=int, default=None, help="Only write entries with CWE ID <= END.")
    parser.add_argument(
        "--types",
        nargs="+",
        choices=sorted(TYPES),
        default=sorted(TYPES),
        help="Which CWE entry types to download (default: all).",
    )
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"Root directory for downloaded data (default: {DATA_ROOT}).")
    parser.add_argument("--force", action="store_true", help="Re-fetch from the API and overwrite existing files.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if args.start is not None and args.end is not None and args.start > args.end:
        logger.error("--start (%d) must be <= --end (%d)", args.start, args.end)
        return 1

    total_written = 0
    total_skipped = 0
    for type_name in args.types:
        entries = fetch_all(type_name)
        written, skipped = write_entries(type_name, entries, args.data_dir, args.start, args.end, args.force)
        total_written += written
        total_skipped += skipped

    logger.info("Done. %d files written, %d already present.", total_written, total_skipped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
