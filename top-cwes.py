#!/usr/bin/env python3
"""
Count how many PRs list each CWE and print the most common ones.
Skips Dependabot PRs and PRs with no valid CWE, same as make-repo-figure.py.

Usage:
    python top-cwes.py [--data-dir data] [--cwe-dir cwes] [--top 5]
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DEPENDABOT = {"dependabot[bot]", "dependabot-preview[bot]"}
CWE_TYPES = ["weakness", "category", "view"]


def count_cwes(data_dir: Path) -> tuple[int, Counter, Counter, Counter]:
    """Return (PRs kept, PRs per CWE, PRs mentioning it, PRs linking it via a CVE)."""
    kept = 0
    total: Counter[str] = Counter()
    mentioned: Counter[str] = Counter()
    via_cves: Counter[str] = Counter()
    for path in data_dir.glob("*/*/*/cwes.json"):
        pr_path = path.parent / f"{path.parent.name}.json"
        try:
            cwes = json.loads(path.read_text(encoding="utf-8"))
            if not cwes:
                continue
            author = json.loads(pr_path.read_text(encoding="utf-8"))["user"]["login"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if author in DEPENDABOT:
            continue
        kept += 1
        for cwe, sources in cwes.items():
            total[cwe] += 1
            if sources.get("mentioned"):
                mentioned[cwe] += 1
            if sources.get("via_cves"):
                via_cves[cwe] += 1
    return kept, total, mentioned, via_cves


def cwe_name(cwe: str, cwe_dir: Path) -> str:
    """Look up a CWE's name in the downloaded catalog; '?' if it is not there."""
    number = cwe.split("-")[-1]
    for cwe_type in CWE_TYPES:
        try:
            record = json.loads((cwe_dir / cwe_type / f"cwe-{number}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        return record.get("Name", "?")
    return "?"


def lowercase_name(name: str) -> str:
    """Lowercase a name for use mid-sentence, keeping acronyms such as HTTP."""
    return " ".join(word if word.isupper() else word.lower() for word in name.split())


def latex_sentence(top: list[tuple[str, str]]) -> str:
    """Join (cwe, name) pairs into the sentence used in the paper."""
    parts = [f"{lowercase_name(name)} ({cwe})" for cwe, name in top]
    if len(parts) > 1:
        parts[-1] = f"and {parts[-1]}"
    separator = ", " if len(parts) > 2 else " "
    return f"The most frequent weaknesses are {separator.join(parts)}."


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=Path, default=Path("data"), help="Root directory of mined PR data (default: data).")
    parser.add_argument("--cwe-dir", type=Path, default=Path("cwes"), help="Root directory of the CWE catalog (default: cwes).")
    parser.add_argument("--top", type=int, default=5, help="How many CWEs to show (default: 5).")
    args = parser.parse_args()

    kept, total, mentioned, via_cves = count_cwes(args.data_dir)
    if not kept:
        sys.exit(f"No PRs with a valid CWE found under {args.data_dir}. Check --data-dir.")

    # Sort by count, then by CWE ID, so ties always come out in the same order.
    ranked = sorted(total.items(), key=lambda item: (-item[1], item[0]))[: args.top]
    top = [(cwe, cwe_name(cwe, args.cwe_dir)) for cwe, _ in ranked]

    print(f"PRs counted: {kept:,}")
    print(f"Distinct CWEs: {len(total):,}")
    print()
    print(f"{'Rank':>4}  {'CWE':<9} {'PRs':>7} {'Share':>6} {'Mentioned':>9} {'Via CVE':>8}  Name")
    for rank, ((cwe, n), (_, name)) in enumerate(zip(ranked, top), 1):
        print(f"{rank:>4}  {cwe:<9} {n:>7,} {n / kept:>6.1%} {mentioned[cwe]:>9,} {via_cves[cwe]:>8,}  {name}")
    print()
    print(latex_sentence(top))


if __name__ == "__main__":
    main()
