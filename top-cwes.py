#!/usr/bin/env python3
"""
Count how many PRs list each CWE and print the most common ones.
Skips Dependabot PRs and PRs with no valid CWE, same as make-repo-figure.py.

Usage:
    python top-cwes.py [--data-dir data] [--cwe-dir cwes] [--top 5] [--groups groups.csv]
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

DEPENDABOT = {"dependabot[bot]", "dependabot-preview[bot]"}
CWE_TYPES = ["weakness", "category", "view"]


def parse_groups(path: Path) -> list[list[str]]:
    """Read a CSV where each row is a comma-separated list of CWE numbers."""
    groups = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        members = [f"CWE-{token.strip().removeprefix('CWE-')}" for token in line.split(",") if token.strip()]
        if members:
            groups.append(members)
    return groups


def count_cwes(
    data_dir: Path, groups: list[list[str]] | None = None
) -> tuple[int, Counter, Counter, Counter, list[dict[str, int]]]:
    """Return (PRs kept, PRs per CWE, PRs mentioning it, PRs linking it via a CVE, per-group counts)."""
    groups = groups or []
    group_counts = [{"total": 0, "mentioned": 0, "via_cves": 0} for _ in groups]
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
        for i, group in enumerate(groups):
            present = [m for m in group if m in cwes]
            if not present:
                continue
            group_counts[i]["total"] += 1
            if any(cwes[m].get("mentioned") for m in present):
                group_counts[i]["mentioned"] += 1
            if any(cwes[m].get("via_cves") for m in present):
                group_counts[i]["via_cves"] += 1
    return kept, total, mentioned, via_cves, group_counts


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
    parser.add_argument("--groups", type=Path, help="CSV file where each row is a comma-separated group of CWEs to count together.")
    parser.add_argument("--no-name", action="store_true", help="Omit the Name column (and the LaTeX name sentence) from the output.")
    parser.add_argument("--pillars", action="store_true", help="With --groups, label each group as P<pillar> (first member) instead of joining all member numbers.")
    args = parser.parse_args()

    groups = parse_groups(args.groups) if args.groups else []
    kept, total, mentioned, via_cves, group_counts = count_cwes(args.data_dir, groups)
    if not kept:
        sys.exit(f"No PRs with a valid CWE found under {args.data_dir}. Check --data-dir.")

    # Each entry is (label, count, mentioned, via CVE, name). Groups join their members' names.
    entries = [
        (cwe, n, mentioned[cwe], via_cves[cwe], cwe_name(cwe, args.cwe_dir) if not args.no_name else "")
        for cwe, n in total.items()
    ]
    for group, counts in zip(groups, group_counts):
        if args.pillars:
            label = f"P{group[0].split('-')[-1]}"
        else:
            label = "+".join(cwe.split("-")[-1] for cwe in group)
        if args.no_name:
            name = ""
        elif args.pillars:
            name = cwe_name(group[0], args.cwe_dir)
        else:
            name = "; ".join(cwe_name(cwe, args.cwe_dir) for cwe in group)
        entries.append((label, counts["total"], counts["mentioned"], counts["via_cves"], name))

    # Sort by count, then by label, so ties always come out in the same order.
    ranked = sorted(entries, key=lambda item: (-item[1], item[0]))[: args.top]
    top = [(label, name) for label, _, _, _, name in ranked]

    print(f"PRs counted: {kept:,}")
    print(f"Distinct CWEs: {len(total):,}")
    if groups:
        print(f"Groups: {len(groups):,}")
    print()
    header = f"{'Rank':>4}  {'CWE':<28} {'PRs':>7} {'Share':>6} {'Mentioned':>9} {'Via CVE':>8}"
    if not args.no_name:
        header += "  Name"
    print(header)
    for rank, (label, n, ment, via, name) in enumerate(ranked, 1):
        row = f"{rank:>4}  {label:<28} {n:>7,} {n / kept:>6.1%} {ment:>9,} {via:>8,}"
        if not args.no_name:
            row += f"  {name}"
        print(row)
    print()
    if not args.no_name:
        print(latex_sentence(top))


if __name__ == "__main__":
    main()
