#!/usr/bin/env python3
"""Generate a reproducible, balanced PR rating sample workbook."""

import argparse
import itertools
import math
import random
import sys
from pathlib import Path
from urllib.parse import quote

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

DATA_ROOT = Path("data")
OUTPUT_FILE = Path("sample.xlsx")
DEFAULT_SEED = "crest-pr-miner"
RATING_VALUES = ("SecurityRelated", "NotSecurityRelated")


def positive_int(value: str) -> int:
    """Parse a positive integer command-line value."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def find_pr_files(data_dir: Path) -> list[Path]:
    """Return PR JSON files in data/<owner>/<repo>/<number>/<number>.json order."""
    return sorted(path for path in data_dir.glob("*/*/*/*.json") if path.stem == path.parent.name)


def default_sample_size(population_size: int) -> int:
    """Calculate a finite-population sample size for 95% confidence and 5% error."""
    z_score = 1.96
    proportion = 0.5
    margin = 0.05
    variance = z_score**2 * proportion * (1 - proportion)
    return math.ceil(
        population_size * variance
        / (margin**2 * (population_size - 1) + variance)
    )


def systematic_sample(
    prs: list[Path], sample_size: int, rng: random.Random
) -> list[Path]:
    """Sample a sorted population at a fixed interval from a random start."""
    interval = len(prs) / sample_size
    start = rng.random() * interval
    indices = [min(len(prs) - 1, int(start + i * interval)) for i in range(sample_size)]
    if len(set(indices)) != sample_size:
        raise RuntimeError("Systematic sampling produced duplicate PRs")
    return [prs[index] for index in indices]


def balanced_pair_schedule(
    sample_size: int, raters: int, rng: random.Random
) -> list[tuple[int, int]]:
    """Balance pair counts first and rater workloads simultaneously."""
    pairs = list(itertools.combinations(range(raters), 2))
    pair_floor, extra_pairs = divmod(sample_size, len(pairs))

    # The regular pair assignments give every rater the same base workload.
    # Choose a randomized, nearly regular simple graph for the remaining pairs.
    extra_degrees = [2 * extra_pairs // raters] * raters
    high_degree_count = (2 * extra_pairs) % raters
    rater_order = list(range(raters))
    rng.shuffle(rater_order)
    for rater in rater_order[:high_degree_count]:
        extra_degrees[rater] += 1

    remaining = extra_degrees[:]
    extra_edges: list[tuple[int, int]] = []
    while any(remaining):
        candidates = [rater for rater, degree in enumerate(remaining) if degree]
        rng.shuffle(candidates)
        current = max(candidates, key=remaining.__getitem__)
        degree = remaining[current]
        neighbors = [rater for rater in range(raters) if rater != current and remaining[rater]]
        rng.shuffle(neighbors)
        neighbors.sort(key=remaining.__getitem__, reverse=True)
        if degree > len(neighbors) or (
            neighbors and remaining[neighbors[degree - 1]] == 0
        ):
            raise RuntimeError("Could not construct balanced rater pair assignments")
        for neighbor in neighbors[:degree]:
            remaining[neighbor] -= 1
            extra_edges.append(tuple(sorted((current, neighbor))))
        remaining[current] = 0

    schedule = [pair for pair in pairs for _ in range(pair_floor)]
    schedule.extend(extra_edges)
    rng.shuffle(schedule)
    return schedule


def pr_url(pr_file: Path, data_dir: Path) -> str:
    owner, repo, pull_number, _filename = pr_file.relative_to(data_dir).parts
    return (
        f"https://github.com/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/pull/{quote(pull_number, safe='')}"
    )


def create_workbook(
    sampled_prs: list[Path], assignments: list[tuple[int, int]], raters: int, data_dir: Path
) -> None:
    workbook = Workbook()
    summary = workbook.active
    summary.title = "Summary"
    summary.append(["Pull Request", "Rater 1", "Rater 2", "Agreement Status", "Judgment"])

    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(color="FFFFFF", bold=True)
    for sheet in [summary]:
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center")
        sheet.freeze_panes = "A2"

    rater_sheets = []
    for index in range(raters):
        sheet = workbook.create_sheet(f"Rater {index + 1}")
        sheet.append(["Pull Request", "Rating"])
        for cell in sheet[1]:
            cell.fill = header_fill
            cell.font = header_font
            cell.alignment = Alignment(horizontal="center")
        sheet.freeze_panes = "A2"
        sheet.column_dimensions["A"].width = 76
        sheet.column_dimensions["B"].width = 25
        validation = DataValidation(
            type="list",
            formula1='"SecurityRelated,NotSecurityRelated"',
            allow_blank=True,
        )
        validation.errorTitle = "Invalid rating"
        validation.error = "Choose SecurityRelated or NotSecurityRelated."
        validation.showErrorMessage = True
        validation.errorStyle = "stop"
        sheet.add_data_validation(validation)
        rater_sheets.append((sheet, validation))

    rater_rows: list[dict[Path, int]] = [dict() for _ in range(raters)]
    for pr_file, assigned in zip(sampled_prs, assignments):
        url = pr_url(pr_file, data_dir)
        for rater in assigned:
            sheet, validation = rater_sheets[rater]
            row = sheet.max_row + 1
            cell = sheet.cell(row=row, column=1, value=url)
            cell.hyperlink = url
            cell.style = "Hyperlink"
            validation.add(sheet.cell(row=row, column=2))
            rater_rows[rater][pr_file] = row

    for row, (pr_file, assigned) in enumerate(zip(sampled_prs, assignments), start=2):
        url = pr_url(pr_file, data_dir)
        link = summary.cell(row=row, column=1, value=url)
        link.hyperlink = url
        link.style = "Hyperlink"
        first_rater, second_rater = assigned
        summary.cell(
            row=row,
            column=2,
            value=f'=IF(\'Rater {first_rater + 1}\'!B{rater_rows[first_rater][pr_file]}="","",'
            f'\'Rater {first_rater + 1}\'!B{rater_rows[first_rater][pr_file]})',
        )
        summary.cell(
            row=row,
            column=3,
            value=f'=IF(\'Rater {second_rater + 1}\'!B{rater_rows[second_rater][pr_file]}="","",'
            f'\'Rater {second_rater + 1}\'!B{rater_rows[second_rater][pr_file]})',
        )
        summary.cell(
            row=row,
            column=4,
            value=f'=IF(OR(B{row}="",C{row}=""),"Pending",IF(B{row}=C{row},"Agreement","Disagreement"))',
        )

    summary.conditional_formatting.add(
        f"E2:E{summary.max_row}",
        FormulaRule(
            formula=['$D2="Agreement"'],
            fill=PatternFill("solid", fgColor="D9D9D9"),
        ),
    )
    for column, width in {"A": 76, "B": 24, "C": 24, "D": 22, "E": 32}.items():
        summary.column_dimensions[column].width = width
    for sheet in workbook.worksheets:
        sheet.auto_filter.ref = sheet.dimensions
    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.calculation.calcMode = "auto"
    workbook.save(OUTPUT_FILE)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a reproducible sample.xlsx workbook with balanced human raters.",
        epilog=(
            "Examples: python generate-sample.py 380 --raters 6; "
            "python generate-sample.py --sample-size 100 --seed 42"
        ),
    )
    parser.add_argument("sample_size_pos", nargs="?", type=positive_int, help="number of PRs to sample")
    parser.add_argument(
        "--sample-size", dest="sample_size_option", type=positive_int, help="number of PRs to sample"
    )
    parser.add_argument("--raters", "--num-raters", type=positive_int, default=6, help="number of human raters (default: 6)")
    parser.add_argument("--seed", default=DEFAULT_SEED, help=f"random seed (default: {DEFAULT_SEED})")
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"PR data root (default: {DATA_ROOT})")
    args = parser.parse_args()

    if args.raters < 2:
        parser.error("--raters must be at least 2")
    if args.sample_size_pos is not None and args.sample_size_option is not None:
        parser.error("specify the sample size either positionally or with --sample-size, not both")
    requested_size = args.sample_size_option or args.sample_size_pos
    if not args.data_dir.is_dir():
        parser.error(f"input data directory does not exist: {args.data_dir}")

    prs = find_pr_files(args.data_dir)
    if not prs:
        parser.error(f"no PR JSON files found under {args.data_dir}")
    sample_size = requested_size if requested_size is not None else default_sample_size(len(prs))
    if sample_size > len(prs):
        parser.error(
            f"sample size {sample_size} exceeds the {len(prs)} available PRs"
        )

    rng = random.Random(args.seed)
    sampled_prs = systematic_sample(prs, sample_size, rng)
    assignments = balanced_pair_schedule(sample_size, args.raters, rng)
    create_workbook(sampled_prs, assignments, args.raters, args.data_dir)
    print(f"Created {OUTPUT_FILE} with {sample_size} PRs and {args.raters} raters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
