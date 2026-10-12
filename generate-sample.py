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
    summary.append(
        [
            "Pull Request",
            "Rater 1",
            "R1 Judgment",
            "Rater 2",
            "R2 Judgment",
            "Agreement Status",
            "Judgment",
        ]
    )

    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(color="FFFFFF", bold=True)
    for cell in summary[1]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
    summary.freeze_panes = "A2"

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

    validation = DataValidation(
        type="list",
        formula1='"SecurityRelated,NotSecurityRelated"',
        allow_blank=True,
    )
    validation.errorTitle = "Invalid rating"
    validation.error = "Choose SecurityRelated or NotSecurityRelated."
    validation.showErrorMessage = True
    validation.errorStyle = "stop"
    summary.add_data_validation(validation)

    for row, (pr_file, assigned) in enumerate(zip(sampled_prs, assignments), start=2):
        url = pr_url(pr_file, data_dir)
        link = summary.cell(row=row, column=1, value=url)
        link.hyperlink = url
        link.style = "Hyperlink"
        first_rater, second_rater = assigned
        summary.cell(row=row, column=2, value=f"Rater {first_rater + 1}")
        summary.cell(
            row=row,
            column=3,
            value=f'=IF(\'Rater {first_rater + 1}\'!B{rater_rows[first_rater][pr_file]}="","",'
            f'\'Rater {first_rater + 1}\'!B{rater_rows[first_rater][pr_file]})',
        )
        summary.cell(row=row, column=4, value=f"Rater {second_rater + 1}")
        summary.cell(
            row=row,
            column=5,
            value=f'=IF(\'Rater {second_rater + 1}\'!B{rater_rows[second_rater][pr_file]}="","",'
            f'\'Rater {second_rater + 1}\'!B{rater_rows[second_rater][pr_file]})',
        )
        summary.cell(
            row=row,
            column=6,
            value=f'=IF(OR(C{row}="",E{row}=""),"Pending",IF(C{row}=E{row},"Agreement","Disagreement"))',
        )
        summary.cell(
            row=row,
            column=7,
            value=f'=IF(C{row}=E{row},C{row},"")',
        )
        validation.add(summary.cell(row=row, column=7))

    summary.conditional_formatting.add(
        f"G2:G{summary.max_row}",
        FormulaRule(
            formula=['$F2="Agreement"'],
            fill=PatternFill(fill_type="solid", fgColor="BFBFBF", bgColor="C6EFCE"),
        ),
    )
    summary.conditional_formatting.add(
        f"G2:G{summary.max_row}",
        FormulaRule(
            formula=['$F2="Disagreement"'],
            fill=PatternFill(fill_type="solid", fgColor="BFBFBF", bgColor="FFC7CE"),
        ),
    )
    summary.conditional_formatting.add(
        f"G2:G{summary.max_row}",
        FormulaRule(
            formula=['$F2="Pending"'],
            fill=PatternFill(fill_type="solid", fgColor="BFBFBF", bgColor="FFEB9C"),
        ),
    )
    for column, width in {
        "A": 76,
        "B": 16,
        "C": 24,
        "D": 16,
        "E": 24,
        "F": 22,
        "G": 32,
    }.items():
        summary.column_dimensions[column].width = width

    kappa = workbook.create_sheet("Fleiss' Kappa")
    kappa["A1"] = "Fleiss' Kappa (completed PRs only)"
    kappa["A2"] = "Overall Fleiss' Kappa"
    kappa["A3"] = "Mean item agreement"
    kappa["A4"] = "SecurityRelated proportion"
    kappa["A5"] = "NotSecurityRelated proportion"
    details_start = 8
    details_end = details_start + len(sampled_prs) - 1
    kappa["B2"] = (
        f'=IF(OR(B3="",B4="",B5="",1-(B4^2+B5^2)=0),"",'
        f'(B3-(B4^2+B5^2))/(1-(B4^2+B5^2)))'
    )
    kappa["B3"] = f'=IF(COUNT(D{details_start}:D{details_end})=0,"",AVERAGE(D{details_start}:D{details_end}))'
    kappa["B4"] = (
        f'=IF(COUNT(D{details_start}:D{details_end})=0,"",'
        f'SUM(B{details_start}:B{details_end})/(2*COUNT(D{details_start}:D{details_end})))'
    )
    kappa["B5"] = (
        f'=IF(COUNT(D{details_start}:D{details_end})=0,"",'
        f'SUM(C{details_start}:C{details_end})/(2*COUNT(D{details_start}:D{details_end})))'
    )
    for column, heading in enumerate(
        [
            "Pull Request",
            "SecurityRelated",
            "NotSecurityRelated",
            "Item Agreement",
            "Agreement Status",
        ],
        start=1,
    ):
        kappa.cell(row=7, column=column, value=heading)
    for cell in kappa[7]:
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center")
    kappa.freeze_panes = "A8"
    for index, pr_file in enumerate(sampled_prs, start=details_start):
        summary_row = index - details_start + 2
        url = pr_url(pr_file, data_dir)
        link = kappa.cell(row=index, column=1, value=url)
        link.hyperlink = url
        link.style = "Hyperlink"
        kappa.cell(
            row=index,
            column=2,
            value=f'=IF(\'Summary\'!F{summary_row}="Pending","",'
            f'COUNTIF(\'Summary\'!C{summary_row},"SecurityRelated")+'
            f'COUNTIF(\'Summary\'!E{summary_row},"SecurityRelated"))',
        )
        kappa.cell(
            row=index,
            column=3,
            value=f'=IF(\'Summary\'!F{summary_row}="Pending","",'
            f'COUNTIF(\'Summary\'!C{summary_row},"NotSecurityRelated")+'
            f'COUNTIF(\'Summary\'!E{summary_row},"NotSecurityRelated"))',
        )
        kappa.cell(
            row=index,
            column=4,
            value=f'=IF(\'Summary\'!F{summary_row}="Pending","",'
            f'((B{index}^2+C{index}^2)-2)/(2*(2-1)))',
        )
        kappa.cell(row=index, column=5, value=f"='Summary'!F{summary_row}")
    kappa.column_dimensions["A"].width = 76
    kappa.column_dimensions["B"].width = 24
    kappa.column_dimensions["C"].width = 26
    kappa.column_dimensions["D"].width = 20
    kappa.column_dimensions["E"].width = 22
    for cell in kappa[1]:
        cell.font = Font(bold=True, size=14)
    kappa.auto_filter.ref = f"A7:E{details_end}"

    for sheet in workbook.worksheets:
        if sheet != kappa:
            sheet.auto_filter.ref = sheet.dimensions
    workbook.calculation.fullCalcOnLoad = True
    workbook.calculation.forceFullCalc = True
    workbook.calculation.calcMode = "auto"
    workbook.save(OUTPUT_FILE)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a reproducible sample.xlsx workbook with balanced human raters.",
        epilog=(
            "Examples: python generate-sample.py --sample-size 380 --raters 6; "
            "python generate-sample.py --sample-size 100 --seed 42"
        ),
    )
    parser.add_argument(
        "--sample-size", type=positive_int, help="number of PRs to sample (default: calculated)"
    )
    parser.add_argument("--raters", "--num-raters", type=positive_int, default=6, help="number of human raters (default: 6)")
    parser.add_argument("--seed", default=DEFAULT_SEED, help=f"random seed (default: {DEFAULT_SEED})")
    parser.add_argument("--data-dir", type=Path, default=DATA_ROOT, help=f"PR data root (default: {DATA_ROOT})")
    args = parser.parse_args()

    if args.raters < 2:
        parser.error("--raters must be at least 2")
    if not args.data_dir.is_dir():
        parser.error(f"input data directory does not exist: {args.data_dir}")

    prs = find_pr_files(args.data_dir)
    if not prs:
        parser.error(f"no PR JSON files found under {args.data_dir}")
    sample_size = args.sample_size or default_sample_size(len(prs))
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
