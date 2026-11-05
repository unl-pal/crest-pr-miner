#!/usr/bin/env python3
"""
Make the language-to-outcome flow (Sankey) figure for the paper.

Reads the mined PRs under data/ and draws a TikZ flow from each repo's language
to the PR's outcome when collected: merged, closed without merging, or open.
Flow width is proportional to the number of PRs. Languages other than C, C++,
Java, and Python, or none reported (mostly forks), are grouped as "Other".

Skips Dependabot PRs and PRs whose cwes.json lists no valid CWE.

Needs in the paper's preamble: \\usepackage{tikz} (or pgfplots) and graphicx.

Usage:
    python make-repo-figure.py [--data-dir data] [--out figures/fig-language-outcome.tex] [--svg [PATH]]
"""

import argparse
import json
from collections import Counter
from pathlib import Path

DEFAULT_OUT = Path(__file__).resolve().parent / "figures" / "fig-language-outcome.tex"
README = Path(__file__).resolve().parent / "README.md"
README_START, README_END = "<!-- language-figure:start -->", "<!-- language-figure:end -->"
GROUPS = ["C", "C++", "Java", "Python", "Other"]
# Validated with the dataviz palette checker (lightness, chroma, colorblind
# separation, contrast all pass); gray is the neutral "Other" bucket.
COLORS = {"C": "2A6EBB", "C++": "E64B35", "Java": "00A087", "Python": "925E9F", "Other": "ADB6B6"}
OUTCOMES = ["Merged", "Closed, not merged", "Open"]
# Neutral grays, dark to light, so the language colors stay the focus.
OUTCOME_COLORS = {"Merged": "5B6770", "Closed, not merged": "98A2AB", "Open": "C9CFD4"}
SKIP_NAMES = {"cves.json", "cwes.json", "comments.json", "timeline.json"}
DEPENDABOT = {"dependabot[bot]", "dependabot-preview[bot]"}
# Figure geometry, in TikZ units (cm).
HEIGHT, GAP_LEFT, GAP_RIGHT, MIN_BAR = 7.0, 0.3, 0.45, 0.06
X0, X1, BAR = 0.28, 8.2, 0.28
XM = (X0 + X1) / 2


def has_no_valid_cwe(pr_dir: Path) -> bool:
    """True if find-cwes-in-prs.py ran for this PR and found no valid CWE."""
    try:
        return not json.loads((pr_dir / "cwes.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False


def outcome(pr: dict) -> str:
    """The PR's state when it was downloaded."""
    if pr.get("merged") or pr.get("merged_at"):
        return "Merged"
    return "Open" if pr.get("state") == "open" else "Closed, not merged"


def count_by_language(data_dir: Path) -> tuple[Counter, Counter, Counter]:
    """Return (repositories per group, PRs per group, PRs per (group, outcome))."""
    per_repo: Counter[str] = Counter()
    language: dict[str, str] = {}
    outcomes_per_repo: dict[str, Counter] = {}
    for path in data_dir.glob("*/*/*/*.json"):
        if path.name in SKIP_NAMES or not path.stem.isdigit():
            continue
        try:
            pr = json.loads(path.read_text(encoding="utf-8"))
            repo = pr["base"]["repo"]
            author = pr["user"]["login"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if author in DEPENDABOT or has_no_valid_cwe(path.parent):
            continue
        per_repo[repo["full_name"]] += 1
        language[repo["full_name"]] = repo.get("language")
        outcomes_per_repo.setdefault(repo["full_name"], Counter())[outcome(pr)] += 1

    repos: Counter[str] = Counter()
    prs: Counter[str] = Counter()
    flows: Counter[tuple[str, str]] = Counter()
    for name, n in per_repo.items():
        group = language[name] if language[name] in GROUPS[:-1] else "Other"
        repos[group] += 1
        prs[group] += n
        for result, k in outcomes_per_repo[name].items():
            flows[group, result] += k
    return repos, prs, flows


def tex_number(n: int) -> str:
    return f"{n:,}".replace(",", "{,}")


def stack(heights: list[float], top: float, gap: float) -> list[tuple[float, float]]:
    """Stack bars downward from top; return (upper, lower) y of each."""
    spans = []
    for h in heights:
        spans.append((top, top - h))
        top -= h + gap
    return spans


def spread_labels(centers: list[float], min_sep: float) -> list[float]:
    """Move label centers down where needed so two-line labels never overlap."""
    out = []
    for c in centers:
        out.append(min(c, out[-1] - min_sep) if out else c)
    return out


def flow_layout(prs: Counter, flows: Counter) -> tuple[dict, dict, dict]:
    """Return (thickness of each flow, y span of each language bar, y span of each outcome bar)."""
    total = sum(prs.values()) or 1
    usable = HEIGHT - GAP_LEFT * (len(GROUPS) - 1)

    # Flow thickness; a language too small to see gets a minimum bar, split in proportion.
    thick = {}
    for g in GROUPS:
        scale = usable / total
        if prs[g] and prs[g] * scale < MIN_BAR:
            scale = MIN_BAR / prs[g]
        for o in OUTCOMES:
            thick[g, o] = flows[g, o] * scale
    left_h = [sum(thick[g, o] for o in OUTCOMES) for g in GROUPS]
    right_h = [sum(thick[g, o] for g in GROUPS) for o in OUTCOMES]
    left = dict(zip(GROUPS, stack(left_h, HEIGHT, GAP_LEFT)))
    right_top = HEIGHT - (sum(left_h) + GAP_LEFT * 4 - sum(right_h) - GAP_RIGHT * 2) / 2
    right = dict(zip(OUTCOMES, stack(right_h, right_top, GAP_RIGHT)))
    return thick, left, right


def make_svg(repos: Counter, prs: Counter, flows: Counter) -> str:
    """The same diagram as make_flow_figure, as an SVG image (for GitHub and the like)."""
    total = sum(prs.values()) or 1
    thick, left, right = flow_layout(prs, flows)
    left_labels = spread_labels([(left[g][0] + left[g][1]) / 2 for g in GROUPS], 0.72)
    right_labels = spread_labels([(right[o][0] + right[o][1]) / 2 for o in OUTCOMES], 0.62)

    unit, margin, pad = 72, 200, 16
    bottom = min(*(s[1] for s in left.values()), *(s[1] for s in right.values()), *left_labels, *right_labels) - 0.4
    width = 2 * margin + (X1 + BAR) * unit
    px = lambda x: f"{margin + x * unit:.1f}"
    py = lambda y: f"{pad + (HEIGHT - y) * unit:.1f}"
    full_height = pad + (HEIGHT - bottom) * unit

    gradients, shapes = [], []
    left_cursor = {g: left[g][0] for g in GROUPS}
    right_cursor = {o: right[o][0] for o in OUTCOMES}
    for i, g in enumerate(GROUPS):
        for j, o in enumerate(OUTCOMES):
            h = thick[g, o]
            if h <= 0:
                continue
            a0, b0 = left_cursor[g], right_cursor[o]
            a1, b1 = a0 - h, b0 - h
            left_cursor[g], right_cursor[o] = a1, b1
            gradients.append(
                f'<linearGradient id="flow{i}{j}" gradientUnits="userSpaceOnUse" x1="{px(X0)}" y1="0" x2="{px(X1)}" y2="0">'
                f'<stop offset="0" stop-color="#{COLORS[g]}"/><stop offset="1" stop-color="#{OUTCOME_COLORS[o]}"/></linearGradient>'
            )
            shapes.append(
                f'<path fill="url(#flow{i}{j})" opacity="0.55" d="M{px(X0)} {py(a0)} C{px(XM)} {py(a0)} {px(XM)} {py(b0)} {px(X1)} {py(b0)} '
                f'L{px(X1)} {py(b1)} C{px(XM)} {py(b1)} {px(XM)} {py(a1)} {px(X0)} {py(a1)} Z">'
                f"<title>{g} to {o}: {flows[g, o]:,} PRs</title></path>"
            )
            if h >= 0.32:  # label only flows thick enough to hold a number
                shapes.append(f'<text class="num" x="{px(X0 + 0.12)}" y="{py((a0 + a1) / 2)}" dy="0.35em">{flows[g, o]:,}</text>')

    for g, c in zip(GROUPS, left_labels):
        up, low = left[g]
        shapes += [
            f'<rect x="{px(0)}" y="{py(up)}" width="{BAR * unit:.1f}" height="{(up - low) * unit:.1f}" rx="1.5" fill="#{COLORS[g]}"/>',
            f'<text class="name" text-anchor="end" x="{px(-0.1)}" y="{py(c)}" dy="-4">{g}</text>',
            f'<text class="sub" text-anchor="end" x="{px(-0.1)}" y="{py(c)}" dy="12">{repos[g]:,} repos · {prs[g]:,} PRs</text>',
        ]
    for o, c in zip(OUTCOMES, right_labels):
        up, low = right[o]
        n = sum(flows[g, o] for g in GROUPS)
        name = "Open when collected" if o == "Open" else o
        shapes += [
            f'<rect x="{px(X1)}" y="{py(up)}" width="{BAR * unit:.1f}" height="{(up - low) * unit:.1f}" rx="1.5" fill="#{OUTCOME_COLORS[o]}"/>',
            f'<text class="name" x="{px(X1 + BAR + 0.1)}" y="{py(c)}" dy="-4">{name}</text>',
            f'<text class="sub" x="{px(X1 + BAR + 0.1)}" y="{py(c)}" dy="12">{n:,} PRs · {round(100 * n / total)}%</text>',
        ]

    # The white background keeps the dark text readable on GitHub's dark theme.
    return "\n".join([
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width:.0f} {full_height:.0f}" role="img" '
        f'aria-label="Flow of {sum(prs.values()):,} PRs from repository language to PR outcome">',
        "<style>text{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif}"
        ".name{font-size:15px;fill:#262626}.sub{font-size:13px;fill:#595959}.num{font-size:13px;fill:#262626}</style>",
        f"<defs>{''.join(gradients)}</defs>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        *shapes,
        "</svg>",
        "",
    ])


def make_flow_figure(repos: Counter, prs: Counter, flows: Counter) -> str:
    """Sankey diagram from language (left) to outcome (right), in the style of
    the paper's other flow figures: shaded flows that fade from the language
    color into the outcome color, bars with a name and a count beside them."""
    total = sum(prs.values()) or 1
    x0, x1, bar, xm = X0, X1, BAR, XM
    thick, left, right = flow_layout(prs, flows)

    lines = [
        "% Generated by make-repo-figure.py -- do not edit by hand, rerun the script.",
        "% Needs graphicx (for \\resizebox) and TikZ, which pgfplots loads.",
    ]
    lines += [f"\\definecolor{{lang{i}}}{{HTML}}{{{COLORS[g]}}}" for i, g in enumerate(GROUPS)]
    lines += [f"\\definecolor{{out{j}}}{{HTML}}{{{OUTCOME_COLORS[o]}}}" for j, o in enumerate(OUTCOMES)]
    lines += [
        "",
        "\\begin{figure}[!htbp]",
        "\\centering",
        "\\resizebox{\\columnwidth}{!}{%",
        "\\begin{tikzpicture}[",
        "    flow/.style={draw=none, opacity=0.55},",
        "    num/.style={font=\\footnotesize, text=black!75},",
        "    name/.style={font=\\small, text=black!85},",
        "    sub/.style={font=\\footnotesize, text=black!60},",
        "]",
        "% ---- flows (language colour fades into outcome colour)",
    ]

    left_cursor = {g: left[g][0] for g in GROUPS}
    right_cursor = {o: right[o][0] for o in OUTCOMES}
    for i, g in enumerate(GROUPS):
        lines.append(f"% {g}")
        for j, o in enumerate(OUTCOMES):
            h = thick[g, o]
            if h <= 0:
                continue
            a0, b0 = left_cursor[g], right_cursor[o]
            a1, b1 = a0 - h, b0 - h
            left_cursor[g], right_cursor[o] = a1, b1
            lines.append(
                f"\\shade[flow, left color=lang{i}, right color=out{j}] "
                f"({x0},{a0:.3f}) .. controls ({xm:.2f},{a0:.3f}) and ({xm:.2f},{b0:.3f}) .. ({x1},{b0:.3f}) -- "
                f"({x1},{b1:.3f}) .. controls ({xm:.2f},{b1:.3f}) and ({xm:.2f},{a1:.3f}) .. ({x0},{a1:.3f}) -- cycle;"
                f"  % {flows[g, o]} PRs"
            )
            if h >= 0.32:  # label only flows thick enough to hold a number
                lines.append(f"\\node[num, anchor=west] at ({x0 + 0.12:.2f},{(a0 + a1) / 2:.3f}) {{{tex_number(flows[g, o])}}};")

    lines.append("% ---- language bars and labels")
    centers = spread_labels([(left[g][0] + left[g][1]) / 2 for g in GROUPS], 0.72)
    for i, (g, c) in enumerate(zip(GROUPS, centers)):
        up, low = left[g]
        lines += [
            f"\\fill[lang{i}, rounded corners=1pt] (0,{low:.3f}) rectangle ({bar},{up:.3f});",
            f"\\node[name, anchor=south east, inner sep=1pt] at (-0.1,{c:.3f}) {{{g.replace('+', '{+}')}}};",
            f"\\node[sub, anchor=north east, inner sep=1pt] at (-0.1,{c:.3f}) "
            f"{{{tex_number(repos[g])} repos $\\cdot$ {tex_number(prs[g])} PRs}};",
        ]

    lines.append("% ---- outcome bars and labels")
    centers = spread_labels([(right[o][0] + right[o][1]) / 2 for o in OUTCOMES], 0.62)
    for j, (o, c) in enumerate(zip(OUTCOMES, centers)):
        up, low = right[o]
        n = sum(flows[g, o] for g in GROUPS)
        name = "Open when collected" if o == "Open" else o
        lines += [
            f"\\fill[out{j}, rounded corners=1pt] ({x1},{low:.3f}) rectangle ({x1 + bar},{up:.3f});",
            f"\\node[name, anchor=south west, inner sep=1pt] at ({x1 + bar + 0.1:.2f},{c:.3f}) {{{name}}};",
            f"\\node[sub, anchor=north west, inner sep=1pt] at ({x1 + bar + 0.1:.2f},{c:.3f}) "
            f"{{{tex_number(n)} PRs $\\cdot$ {round(100 * n / total)}\\%}};",
        ]

    lines += [
        "\\end{tikzpicture}%",
        "}",
        "\\caption{Flow of the dataset's PRs from the repository's language to the PR's outcome when we "
        "collected it. Flow width is proportional to the number of PRs. Other: repositories for which GitHub "
        "reports a different language or none, mostly forks.}",
        "\\label{fig:language_outcome}",
        "\\end{figure}",
        "",
    ]
    return "\n".join(lines)


def update_readme(readme: Path, svg: Path, note: str) -> None:
    """Show the SVG in the README between the figure markers, adding them at the end if absent."""
    try:
        link = svg.resolve().relative_to(readme.parent).as_posix()
        text = readme.read_text(encoding="utf-8")
    except ValueError:
        print(f"Did not update {readme.name}: the SVG is outside the repo, so the image link would not work")
        return
    except OSError as e:
        print(f"Did not update {readme.name}: {e}")
        return

    block = f"{README_START}\n![Flow of PRs from repository language to PR outcome]({link})\n\n*{note}*\n{README_END}"
    before, start, rest = text.partition(README_START)
    if start and README_END not in rest:
        print(f"Did not update {readme.name}: it has {README_START} but no {README_END}")
        return
    if start:
        text = before + block + rest.partition(README_END)[2]
    else:
        text = text.rstrip("\n") + "\n\n" + block + "\n"
    readme.write_text(text, encoding="utf-8")
    print(f"Updated {readme}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--data-dir", type=Path, default=Path("data"), help="Root directory of mined PR data (default: data).")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output .tex file (default: figures/fig-language-outcome.tex in the repo; the folder is created if missing).")
    parser.add_argument("--svg", type=Path, nargs="?", const=DEFAULT_OUT.with_suffix(".svg"), metavar="PATH", help="Also write an SVG image and show it in README.md (default path: figures/fig-language-outcome.svg in the repo).")
    args = parser.parse_args()

    repos, prs, flows = count_by_language(args.data_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(make_flow_figure(repos, prs, flows), encoding="utf-8")

    print(f"Wrote {args.out}")
    if args.svg:
        args.svg.parent.mkdir(parents=True, exist_ok=True)
        args.svg.write_text(make_svg(repos, prs, flows), encoding="utf-8")
        print(f"Wrote {args.svg}")
        update_readme(README, args.svg, f"Generated from `{args.data_dir.name}`: {sum(prs.values()):,} PRs.")
    for group in GROUPS:
        print(f"  {group:7} {repos[group]:7,} repositories {prs[group]:9,} PRs")
    print(f"  {'Total':7} {sum(repos.values()):7,} repositories {sum(prs.values()):9,} PRs")
    total = sum(prs.values()) or 1
    for o in OUTCOMES:
        n = sum(flows[g, o] for g in GROUPS)
        print(f"  {o:19} {n:9,} PRs ({n / total:.0%})")

    print(f"""
Of the \\minedPRs PRs,
\\textbf{{{prs["C"]:,}}} come from C repositories,
\\textbf{{{prs["C++"]:,}}} from C++,
\\textbf{{{prs["Java"]:,}}} from Java, and
\\textbf{{{prs["Python"]:,}}} from Python;
the remaining \\textbf{{{prs["Other"]:,}}} come from repositories that GitHub now lists under another language or none.
\\textbf{{{sum(flows[g, "Merged"] for g in GROUPS):,}}} (\\textbf{{{sum(flows[g, "Merged"] for g in GROUPS) / total * 100:.0f}\\%}}) were merged,
\\textbf{{{sum(flows[g, "Closed, not merged"] for g in GROUPS):,}}} (\\textbf{{{sum(flows[g, "Closed, not merged"] for g in GROUPS) / total * 100:.0f}\\%}}) were closed without merging, and
\\textbf{{{sum(flows[g, "Open"] for g in GROUPS):,}}} (\\textbf{{{sum(flows[g, "Open"] for g in GROUPS) / total * 100:.0f}\\%}}) were still open when we collected them (Figure~\\ref{{fig:language_outcome}}).
""")


if __name__ == "__main__":
    main()
