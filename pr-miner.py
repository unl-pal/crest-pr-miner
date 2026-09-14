#!/usr/bin/env python3
"""
GitHub Pull Request Miner for CVEfixes

Reads vulnerability fixing commits from CVEfixes (SQLite database or SQL dump)
and resolves associated GitHub Pull Request links from the commit hashes.

Features:
  - Supports CVEfixes SQLite database (.db / .sqlite) and SQL dumps (.sql)
  - Automatic round-robin GitHub token rotation and rate-limit handling
  - Multiple PR detection strategies:
      1. GitHub Commits API (/repos/{owner}/{repo}/commits/{sha}/pulls)
      2. Commit message parsing (e.g. "Merge pull request #123", "(#123)")
      3. GitHub Search API fallback
  - Processes first 100 commits by default (customizable via --limit)
  - Outputs structured JSON results and a clean summary report
"""

import argparse
from datetime import datetime, timedelta, timezone
import json
import logging
import os
from pathlib import Path
import re
import sys
import time
from typing import Optional, List, Dict, Any

from dotenv import load_dotenv
from github import Auth, Github, RateLimitExceededException, GithubException

from cvefixes import (
    CVEfixesDatabase,
    SampleCVEfixesProvider,
    FixingCommit,
    parse_github_repo,
)

load_dotenv()

log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token Pool & Rate Limiting
# ---------------------------------------------------------------------------
class TokenPool:
    """Round-robin token pool supporting multiple GitHub tokens and rate-limit categories."""

    def __init__(self, tokens: Optional[List[str]] = None):
        tokens = tokens or []
        self._unauthenticated = len(tokens) == 0

        if self._unauthenticated:
            logger.warning(
                "No GitHub token provided. Running unauthenticated with strict rate limits (60 req/hr). "
                "Set GH_TOKEN_LIST or GITHUB_TOKEN in .env or pass --token to increase limits."
            )
            self._pool = [
                {
                    "token": "unauthenticated",
                    "client": Github(
                        per_page=100,
                        user_agent="CREST-PR-Miner/2.0.0 (https://github.com/unl-pal/crest-pr-miner)",
                    ),
                    "reset_at": {},
                }
            ]
        else:
            self._pool = [
                {
                    "token": t,
                    "client": Github(
                        auth=Auth.Token(t),
                        per_page=100,
                        user_agent="CREST-PR-Miner/2.0.0 (https://github.com/unl-pal/crest-pr-miner)",
                    ),
                    "reset_at": {},
                }
                for t in tokens
            ]
        self._current = 0

    def get(self, category: str = "core") -> Github:
        """Return the next available GitHub client, sleeping if all are exhausted."""
        now = datetime.now(tz=timezone.utc)
        n = len(self._pool)

        for i in range(n):
            entry = self._pool[(self._current + i) % n]
            ra = entry["reset_at"].get(category)
            if ra is None or ra <= now:
                self._current = (self._current + i + 1) % n
                return entry["client"]

        # All tokens rate-limited; wait for earliest reset
        best = min(self._pool, key=lambda e: e["reset_at"].get(category, now))
        reset_time = best["reset_at"].get(category, now)
        wait_seconds = max(5.0, (reset_time - now).total_seconds() + 2)
        logger.warning(
            "All tokens rate-limited for '%s'; sleeping %.0f seconds until %s",
            category,
            wait_seconds,
            reset_time.isoformat(),
        )
        time.sleep(wait_seconds)
        self._current = (self._pool.index(best) + 1) % n
        return best["client"]

    def mark_rate_limited(self, client: Github, category: str = "core"):
        """Mark a client as rate-limited until reset."""
        now = datetime.now(tz=timezone.utc)
        for entry in self._pool:
            if entry["client"] is client:
                try:
                    rl = client.get_rate_limit()
                    resource = getattr(rl, category, None)
                    reset_ts = resource.reset.replace(tzinfo=timezone.utc) if resource else None
                except Exception:
                    reset_ts = None

                if reset_ts is None or reset_ts <= now:
                    reset_ts = now + timedelta(minutes=15)

                entry["reset_at"][category] = reset_ts
                logger.warning(
                    "Token %s... rate-limited for '%s'; resets at %s",
                    entry["token"][:8] if entry["token"] != "unauthenticated" else "unauth",
                    category,
                    reset_ts.isoformat(),
                )
                break


def load_github_tokens(cli_token: Optional[str] = None) -> List[str]:
    """Collect tokens from CLI arguments, GH_TOKEN_LIST, or GITHUB_TOKEN."""
    tokens: List[str] = []
    if cli_token:
        tokens.extend([t.strip() for t in cli_token.split(",") if t.strip()])

    env_list = os.environ.get("GH_TOKEN_LIST", "")
    if env_list:
        tokens.extend([t.strip() for t in env_list.split(",") if t.strip()])

    single_token = os.environ.get("GITHUB_TOKEN", "")
    if single_token and single_token not in tokens:
        tokens.append(single_token.strip())

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# ---------------------------------------------------------------------------
# PR Extraction Strategies & Confidence Scoring
# ---------------------------------------------------------------------------
PR_NUMBER_PATTERNS = [
    re.compile(r"\(#(\d+)\)"),                         # Standard GitHub squash: "Title (#123)"
    re.compile(r"[Mm]erge pull request #(\d+)"),        # Standard merge: "Merge pull request #123"
    re.compile(r"[Pp]ull request #(\d+)"),             # "Pull request #123"
    re.compile(r"[Gg]itHub PR:?\s*#(\d+)"),             # "GitHub PR #123"
    re.compile(r"https?://github\.com/[^/\s]+/[^/\s]+/pull/(\d+)"), # Full PR link in commit message
]

SECURITY_KEYWORDS = [
    "vulnerabilit", "security", "exploit", "cve", "cwe", "ghsa",
    "sanitize", "sanitiz", "overflow", "traversal", "unauthorized",
    "infinite loop", "bypass", "injection", "privilege escalation",
    "rce", "csrf", "xss", "ssrf", "denial of service", "dos",
    "out-of-bounds", "memory corruption", "hijack", "race condition",
    "arbitrary", "null pointer", "advisory", "file://", "permission",
]

REFACTOR_KEYWORDS = [
    "modernize", "refactor", "cleanup", "clean up", "pep ",
    "style", "bump version", "release prep", "update docs", "format",
]


def extract_pr_numbers_from_message(message: Optional[str]) -> List[int]:
    """Scan commit message for pull request numbers or links."""
    if not message:
        return []
    numbers = []
    for pattern in PR_NUMBER_PATTERNS:
        for match in pattern.finditer(message):
            try:
                numbers.append(int(match.group(1)))
            except (ValueError, IndexError):
                pass
    return list(dict.fromkeys(numbers))


def extract_commit_code_changes(gh_commit) -> List[Dict[str, Any]]:
    """Extract modified files with diff patch, vulnerable code, and fixed code."""
    changes = []
    try:
        for f in gh_commit.files:
            patch = f.patch or ""
            vuln_lines = [line[1:] for line in patch.splitlines() if line.startswith("-") and not line.startswith("---")]
            fixed_lines = [line[1:] for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")]
            changes.append({
                "filename": f.filename,
                "status": f.status,
                "additions": f.additions,
                "deletions": f.deletions,
                "patch": patch,
                "vulnerable_code": "\n".join(vuln_lines),
                "fixed_code": "\n".join(fixed_lines),
            })
    except Exception as e:
        logger.debug("Could not extract file changes from commit: %s", e)
    return changes


def calculate_pr_confidence(
    cve_id: Optional[str],
    pr_data: Dict[str, Any],
    commit_msg: Optional[str] = None,
    detection_method: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluates confidence that a PR is the actual security remediation for a CVE.
    Returns:
      - confidence_score: int (0 to 100)
      - confidence_tier: 'HIGH', 'MEDIUM', 'LOW', 'SUSPICIOUS'
      - confidence_factors: list of explanations
    """
    score = 50  # baseline
    factors = []

    # 1. Temporal Analysis (CVE Year vs PR Merged/Created Year)
    cve_year = None
    if cve_id and cve_id.startswith("CVE-"):
        parts = cve_id.split("-")
        if len(parts) >= 2 and parts[1].isdigit():
            cve_year = int(parts[1])

    pr_year = None
    merged_at = pr_data.get("merged_at") or pr_data.get("created_at")
    if merged_at and len(merged_at) >= 4 and merged_at[:4].isdigit():
        pr_year = int(merged_at[:4])

    if cve_year and pr_year:
        diff = cve_year - pr_year
        if diff == 0:
            score += 25
            factors.append(f"PR merged in same year as CVE ({pr_year}) (+25)")
        elif diff == 1:
            score += 20
            factors.append(f"PR merged 1 year prior to CVE ({pr_year} vs {cve_year}) (+20)")
        elif diff == -1:
            score += 15
            factors.append("PR merged 1 year after CVE publication (+15)")
        elif diff >= 3:
            score -= 50
            factors.append(f"PR merged {diff} years before CVE ({pr_year} vs {cve_year}) - likely bug-introducing or legacy commit (-50)")
        elif diff == 2:
            score -= 15
            factors.append(f"PR merged 2 years before CVE ({pr_year} vs {cve_year}) (-15)")

    # 2. Text Analysis (PR Title, Commit Message)
    title = (pr_data.get("title") or "").lower()
    msg = (commit_msg or "").lower()
    text = f"{title} {msg}"

    # Explicit CVE or Advisory match
    if cve_id and cve_id.lower() in text:
        score += 35
        factors.append(f"Explicitly mentions {cve_id} (+35)")
    elif "ghsa-" in text:
        score += 25
        factors.append("Mentions GitHub Security Advisory (GHSA) (+25)")

    # Security terminology
    matched_sec_kw = [kw for kw in SECURITY_KEYWORDS if kw in text]
    if matched_sec_kw:
        bonus = min(25, 10 + len(matched_sec_kw) * 5)
        score += bonus
        factors.append(f"Security terminology found: {', '.join(matched_sec_kw[:3])} (+{bonus})")

    # Refactor / non-security terminology (when lacking security terminology)
    if not matched_sec_kw:
        matched_ref_kw = [kw for kw in REFACTOR_KEYWORDS if kw in title]
        if matched_ref_kw:
            score -= 25
            factors.append(f"Refactor/maintenance title without security terms: '{matched_ref_kw[0]}' (-25)")

    # 3. Detection Method
    if detection_method in ("commits_api", "commit_message"):
        score += 10
        factors.append("Authoritatively linked via commit git DAG / merge message (+10)")
    elif detection_method == "search_api":
        score -= 20
        factors.append("Matched via loose search API (susceptible to quoted hashes) (-20)")

    score = max(0, min(100, score))

    if score >= 75:
        tier = "HIGH"
    elif score >= 50:
        tier = "MEDIUM"
    elif score >= 30:
        tier = "LOW"
    else:
        tier = "SUSPICIOUS"

    return {
        "confidence_score": score,
        "confidence_tier": tier,
        "confidence_factors": factors,
    }


def find_pull_requests_for_commit(
    pool: TokenPool,
    owner: str,
    repo: str,
    commit_sha: str,
    cve_id: Optional[str] = None,
    commit_message: Optional[str] = None,
    allow_search_api: bool = False,
    max_retries: int = 3,
) -> Dict[str, Any]:
    """
    Attempt to find GitHub PR link(s) for a given commit SHA.

    Returns a dict with:
      - status: 'found', 'not_found', 'repo_not_found', 'commit_not_found', 'error'
      - method: 'commits_api', 'commit_message', 'search_api', or None
      - pull_requests: list of PR summaries with confidence scores
      - code_changes: list of file changes with vulnerable vs fixed code
      - error_message: error description if any
    """
    result: Dict[str, Any] = {
        "status": "not_found",
        "method": None,
        "pull_requests": [],
        "code_changes": [],
        "error_message": None,
    }

    retries = 0
    while retries <= max_retries:
        client = pool.get(category="core")
        try:
            gh_repo = client.get_repo(f"{owner}/{repo}")
            gh_commit = gh_repo.get_commit(commit_sha)

            # Strategy 1: GitHub Commits API (/repos/{owner}/{repo}/commits/{sha}/pulls)
            try:
                pulls = list(gh_commit.get_pulls())
                if pulls:
                    result["status"] = "found"
                    result["method"] = "commits_api"
                    prs = []
                    for pr in pulls:
                        pr_dict = {
                            "number": pr.number,
                            "url": pr.html_url,
                            "title": pr.title,
                            "state": pr.state,
                            "merged": pr.merged,
                            "merged_at": pr.merged_at.isoformat() if pr.merged_at else None,
                        }
                        conf = calculate_pr_confidence(
                            cve_id=cve_id,
                            pr_data=pr_dict,
                            commit_msg=gh_commit.commit.message or commit_message,
                            detection_method="commits_api",
                        )
                        pr_dict.update(conf)
                        prs.append(pr_dict)

                    result["pull_requests"] = prs
                    result["code_changes"] = extract_commit_code_changes(gh_commit)
                    return result
            except Exception as e:
                logger.debug("get_pulls() failed for %s/%s@%s: %s", owner, repo, commit_sha, e)

            # Strategy 2: Extract PR numbers from commit message
            msg = gh_commit.commit.message or commit_message
            pr_numbers = extract_pr_numbers_from_message(msg)
            if pr_numbers:
                found_prs = []
                for pr_num in pr_numbers:
                    try:
                        pr = gh_repo.get_pull(pr_num)
                        found_prs.append(
                            {
                                "number": pr.number,
                                "url": pr.html_url,
                                "title": pr.title,
                                "state": pr.state,
                                "merged": pr.merged,
                                "merged_at": pr.merged_at.isoformat() if pr.merged_at else None,
                            }
                        )
                    except GithubException as ge:
                        if ge.status == 404:
                            continue
                        raise

                if found_prs:
                    prs = []
                    for pr_data in found_prs:
                        conf = calculate_pr_confidence(
                            cve_id=cve_id,
                            pr_data=pr_data,
                            commit_msg=gh_commit.commit.message or commit_message,
                            detection_method="commit_message",
                        )
                        pr_data.update(conf)
                        prs.append(pr_data)

                    result["status"] = "found"
                    result["method"] = "commit_message"
                    result["pull_requests"] = prs
                    result["code_changes"] = extract_commit_code_changes(gh_commit)
                    return result

            # Strategy 3: GitHub Search API fallback
            if allow_search_api:
                search_client = pool.get(category="search")
                try:
                    search_query = f"repo:{owner}/{repo} is:pr {commit_sha}"
                    search_results = list(search_client.search_issues(search_query)[:3])
                    if search_results:
                        result["status"] = "found"
                        result["method"] = "search_api"
                        prs = []
                        for issue in search_results:
                            pr_data = {
                                "number": issue.number,
                                "url": issue.html_url,
                                "title": issue.title,
                                "state": issue.state,
                                "merged": getattr(issue, "pull_request", None) is not None,
                            }
                            conf = calculate_pr_confidence(
                                cve_id=cve_id,
                                pr_data=pr_data,
                                commit_msg=gh_commit.commit.message or commit_message,
                                detection_method="search_api",
                            )
                            pr_data.update(conf)
                            prs.append(pr_data)

                        result["pull_requests"] = prs
                        result["code_changes"] = extract_commit_code_changes(gh_commit)
                        return result
                except RateLimitExceededException:
                    pool.mark_rate_limited(search_client, category="search")
                except Exception as se:
                    logger.debug("Search API error for %s/%s@%s: %s", owner, repo, commit_sha, se)

            # No PR found through any strategy
            result["status"] = "not_found"
            return result

        except RateLimitExceededException:
            pool.mark_rate_limited(client, category="core")
            retries += 1
            continue

        except GithubException as ge:
            if ge.status in (403, 429) and "rate limit" in str(ge).lower():
                pool.mark_rate_limited(client, category="core")
                retries += 1
                continue
            elif ge.status == 404 or (ge.status == 422 and "commit" in str(ge).lower()):
                # Differentiate between repo 404 and commit 404/422
                error_body = str(ge.data) if hasattr(ge, "data") else str(ge)
                if "commit" in error_body.lower():
                    result["status"] = "commit_not_found"
                else:
                    result["status"] = "repo_not_found"
                result["error_message"] = error_body
                return result
            elif ge.status == 451:
                result["status"] = "unavailable_dmca"
                result["error_message"] = "Repository or commit unavailable for legal reasons (DMCA)"
                return result
            else:
                result["status"] = "error"
                result["error_message"] = f"GitHub API error {ge.status}: {ge.data if hasattr(ge, 'data') else str(ge)}"
                return result

        except Exception as e:
            result["status"] = "error"
            result["error_message"] = str(e)
            return result

    result["status"] = "error"
    result["error_message"] = "Max retries exceeded due to rate limits"
    return result


# ---------------------------------------------------------------------------
# Main Mining Process
# ---------------------------------------------------------------------------
def mine_prs_from_cvefixes(
    provider: CVEfixesDatabase | SampleCVEfixesProvider,
    token_pool: TokenPool,
    limit: int = 100,
    output_path: Path = Path("cvefixes_pr_links.json"),
    found_output_path: Path = Path("found_pr_links.json"),
    allow_search_api: bool = False,
    order: str = "default",
    min_year: Optional[int] = None,
):
    """Fetch fixing commits from CVEfixes and resolve GitHub PR links for the first `limit` items."""
    logger.info("Extracting fixing commits from CVEfixes (limit=%d, order=%s, min_year=%s)...", limit, order, min_year)
    if isinstance(provider, CVEfixesDatabase):
        commits: List[FixingCommit] = provider.get_fixing_commits(limit=limit, order=order, min_year=min_year)
    else:
        commits: List[FixingCommit] = provider.get_fixing_commits(limit=limit)

    if not commits:
        logger.warning("No commits returned from CVEfixes data source.")
        return

    logger.info("Processing %d commits to find GitHub pull requests...", len(commits))
    results: List[Dict[str, Any]] = []

    stats = {
        "total": len(commits),
        "found": 0,
        "not_found": 0,
        "non_github": 0,
        "repo_not_found": 0,
        "commit_not_found": 0,
        "error": 0,
    }

    start_time = time.time()

    for idx, commit in enumerate(commits, start=1):
        cve_tag = f"[{commit.cve_id}] " if commit.cve_id else ""
        short_hash = commit.commit_hash[:8] if commit.commit_hash else "unknown"

        record: Dict[str, Any] = {
            "index": idx,
            "cve_id": commit.cve_id,
            "commit_hash": commit.commit_hash,
            "repo_url": commit.repo_url,
            "owner": commit.owner,
            "repo": commit.repo_name,
            "pr_status": "pending",
            "detection_method": None,
            "pull_requests": [],
            "error": None,
        }

        # Check if repository is GitHub
        if not commit.owner or not commit.repo_name:
            # Check if repo_url can be parsed
            parsed = parse_github_repo(commit.repo_url)
            if parsed:
                commit.owner, commit.repo_name = parsed
            else:
                record["pr_status"] = "non_github_repository"
                stats["non_github"] += 1
                logger.info(
                    "[%d/%d] %s%s @ %s -> Skipped (non-GitHub repo: %s)",
                    idx,
                    len(commits),
                    cve_tag,
                    commit.repo_url,
                    short_hash,
                    commit.repo_url,
                )
                results.append(record)
                continue

        # Look up PR for GitHub commit
        res = find_pull_requests_for_commit(
            pool=token_pool,
            owner=commit.owner,
            repo=commit.repo_name,
            commit_sha=commit.commit_hash,
            cve_id=commit.cve_id,
            commit_message=commit.message,
            allow_search_api=allow_search_api,
        )

        record["pr_status"] = res["status"]
        record["detection_method"] = res["method"]
        record["pull_requests"] = res["pull_requests"]
        record["code_changes"] = res.get("code_changes", [])
        record["error"] = res["error_message"]

        if res["status"] == "found":
            stats["found"] += 1
            urls = ", ".join(pr["url"] for pr in res["pull_requests"])
            top_score = max((pr.get("confidence_score", 0) for pr in res["pull_requests"]), default=0)
            logger.info(
                "[%d/%d] %s%s/%s @ %s -> FOUND %d PR(s) [Score: %d] via %s: %s",
                idx,
                len(commits),
                cve_tag,
                commit.owner,
                commit.repo_name,
                short_hash,
                len(res["pull_requests"]),
                top_score,
                res["method"],
                urls,
            )
        elif res["status"] == "not_found":
            stats["not_found"] += 1
            logger.info(
                "[%d/%d] %s%s/%s @ %s -> No PR found",
                idx,
                len(commits),
                cve_tag,
                commit.owner,
                commit.repo_name,
                short_hash,
            )
        elif res["status"] == "repo_not_found":
            stats["repo_not_found"] += 1
            logger.warning(
                "[%d/%d] %s%s/%s @ %s -> Repository not found (404/deleted)",
                idx,
                len(commits),
                cve_tag,
                commit.owner,
                commit.repo_name,
                short_hash,
            )
        elif res["status"] == "commit_not_found":
            stats["commit_not_found"] += 1
            logger.warning(
                "[%d/%d] %s%s/%s @ %s -> Commit not found in repository",
                idx,
                len(commits),
                cve_tag,
                commit.owner,
                commit.repo_name,
                short_hash,
            )
        else:
            stats["error"] += 1
            logger.error(
                "[%d/%d] %s%s/%s @ %s -> Error: %s",
                idx,
                len(commits),
                cve_tag,
                commit.owner,
                commit.repo_name,
                short_hash,
                res["error_message"],
            )

        results.append(record)

        # Periodically save incremental progress
        if idx % 10 == 0 or idx == len(commits):
            _save_results(output_path, results, stats, found_output_path)

    elapsed = time.time() - start_time
    _print_summary(stats, elapsed, output_path, found_output_path)


def _save_results(
    output_path: Path,
    results: List[Dict[str, Any]],
    stats: Dict[str, int],
    found_output_path: Optional[Path] = None,
):
    """Save results JSON with summary metadata, and write a found-only JSON file ordered by confidence score."""
    payload = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "summary": stats,
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    if found_output_path:
        found_entries = []
        for r in results:
            if r.get("pr_status") == "found" and r.get("pull_requests"):
                prs = r.get("pull_requests", [])
                best_conf = max((pr.get("confidence_score", 0) for pr in prs), default=0)
                best_tier = prs[0].get("confidence_tier", "UNKNOWN") if prs else "UNKNOWN"
                found_entries.append({
                    "cve_id": r.get("cve_id"),
                    "commit_hash": r.get("commit_hash"),
                    "repo_url": r.get("repo_url"),
                    "owner": r.get("owner"),
                    "repo": r.get("repo"),
                    "confidence_score": best_conf,
                    "confidence_tier": best_tier,
                    "pr_urls": [pr["url"] for pr in prs],
                    "pull_requests": prs,
                    "code_changes": r.get("code_changes", []),
                    "detection_method": r.get("detection_method"),
                })

        # Sort in order of confidence score (highest first)
        found_entries.sort(key=lambda x: x.get("confidence_score", 0), reverse=True)

        found_payload = {
            "total_found": len(found_entries),
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "found_prs": found_entries,
        }
        found_output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(found_output_path, "w", encoding="utf-8") as f:
            json.dump(found_payload, f, indent=2)


def _print_summary(
    stats: Dict[str, int],
    elapsed: float,
    output_path: Path,
    found_output_path: Optional[Path] = None,
):
    """Print clean terminal summary of mining results."""
    total = stats["total"]
    found = stats["found"]
    pct = (found / total * 100) if total > 0 else 0.0

    print("\n" + "=" * 60)
    print(" CVEfixes GitHub Pull Request Miner - Summary Report")
    print("=" * 60)
    print(f" Total commits processed:        {total}")
    print(f" PRs successfully found:         {found} ({pct:.1f}%)")
    print(f" No PR associated:               {stats['not_found']}")
    print(f" Non-GitHub repositories:        {stats['non_github']}")
    print(f" Repository not found (404):     {stats['repo_not_found']}")
    print(f" Commit not found in repo:       {stats['commit_not_found']}")
    print(f" Other errors:                   {stats['error']}")
    print(f" Total time elapsed:             {elapsed:.1f} seconds")
    print(f" All results saved to:           {output_path.resolve()}")
    if found_output_path:
        print(f" Found PRs saved to:             {found_output_path.resolve()}")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mine GitHub Pull Request links from CVEfixes fixing commits."
    )
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to CVEfixes SQLite database file (e.g. CVEfixes.db).",
    )
    parser.add_argument(
        "--sql-dump",
        type=str,
        default=None,
        help="Path to CVEfixes SQL dump file (e.g. cvefixes.sql).",
    )
    parser.add_argument(
        "--limit",
        "-n",
        type=int,
        default=100,
        help="Number of commits to process from CVEfixes (default: 100).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="cvefixes_pr_links.json",
        help="Path to output JSON file (default: cvefixes_pr_links.json).",
    )
    parser.add_argument(
        "--found-output",
        type=str,
        default="found_pr_links.json",
        help="Path to output JSON file containing only found PRs (default: found_pr_links.json).",
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="GitHub personal access token(s), comma-separated. Overrides .env.",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Use built-in sample CVE fixing commits for testing without a database.",
    )
    parser.add_argument(
        "--order",
        choices=["default", "recent"],
        default="default",
        help="Order to query commits: 'default' (natural dump order starting 1999) or 'recent' (newest CVEs first).",
    )
    parser.add_argument(
        "--min-year",
        type=int,
        default=None,
        help="Filter CVEs to only those published in or after MIN_YEAR (e.g. 2020).",
    )
    parser.add_argument(
        "--use-search-api",
        action="store_true",
        default=False,
        help="Enable GitHub Search API fallback (disabled by default to prevent false positives where commit hashes are quoted in comments).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    tokens = load_github_tokens(args.token)
    token_pool = TokenPool(tokens)

    if args.sample:
        provider = SampleCVEfixesProvider()
    else:
        try:
            provider = CVEfixesDatabase(
                db_path=args.db_path,
                sql_dump_path=args.sql_dump,
            )
            # Verify database accessibility
            _ = provider.connect()
        except FileNotFoundError as e:
            logger.error("%s", e)
            print("\n[NOTE] CVEfixes data file not detected.")
            print("While your data is still downloading, you can run with `--sample` to test the pipeline:")
            print("    python pr-miner.py --sample --limit 5\n")
            sys.exit(1)

    output_file = Path(args.output)
    found_output_file = Path(args.found_output)
    mine_prs_from_cvefixes(
        provider=provider,
        token_pool=token_pool,
        limit=args.limit,
        output_path=output_file,
        found_output_path=found_output_file,
        allow_search_api=args.use_search_api,
        order=args.order,
        min_year=args.min_year,
    )


if __name__ == "__main__":
    main()
