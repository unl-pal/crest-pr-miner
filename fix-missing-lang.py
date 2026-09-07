import json
import logging
import os
import re

from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from github import Auth, Github, RateLimitExceededException, GithubException
from pathlib import Path

load_dotenv()

log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=log_level,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

DATA_ROOT = Path("data")


class TokenPool:
    """Round-robin token pool that respects per-token rate-limit resets.

    GitHub exposes separate rate-limit buckets for different API categories
    (e.g. ``core`` for most REST calls and ``search`` for the search API).
    Each token entry tracks a reset time per category so that the pool
    can rotate and sleep correctly regardless of which bucket a call uses.
    """

    def __init__(self, tokens: list[str]):
        if not tokens:
            raise ValueError("At least one GitHub token is required.")
        # Each entry: {"token": str, "client": Github, "reset_at": {category: datetime|None}}
        self._pool = [
            {
                "token": t,
                "client": Github(auth=Auth.Token(t), per_page=100, user_agent="CREST-PR-Miner/1.0.0 (https://github.com/unl-pal/crest-pr-miner)"),
                "reset_at": {},
            }
            for t in tokens
        ]
        self._current = 0

    def get(self, category: str = "core") -> Github:
        """Return the next available GitHub client in round-robin order.

        Only tokens whose ``category`` rate-limit reset time has passed are
        considered available.  If all tokens are exhausted the method sleeps
        until the earliest reset and then returns that token's client.
        """
        now = datetime.now(tz=timezone.utc)
        n = len(self._pool)

        # Try each token starting from _current, wrapping around.
        for i in range(n):
            entry = self._pool[(self._current + i) % n]
            ra = entry["reset_at"].get(category)
            if ra is None or ra <= now:
                logger.info("[pool] using token %s with reset %s", entry["token"], ra)
                self._current = (self._current + i + 1) % n
                return entry["client"]

        # All tokens are rate-limited for this category; sleep until earliest reset.
        best = min(self._pool, key=lambda e: e["reset_at"].get(category, now))
        wait = (best["reset_at"][category] - now).total_seconds() + 5
        logger.warning(
            "All tokens rate-limited for '%s'; sleeping %.0f seconds until %s",
            category,
            wait,
            best["reset_at"][category].isoformat(),
        )
        time.sleep(wait)
        self._current = (self._pool.index(best) + 1) % n
        return best["client"]

    def get_token(self, client: Github) -> str | None:
        """Return the raw token string associated with a client."""
        for entry in self._pool:
            if entry["client"] is client:
                return entry["token"]
        return None

    def _fetch_reset(self, client: Github, category: str) -> datetime | None:
        """Fetch the rate-limit reset time for *category* from the API."""
        try:
            rl = client.get_rate_limit()
            print(json.dumps(rl))
            resource = getattr(rl, category, None)
            if resource is not None:
                reset_ts = resource.reset
                return reset_ts.replace(tzinfo=timezone.utc)
        except Exception:
            pass
        return None

    def update_rate_limit(self, client: Github, category: str = "core"):
        """Refresh the rate-limit reset time for a client after a successful API call."""
        for entry in self._pool:
            if entry["client"] is client:
                ts = self._fetch_reset(client, category)
                logger.debug("[pool] token %s category %s resets %s", entry["token"], category, ts)
                if ts is not None:
                    entry["reset_at"][category] = ts
                break

    def mark_rate_limited(self, client: Github, category: str = "core"):
        """Record the reset time for a client that just hit a rate limit."""
        for entry in self._pool:
            if entry["client"] is client:
                ts = self._fetch_reset(client, category)
                if ts is None:
                    ts = datetime.now(tz=timezone.utc) + timedelta(hours=1)
                entry["reset_at"][category] = ts
                logger.info("Token rate-limited (%s); reset at %s", category, ts)
                break


def _iter_pr_dirs():
    """Yield (pr_dir, repo_full_name, pr_number) for all previously mined PRs."""
    for json_path in sorted(DATA_ROOT.rglob("*.json")):
        if json_path.name in ("comments.json", "timeline.json"):
            continue
        if json_path.parent.name in ("reviews", "commits"):
            continue
        pr_dir = json_path.parent
        parts = pr_dir.relative_to(DATA_ROOT).parts
        repo_full_name = f"{parts[0]}/{parts[1]}"
        yield pr_dir, repo_full_name, parts[2]


def _call_with_retry(pool: TokenPool, fn, *args, category: str = "core", **kwargs):
    """Call fn(client, *args, **kwargs), rotating tokens on rate limits.

    ``category`` identifies the GitHub API rate-limit bucket the call uses
    (e.g. ``"core"`` or ``"search"``).  It is forwarded to :meth:`TokenPool.get`,
    :meth:`TokenPool.update_rate_limit`, and :meth:`TokenPool.mark_rate_limited`
    so that each bucket is tracked independently.
    """
    while True:
        client = pool.get(category)
        try:
            result = fn(client, *args, **kwargs)
            pool.update_rate_limit(client, category)
            return result
        except RateLimitExceededException:
            pool.mark_rate_limited(client, category)


# Load tokens
raw = os.environ.get("GH_TOKEN_LIST", "")
tokens = [t.strip() for t in raw.split(",") if t.strip()]
if not tokens:
    logger.error(
        "No GitHub tokens found. Set GH_TOKEN_LIST in your environment or .env file."
    )
    sys.exit(1)

# Validate token format: must start with "ghp_" followed by 36 alphanumeric chars
_token_re = re.compile(r'^ghp_[A-Za-z0-9]{36}$')
invalid = [t for t in tokens if not _token_re.match(t)]
if invalid:
    logger.error(
        "Invalid GitHub token(s) detected (expected ghp_ + 36 alphanumeric chars): %s",
        ", ".join(invalid),
    )
    sys.exit(1)

pool = TokenPool(tokens)

for pr_dir, repo_full_name, pr_number in _iter_pr_dirs():
    with open(pr_dir / (str(pr_number) + ".json"), "r") as f:
        data = json.load(f)
    lang = None
    try:
        lang = data['base']['repo']['language'].lower()
    except:
        def _get_repo(client, rfn):
            return client.get_repo(rfn)
        repo = _call_with_retry(pool, _get_repo, repo_full_name)
        if not repo.language:
            langs = repo.get_languages()
            lang = next(iter(langs))
        elif repo.language in ['Java', 'C', 'C++', 'Python']:
            lang = repo.language

        if lang:
            print('FOUND:', repo_full_name, lang)
            data['base']['repo']['language'] = lang
            with open(pr_dir / (str(pr_number) + ".json"), "w") as f:
                json.dump(data, f, indent=2)

    if not lang:
        print("STILL MISSING:", pr_dir)
