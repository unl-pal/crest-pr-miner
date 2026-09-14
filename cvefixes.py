"""
CVEfixes Data Extractor

Encapsulates loading and querying commits and fixes from a CVEfixes SQLite database or SQL dump.
Provides default query implementations matching the standard CVEfixes schema (Zenodo release),
while structuring the class with clear hooks so it can easily be tailored or filled in with
exact schema details once the download finishes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
import logging
from pathlib import Path
import re
import sqlite3
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class FixingCommit:
    """Represents a vulnerability-fixing commit extracted from CVEfixes."""
    commit_hash: str
    repo_url: str
    cve_id: Optional[str] = None
    owner: Optional[str] = None
    repo_name: Optional[str] = None
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_github_repo(url: str) -> Optional[tuple[str, str]]:
    """
    Extract (owner, repo) from a repository or commit URL.
    Handles various GitHub URL formats:
      - https://github.com/owner/repo
      - https://github.com/owner/repo.git
      - https://github.com/owner/repo/commit/<sha>
      - git@github.com:owner/repo.git
      - http://github.com/owner/repo
    """
    if not url:
        return None
    match = re.search(r"github\.com[/:](?P<owner>[^/\s]+)/(?P<repo>[^/\s#?]+)", url)
    if match:
        owner = match.group("owner")
        repo = match.group("repo")
        if repo.endswith(".git"):
            repo = repo[:-4]
        return owner, repo
    return None


class CVEfixesProvider(ABC):
    """Abstract base class for extracting commits from CVEfixes data."""

    @abstractmethod
    def get_fixing_commits(self, limit: int = 100) -> List[FixingCommit]:
        """
        Retrieve up to `limit` vulnerability fixing commits.
        Subclasses implement specific extraction logic (SQLite DB, SQL dump, etc.).
        """
        pass


class CVEfixesDatabase(CVEfixesProvider):
    """
    Extractor for CVEfixes database / SQL dump.

    Standard CVEfixes Schema (Bhandari et al., MSR 2021 / Zenodo):
      - Table `fixes`:
          - `cve_id`: CVE identifier (e.g. 'CVE-2020-11022')
          - `hash`: Commit SHA (e.g. '9dae1e8...')
          - `repo_url`: Repository URL (e.g. 'https://github.com/jquery/jquery')
      - Table `commits`:
          - `hash`: Commit SHA
          - `repo_url`: Repository URL
          - `msg`: Commit message
          - `author_date`, `committer_date`, etc.
      - Table `repository`:
          - `repo_url`, `repo_name`, `owner`, etc.

    NOTE FOR SCHEMA CUSTOMIZATION:
    If your downloaded SQL dump or database uses different table names or column names,
    you can adjust the SQL queries in `get_fixing_commits` below.
    """

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        sql_dump_path: Optional[str | Path] = None,
    ):
        self.db_path = Path(db_path) if db_path else None
        self.sql_dump_path = Path(sql_dump_path) if sql_dump_path else None
        self._conn: Optional[sqlite3.Connection] = None

    def find_default_data_file(self) -> Optional[Path]:
        """Look for common CVEfixes file names in current and data directories, or extract from zip."""
        candidates = [
            "cvefixes.db",
            "CVEfixes.db",
            "data/cvefixes.db",
            "data/CVEfixes.db",
            "CVEfixes.sqlite",
            "cvefixes.sqlite",
            "CVEfixes.sql",
            "cvefixes.sql",
            "data/CVEfixes.sql",
            "data/cvefixes.sql",
        ]
        for c in candidates:
            p = Path(c)
            if p.is_file():
                return p

        # Check for CVEfixes zip archive in current or parent directory
        zip_candidates = list(Path(".").glob("*CVEfixes*.zip")) + list(Path("..").glob("*CVEfixes*.zip"))
        if zip_candidates:
            zip_path = zip_candidates[0]
            logger.info("Found CVEfixes zip archive at %s. Extracting fixes and commits tables...", zip_path)
            db_target = Path("cvefixes.db")
            self._extract_from_zip(zip_path, db_target)
            if db_target.is_file():
                return db_target

        return None

    @staticmethod
    def _extract_from_zip(zip_path: Path, db_target: Path):
        """Extract fixes and commits tables directly from SQL dump in zip without full decompression."""
        import zipfile
        import gzip
        conn = sqlite3.connect(str(db_target))
        c = conn.cursor()
        c.execute("DROP TABLE IF EXISTS fixes")
        c.execute("DROP TABLE IF EXISTS commits")
        c.execute("CREATE TABLE fixes (cve_id TEXT, hash TEXT, repo_url TEXT)")
        c.execute("CREATE TABLE commits (hash TEXT, repo_url TEXT, author TEXT, author_date TEXT, author_timezone TEXT, committer TEXT, committer_date TEXT, committer_timezone TEXT, msg TEXT, merge TEXT, parents TEXT, num_lines_added TEXT, num_lines_deleted TEXT, dmm_unit_complexity TEXT, dmm_unit_interfacing TEXT, dmm_unit_size TEXT)")

        with zipfile.ZipFile(str(zip_path)) as z:
            sql_gz_members = [m for m in z.namelist() if m.endswith(".sql.gz") or m.endswith(".sql")]
            if not sql_gz_members:
                logger.warning("No .sql or .sql.gz found inside %s", zip_path)
                return
            target_member = sql_gz_members[0]
            with z.open(target_member) as raw_stream:
                stream = gzip.GzipFile(fileobj=raw_stream) if target_member.endswith(".gz") else raw_stream
                in_commits = False
                for line in stream:
                    decoded = line.decode("utf-8", errors="ignore")
                    if decoded.startswith("INSERT INTO fixes "):
                        c.execute(decoded)
                    elif "CREATE TABLE IF NOT EXISTS \"commits\"" in decoded:
                        in_commits = True
                    elif in_commits:
                        if decoded.startswith("INSERT INTO commits "):
                            c.execute(decoded)
                        elif decoded.startswith("CREATE TABLE IF NOT EXISTS \"file_change\""):
                            break
        conn.commit()
        conn.close()
        logger.info("Successfully created lightweight database at %s", db_target)

    def connect(self) -> sqlite3.Connection:
        """Connect to the SQLite database or import the SQL dump into an in-memory DB."""
        if self._conn is not None:
            return self._conn

        target_file = self.db_path or self.sql_dump_path
        if not target_file:
            target_file = self.find_default_data_file()

        if not target_file or not target_file.is_file():
            raise FileNotFoundError(
                f"CVEfixes database or dump not found at {target_file}. "
                "Specify the path using --db-path or --sql-dump, or use --sample for testing."
            )

        suffix = target_file.suffix.lower()
        if suffix in [".db", ".sqlite", ".sqlite3"]:
            logger.info("Opening CVEfixes SQLite database: %s", target_file)
            self._conn = sqlite3.connect(str(target_file))
            self._conn.row_factory = sqlite3.Row
            return self._conn
        elif suffix == ".sql":
            logger.info("Importing SQL dump into in-memory SQLite database from: %s", target_file)
            self._conn = sqlite3.connect(":memory:")
            self._conn.row_factory = sqlite3.Row
            with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                self._conn.executescript(f.read())
            return self._conn
        else:
            # Attempt SQLite connection directly by default
            logger.info("Attempting SQLite connection for: %s", target_file)
            self._conn = sqlite3.connect(str(target_file))
            self._conn.row_factory = sqlite3.Row
            return self._conn

    def get_table_names(self) -> List[str]:
        """Return all table names in the connected database."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        return [row[0] for row in cursor.fetchall()]

    def get_table_schema(self, table_name: str) -> List[Dict[str, Any]]:
        """Return column info for a specific table (useful for inspecting downloaded dump)."""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(f"PRAGMA table_info({table_name})")
        return [dict(row) for row in cursor.fetchall()]

    def get_fixing_commits(
        self,
        limit: int = 100,
        github_only: bool = True,
        order: str = "default",
        min_year: Optional[int] = None,
    ) -> List[FixingCommit]:
        """
        Extract fixing commits from the CVEfixes database.

        Default implementation queries the `fixes` table and optionally joins
        `commits` to retrieve commit messages.
        """
        conn = self.connect()
        cursor = conn.cursor()
        tables = set(self.get_table_names())
        logger.info("Available tables in CVEfixes database: %s", sorted(tables))

        commits: List[FixingCommit] = []

        # =========================================================================
        # Strategy A: Standard CVEfixes schema with `fixes` table
        # =========================================================================
        if "fixes" in tables:
            has_commits_table = "commits" in tables
            if has_commits_table:
                query = """
                    SELECT f.cve_id, f.hash, f.repo_url, c.msg as message
                    FROM fixes f
                    LEFT JOIN commits c ON f.hash = c.hash
                """
            else:
                query = """
                    SELECT f.cve_id, f.hash, f.repo_url, NULL as message
                    FROM fixes f
                """

            where_clauses = []
            params = []
            if github_only:
                where_clauses.append("f.repo_url LIKE '%github.com%'")

            if min_year:
                where_clauses.append("CAST(substr(f.cve_id, 5, 4) AS INTEGER) >= ?")
                params.append(min_year)

            if where_clauses:
                query += " WHERE " + " AND ".join(where_clauses)

            if order in ("recent", "cve-desc", "desc"):
                query += " ORDER BY f.cve_id DESC"
            elif order in ("cve-asc", "asc"):
                query += " ORDER BY f.cve_id ASC"

            query += " LIMIT ?"
            params.append(limit)
            logger.debug("Running query: %s [params=%s]", query.strip(), params)
            cursor.execute(query, tuple(params))

            for row in cursor.fetchall():
                cve_id = row["cve_id"]
                commit_hash = row["hash"]
                repo_url = row["repo_url"]
                msg = row["message"] if "message" in row.keys() else None

                gh = parse_github_repo(repo_url)
                owner, repo_name = gh if gh else (None, None)

                commits.append(
                    FixingCommit(
                        commit_hash=commit_hash,
                        repo_url=repo_url,
                        cve_id=cve_id,
                        owner=owner,
                        repo_name=repo_name,
                        message=msg,
                    )
                )

        # =========================================================================
        # Strategy B: Fallback if only `commits` table exists
        # =========================================================================
        elif "commits" in tables or "commit" in tables:
            tbl = "commits" if "commits" in tables else "commit"
            cols = {c["name"] for c in self.get_table_schema(tbl)}

            hash_col = "hash" if "hash" in cols else "commit_hash" if "commit_hash" in cols else "sha"
            repo_col = "repo_url" if "repo_url" in cols else "repository_url"
            cve_col = "cve_id" if "cve_id" in cols else "cve" if "cve" in cols else None
            msg_col = "msg" if "msg" in cols else "message" if "message" in cols else None

            select_parts = [f"{hash_col} AS hash", f"{repo_col} AS repo_url"]
            if cve_col:
                select_parts.append(f"{cve_col} AS cve_id")
            else:
                select_parts.append("NULL AS cve_id")

            if msg_col:
                select_parts.append(f"{msg_col} AS message")
            else:
                select_parts.append("NULL AS message")

            query = f"SELECT {', '.join(select_parts)} FROM {tbl}"
            if github_only:
                query += f" WHERE {repo_col} LIKE '%github.com%'"
            query += " LIMIT ?"

            logger.debug("Running fallback query: %s [limit=%d]", query, limit)
            cursor.execute(query, (limit,))
            for row in cursor.fetchall():
                cve_id = row["cve_id"]
                commit_hash = row["hash"]
                repo_url = row["repo_url"]
                msg = row["message"]

                gh = parse_github_repo(repo_url)
                owner, repo_name = gh if gh else (None, None)

                commits.append(
                    FixingCommit(
                        commit_hash=commit_hash,
                        repo_url=repo_url,
                        cve_id=cve_id,
                        owner=owner,
                        repo_name=repo_name,
                        message=msg,
                    )
                )

        # =========================================================================
        # Strategy C: Unrecognized / Custom Schema Hook
        # =========================================================================
        else:
            raise ValueError(
                f"Unrecognized schema in CVEfixes database. Tables found: {list(tables)}. "
                "Please update `CVEfixesDatabase.get_fixing_commits()` in cvefixes.py "
                "with your specific table and column names."
            )

        logger.info("Loaded %d commits from CVEfixes database", len(commits))
        return commits


class SampleCVEfixesProvider(CVEfixesProvider):
    """
    Provides real sample CVE fixing commits for testing while the main dataset downloads.
    """

    SAMPLE_COMMITS = [
        FixingCommit(
            cve_id="CVE-2019-14846",
            commit_hash="c032646d65f57f620f4c3cb5dc06b8ff4fbf5c60",
            repo_url="https://github.com/ansible/ansible",
            owner="ansible",
            repo_name="ansible",
            message="Fix unauthorized access vulnerability (#63156)",
        ),
        FixingCommit(
            cve_id="CVE-2020-11022",
            commit_hash="9dae1e8ab1a719ab8414441b2e5a7b8e5c468ad4",
            repo_url="https://github.com/jquery/jquery",
            owner="jquery",
            repo_name="jquery",
            message="HTML containment check regex fix",
        ),
        FixingCommit(
            cve_id="CVE-2021-32559",
            commit_hash="4b9015c92fceea2316e254ff03eb6060c5a2cdfb",
            repo_url="https://github.com/canonical/apport",
            owner="canonical",
            repo_name="apport",
            message="Fix PID reuse race condition",
        ),
        FixingCommit(
            cve_id="CVE-2020-5247",
            commit_hash="15a77ddbe7c1b1ec4562092cc632616259f6ea9b",
            repo_url="https://github.com/puma/puma",
            owner="puma",
            repo_name="puma",
            message="Carriage return injection fix in HTTP headers (#2164)",
        ),
        FixingCommit(
            cve_id="CVE-2021-29421",
            commit_hash="fa098236d39faae0be2fa19e34ec62b2d0fa3c15",
            repo_url="https://github.com/aio-libs/aiohttp",
            owner="aio-libs",
            repo_name="aiohttp",
            message="Fix open redirect in HTTP client",
        ),
    ]

    def get_fixing_commits(self, limit: int = 100) -> List[FixingCommit]:
        logger.info("Using sample CVE fixes provider (limit=%d)", limit)
        return self.SAMPLE_COMMITS[:limit]
