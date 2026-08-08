"""
Git history scanning — walk every commit a repo has ever had, not just the
working tree, looking for secrets that were committed and later removed.

Deleting a leaked key from HEAD does not un-leak it: anyone with a clone of
the repo — including one taken before the deletion — can still read it out
of `git log -p`. This is the single most common way real secrets leak, and
plain `dlp-scan <dir>` mode (which walks the working tree and explicitly
skips `.git`) cannot see it. This module is what closes that gap.

Only *added* lines (`+` in a diff) are scanned, once per commit that
introduced them. That's sufficient and non-redundant: a line later deleted
was necessarily added by some earlier commit, so scanning every commit's
additions covers every line that has ever existed in the repo, exactly once
per commit that introduced it — no need to also scan `-` lines.

Requires the `git` binary on PATH. That's an external tool dependency, not
a Python package dependency — same assumption any git-aware CLI makes, and
this package still ships with zero pip-installable dependencies.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

from dlp_patterns._engine import Finding, Scanner

_COMMIT_MARKER = "\x01DLP-COMMIT\x01"
_FIELD_SEP = "\x02"

# Same lockfile skip-list as directory scanning (__main__.py) — auto-generated
# files full of base64 integrity hashes that false-positive as secrets.
_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "Cargo.lock", "poetry.lock", "Pipfile.lock", "go.sum", "composer.lock",
}


class NotAGitRepoError(RuntimeError):
    """Raised when the target path isn't inside a git working tree."""


class GitNotFoundError(RuntimeError):
    """Raised when the `git` binary isn't on PATH."""


@dataclass
class HistoryFinding:
    """A :class:`~dlp_patterns._engine.Finding` located inside one commit's diff."""
    commit: str
    short_commit: str
    author: str
    date: str
    subject: str
    file: str
    finding: Finding

    def to_dict(self) -> dict:
        d = self.finding.to_dict()
        d.update({
            "commit": self.commit,
            "short_commit": self.short_commit,
            "author": self.author,
            "date": self.date,
            "subject": self.subject,
            "file": self.file,
        })
        return d


@dataclass
class HistoryScanResult:
    findings: List[HistoryFinding] = field(default_factory=list)
    commits_scanned: int = 0
    elapsed_ms: float = 0.0

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def highest_severity(self) -> Optional[str]:
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        best: Optional[str] = None
        for hf in self.findings:
            sev = hf.finding.severity
            if best is None or rank.get(sev, 9) < rank.get(best, 9):
                best = sev
        return best

    def to_dict(self) -> dict:
        return {
            "mode": "history",
            "commits_scanned": self.commits_scanned,
            "findings": [hf.to_dict() for hf in self.findings],
            "elapsed_ms": self.elapsed_ms,
        }


def _require_git(repo_path: str) -> None:
    if shutil.which("git") is None:
        raise GitNotFoundError("git binary not found on PATH — history scanning requires git")
    check = subprocess.run(
        ["git", "-C", repo_path, "rev-parse", "--is-inside-work-tree"],
        capture_output=True, text=True,
    )
    if check.returncode != 0 or check.stdout.strip() != "true":
        raise NotAGitRepoError(f"{repo_path!r} is not inside a git working tree")


def _iter_commit_blocks(repo_path: str, *, max_commits: Optional[int], include_merges: bool) -> Iterator[str]:
    fmt = _COMMIT_MARKER + _FIELD_SEP.join(["%H", "%h", "%an <%ae>", "%aI", "%s"]) + "\n"
    cmd = [
        "git", "-C", repo_path, "log", "--all", "--no-color", "--unified=0",
        f"--pretty=format:{fmt}",
    ]
    if not include_merges:
        cmd.append("--no-merges")
    if max_commits:
        cmd += ["-n", str(max_commits)]
    cmd.append("-p")

    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"git log failed: {proc.stderr.strip()}")

    for block in proc.stdout.split(_COMMIT_MARKER):
        if block.strip():
            yield block


def _parse_commit_block(block: str) -> Optional[Tuple[str, str, str, str, str, str]]:
    header_line, _, rest = block.partition("\n")
    parts = header_line.split(_FIELD_SEP)
    if len(parts) != 5:
        return None
    full_sha, short_sha, author, date, subject = parts
    return full_sha, short_sha, author, date, subject, rest


def _iter_added_chunks_by_file(diff_text: str) -> Iterator[Tuple[str, str]]:
    """Yield (path, added_text) for each file touched in one commit's diff."""
    current_file: Optional[str] = None
    buf: List[str] = []

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            if current_file and buf:
                yield current_file, "\n".join(buf)
            current_file, buf = None, []
        elif line.startswith("+++ "):
            path = line[4:]
            current_file = None if path == "/dev/null" else path[2:] if path.startswith("b/") else path
        elif line.startswith("+") and not line.startswith("+++"):
            if current_file:
                buf.append(line[1:])

    if current_file and buf:
        yield current_file, "\n".join(buf)


def scan_git_history(
    repo_path: str = ".",
    *,
    secrets_only: bool = True,
    max_commits: Optional[int] = None,
    include_merges: bool = False,
    scanner: Optional[Scanner] = None,
) -> HistoryScanResult:
    """
    Scan every commit's added lines across all branches of the repo at
    *repo_path* (default: current directory).

    Parameters
    ----------
    repo_path:
        Path to (or inside) a git working tree.
    secrets_only:
        Defaults to True, unlike :func:`dlp_patterns.scan` — full-history
        PII scanning is extremely noisy (every email/phone number ever
        committed, including in test fixtures), so the secrets-focused
        default matches what this mode is actually useful for. Pass
        ``secrets_only=False`` to also scan for PII across history.
    max_commits:
        Limit to the N most recent commits (across ``--all`` branches).
    include_merges:
        Merge commits are skipped by default (their diffs can be noisy /
        redundant with the commits they merge); pass True to include them.

    Raises
    ------
    GitNotFoundError
        `git` isn't on PATH.
    NotAGitRepoError
        *repo_path* isn't inside a git working tree.
    """
    _require_git(repo_path)
    scanner = scanner or Scanner()
    t0 = time.monotonic()

    result = HistoryScanResult()

    for block in _iter_commit_blocks(repo_path, max_commits=max_commits, include_merges=include_merges):
        parsed = _parse_commit_block(block)
        if not parsed:
            continue
        full_sha, short_sha, author, date, subject, diff_text = parsed
        result.commits_scanned += 1

        for path, added_text in _iter_added_chunks_by_file(diff_text):
            filename = path.rsplit("/", 1)[-1]
            if filename in _SKIP_FILENAMES or not added_text.strip():
                continue
            scan_result = scanner.scan(added_text, secrets_only=secrets_only)
            for f in scan_result.all:
                result.findings.append(HistoryFinding(
                    commit=full_sha, short_commit=short_sha, author=author,
                    date=date, subject=subject, file=path, finding=f,
                ))

    result.elapsed_ms = round((time.monotonic() - t0) * 1000, 2)
    return result
