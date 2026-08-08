"""
Tests for git history scanning (dlp_patterns._history).

Builds real throwaway git repos under tmp_path and shells out to the real
`git` binary — no mocking of git itself, since the whole point of this
module is correctly parsing real `git log -p` output. Skipped automatically
if `git` isn't available in the test environment.
"""
import os
import shutil
import subprocess

import pytest

from dlp_patterns._history import (
    scan_git_history, NotAGitRepoError, GitNotFoundError,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

# High-entropy fixture (same one used in test_patterns.py / test_verify.py) —
# a repeated-char token would fail the entropy gate before even reaching
# the "was it added or removed" logic this module cares about.
_TOKEN = "ghp_9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX"


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo)] + list(args), check=True,
                    capture_output=True, text=True,
                    env={**os.environ,
                         "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.com",
                         "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@example.com"})


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "Test")
    return r


def _commit(repo, filename, content, message):
    (repo / filename).write_text(content)
    _git(repo, "add", filename)
    _git(repo, "commit", "-q", "-m", message)


# ── Core: catches a secret added then removed ───────────────────────────────

def test_finds_secret_added_then_deleted(repo):
    _commit(repo, "config.py", f"API_KEY = '{_TOKEN}'\n", "add key")
    _commit(repo, "config.py", "API_KEY = None\n", "remove key")

    result = scan_git_history(str(repo))

    assert result.has_findings
    assert any(hf.finding.type == "github_token" for hf in result.findings)
    assert result.commits_scanned == 2


def test_working_tree_scan_would_miss_it(repo):
    # Sanity check for the premise of this whole feature: the file at HEAD
    # is clean, so a normal (non-history) scan of the working tree finds
    # nothing — only walking history catches it.
    _commit(repo, "config.py", f"API_KEY = '{_TOKEN}'\n", "add key")
    _commit(repo, "config.py", "API_KEY = None\n", "remove key")

    from dlp_patterns import scan
    head_text = (repo / "config.py").read_text()
    working_tree_result = scan(head_text, secrets_only=True)
    assert not working_tree_result.has_findings

    history_result = scan_git_history(str(repo))
    assert history_result.has_findings


def test_clean_history_has_no_findings(repo):
    _commit(repo, "README.md", "# hello\n", "init")
    result = scan_git_history(str(repo))
    assert not result.has_findings
    assert result.commits_scanned == 1


# ── Metadata attached to each finding ───────────────────────────────────────

def test_finding_carries_commit_metadata(repo):
    _commit(repo, "config.py", f"API_KEY = '{_TOKEN}'\n", "add the leaked key")

    result = scan_git_history(str(repo))
    hf = result.findings[0]
    assert hf.file == "config.py"
    assert hf.subject == "add the leaked key"
    assert len(hf.short_commit) > 0
    assert hf.commit.startswith(hf.short_commit)
    assert "@" in hf.author


# ── secrets_only default ────────────────────────────────────────────────────

def test_history_mode_defaults_to_secrets_only(repo):
    _commit(repo, "notes.txt", "contact: alice@corp.com\n", "add contact")

    default_result = scan_git_history(str(repo))
    assert not any(hf.finding.type == "email" for hf in default_result.findings)

    full_result = scan_git_history(str(repo), secrets_only=False)
    assert any(hf.finding.type == "email" for hf in full_result.findings)


# ── Lockfiles skipped, matching directory-scan behavior ─────────────────────

def test_lockfiles_are_skipped(repo):
    # A base64-ish integrity hash that would otherwise false-positive.
    fake_hash = "sha512-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3AB4CD5EF6GH7IJ=="
    _commit(repo, "package-lock.json", f'{{"integrity": "{fake_hash}"}}\n', "add lockfile")
    result = scan_git_history(str(repo), secrets_only=False)
    assert not result.has_findings


# ── max_commits / include_merges plumbing ───────────────────────────────────

def test_max_commits_limits_scan(repo):
    _commit(repo, "a.txt", "one\n", "c1")
    _commit(repo, "b.txt", "two\n", "c2")
    _commit(repo, "c.txt", "three\n", "c3")

    result = scan_git_history(str(repo), max_commits=1)
    assert result.commits_scanned == 1


# ── Error handling ───────────────────────────────────────────────────────────

def test_not_a_git_repo_raises(tmp_path):
    not_a_repo = tmp_path / "plain_dir"
    not_a_repo.mkdir()
    with pytest.raises(NotAGitRepoError):
        scan_git_history(str(not_a_repo))


def test_git_not_found_raises(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(GitNotFoundError):
        scan_git_history(".")
