"""
Tests for live secret verification (dlp_patterns._verify).

Never touches the network — every provider response is mocked at the
urllib.request.urlopen level, so these run offline like the rest of the
suite. That also means these tests double as documentation of exactly what
each provider is expected to return for a valid / invalid / errored key.
"""
import io
import json
import urllib.error

import pytest

import dlp_patterns
from dlp_patterns import Scanner
from dlp_patterns._verify import verify_value, verify_findings, _ANNOTATE_TYPES


class _FakeResponse:
    def __init__(self, status, body: bytes):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _mock_urlopen(status=200, body=b""):
    def _fn(req, timeout=None):
        return _FakeResponse(status, body)
    return _fn


def _mock_urlopen_http_error(status, body=b""):
    def _fn(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, status, "err", {}, io.BytesIO(body))
    return _fn


# ── verify_value: per-provider behavior ─────────────────────────────────────

def test_github_token_valid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    r = verify_value("github_token", "ghp_fake")
    assert r.status == "valid"


def test_github_token_invalid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(401))
    r = verify_value("github_token", "ghp_fake")
    assert r.status == "invalid"


def test_github_token_network_error_is_not_invalid(monkeypatch):
    def _raise(req, timeout=None):
        raise TimeoutError("timed out")
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    r = verify_value("github_token", "ghp_fake")
    assert r.status == "error"
    assert r.status != "invalid"


def test_slack_token_valid(monkeypatch):
    body = json.dumps({"ok": True, "team": "acme"}).encode()
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200, body))
    r = verify_value("slack_api_token", "xoxb-fake")
    assert r.status == "valid"
    assert "acme" in r.detail


def test_slack_token_invalid(monkeypatch):
    # Slack returns HTTP 200 even for a bad token — ok:false in the body.
    body = json.dumps({"ok": False, "error": "invalid_auth"}).encode()
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200, body))
    r = verify_value("slack_api_token", "xoxb-fake")
    assert r.status == "invalid"


def test_stripe_key_valid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    r = verify_value("stripe_secret_key", "sk_test_fake")
    assert r.status == "valid"


def test_stripe_key_restricted_scope_still_counts_as_valid(monkeypatch):
    # 403 on /balance with a restricted key means "authenticated but not
    # permitted here" — the key is real and live, just narrowly scoped.
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(403))
    r = verify_value("stripe_restricted_key", "rk_test_fake")
    assert r.status == "valid"


def test_stripe_key_invalid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(401))
    r = verify_value("stripe_secret_key", "sk_test_fake")
    assert r.status == "invalid"


def test_telegram_bot_token_valid(monkeypatch):
    body = json.dumps({"ok": True}).encode()
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200, body))
    r = verify_value("telegram_bot_token", "123:fake")
    assert r.status == "valid"


def test_google_api_key_invalid(monkeypatch):
    body = json.dumps({"error": {"errors": [{"reason": "keyInvalid"}]}}).encode()
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(400, body))
    r = verify_value("google_api_key", "AIzaFake")
    assert r.status == "invalid"


def test_google_api_key_restricted_still_counts_as_valid(monkeypatch):
    body = json.dumps({"error": {"errors": [{"reason": "accessNotConfigured"}]}}).encode()
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(403, body))
    r = verify_value("google_api_key", "AIzaFake")
    assert r.status == "valid"


# ── No verifier / no value ──────────────────────────────────────────────────

def test_unsupported_type_is_unverifiable():
    r = verify_value("aws_access_key", "AKIAFAKE00000000000")
    assert r.status == "unverifiable"


def test_empty_value_is_unverifiable():
    r = verify_value("github_token", "")
    assert r.status == "unverifiable"


# ── Safety: never verify side-effecting endpoints ───────────────────────────

def test_annotate_types_includes_unverifiable_secret_shapes():
    # These get an explicit "unverifiable" verdict in --verify output rather
    # than silently having no verdict at all — see _verify.py rule 2.
    assert "aws_access_key" in _ANNOTATE_TYPES
    assert "slack_webhook" in _ANNOTATE_TYPES
    assert "github_token" in _ANNOTATE_TYPES  # has a real verifier too


def test_webhooks_are_never_network_verified(monkeypatch):
    def _fail_if_called(req, timeout=None):
        raise AssertionError("a webhook URL must never be POSTed to during verification")
    monkeypatch.setattr("urllib.request.urlopen", _fail_if_called)

    for t in ("slack_webhook", "discord_webhook"):
        r = verify_value(t, "https://hooks.slack.com/services/FAKE")
        assert r.status == "unverifiable"


# ── verify_findings: in-place mutation, dedup, scoping ──────────────────────

def test_verify_findings_sets_verification_in_place(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    scanner = Scanner()
    result = scanner.scan("token = ghp_9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wA", secrets_only=True)
    assert result.has_findings
    verify_findings(result.all)
    checked = [f for f in result.all if f.type == "github_token"]
    assert checked and checked[0].verification is not None
    assert checked[0].verification.status == "valid"


def test_verify_findings_dedupes_identical_secret(monkeypatch):
    calls = []

    def _counting_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResponse(200, b"")

    monkeypatch.setattr("urllib.request.urlopen", _counting_urlopen)

    scanner = Scanner()
    token = "ghp_9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wY"
    r1 = scanner.scan(f"a = {token}", secrets_only=True)
    r2 = scanner.scan(f"b = {token}", secrets_only=True)
    all_findings = r1.all + r2.all
    assert len(all_findings) == 2

    verify_findings(all_findings)
    assert len(calls) == 1  # same (type, raw) checked once, not twice
    assert all(f.verification.status == "valid" for f in all_findings)


def test_verify_findings_leaves_pii_findings_unset(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    scanner = Scanner()
    result = scanner.scan("Email me at alice@corp.com")
    verify_findings(result.all)
    assert all(f.verification is None for f in result.all if f.type == "email")


def test_raw_value_never_appears_in_to_dict():
    scanner = Scanner()
    result = scanner.scan("token = ghp_9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wC", secrets_only=True)
    for f in result.all:
        d = f.to_dict()
        assert "raw" not in d


# ── Top-level dlp_patterns.verify() convenience wrapper ─────────────────────

def test_top_level_verify_wrapper(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(401))
    result = dlp_patterns.scan("token = ghp_9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wD", secrets_only=True)
    dlp_patterns.verify(result)
    assert any(f.verification and f.verification.status == "invalid" for f in result.all)
