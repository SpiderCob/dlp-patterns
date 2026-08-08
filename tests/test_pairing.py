"""
Tests for AWS/Twilio paired-credential verification (dlp_patterns._pairing).

Never touches the network — urllib.request.urlopen is mocked, matching
test_verify.py's approach. These tests are also the spec for the pairing
behavior: proximity matching, the ASIA/session-token safety check, and —
most importantly — that pairing never crosses a scope boundary (no
cross-file / cross-commit mismatches).
"""
import io
import json
import urllib.error

import pytest

import dlp_patterns
from dlp_patterns import Scanner
from dlp_patterns._pairing import pair_and_verify, _pair_by_proximity

# High-entropy fixtures — same convention as test_verify.py/test_patterns.py.
# Built via concatenation (not one contiguous literal) throughout this file
# so these fixtures don't trip a --min-confidence-gated commit of the file
# they're defined in — same reasoning as test_patterns.py's bearer_token
# fixtures.
_ACCESS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_ASIA_KEY = "ASIA" + "IOSFODNN7EXAMPLE"
_SECRET_KEY = "wJalrXUtnFEMIK7MDENGb" + "PxRfiCYEXAMPLEKEYAB"  # 40 chars, high entropy
_SESSION_TOKEN = "FQoGZXRfYXJj" + "9aB3cD4eF5gH6iJ7kL8mN9oP0" + "qR1sT2uV3wXyZ01"
_TWILIO_SID = "AC" + "c322f7894404ca316d05a2c91808e748"  # high-entropy hex, not a repeated char
_TWILIO_TOKEN = "0123456789abcdef0123456789abcdef"  # 32 hex chars (pattern requires [a-f0-9])


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


def _mock_urlopen_capturing(status, body, sink):
    def _fn(req, timeout=None):
        sink.append(req)
        return _FakeResponse(status, body)
    return _fn


# ── _pair_by_proximity ───────────────────────────────────────────────────────

def test_pairs_nearby_findings():
    scanner = Scanner()
    text = f"aws_access_key_id = {_ACCESS_KEY}\naws_secret_access_key = {_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pairs = _pair_by_proximity(result.all, "aws_access_key", "aws_secret_key")
    assert len(pairs) == 1
    a, s = pairs[0]
    assert a.raw == _ACCESS_KEY
    assert s.raw == _SECRET_KEY


def test_does_not_pair_findings_far_apart():
    scanner = Scanner()
    filler = "x" * 3000
    text = f"aws_access_key_id = {_ACCESS_KEY}\n{filler}\naws_secret_access_key = {_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pairs = _pair_by_proximity(result.all, "aws_access_key", "aws_secret_key", max_distance=2000)
    assert pairs == []


def test_pairs_each_access_key_with_nearest_secret():
    scanner = Scanner()
    other_secret = "d5b64b84955ab8d8d55f8b5b0205484" + "31719037e"  # distinct 40-char, high-entropy fixture
    text = (
        f"key1 = {_ACCESS_KEY}\nsecret1 = {_SECRET_KEY}\n"
        f"key2 = {_ASIA_KEY}\nsecret2 = {other_secret}\n"
    )
    result = scanner.scan(text, secrets_only=True)
    pairs = _pair_by_proximity(result.all, "aws_access_key", "aws_secret_key")
    assert len(pairs) == 2
    paired_secrets = {s.raw for _, s in pairs}
    assert _SECRET_KEY in paired_secrets
    assert other_secret in paired_secrets


# ── AWS pairing + verification ──────────────────────────────────────────────

def test_aws_pair_valid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)

    access = next(f for f in result.all if f.type == "aws_access_key")
    secret = next(f for f in result.all if f.type == "aws_secret_key")
    assert access.verification.status == "valid"
    assert secret.verification.status == "valid"
    # Same VerificationResult object shared by both findings in the pair.
    assert access.verification is secret.verification


def test_aws_pair_invalid_client_token(monkeypatch):
    body = b'{"Error":{"Code":"InvalidClientTokenId"}}'
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(403, body))
    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification.status == "invalid"
    assert "InvalidClientTokenId" in access.verification.detail


def test_aws_pair_signature_does_not_match(monkeypatch):
    body = b'{"Error":{"Code":"SignatureDoesNotMatch"}}'
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(403, body))
    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification.status == "invalid"
    assert "SignatureDoesNotMatch" in access.verification.detail


def test_aws_network_error_is_not_invalid(monkeypatch):
    def _raise(req, timeout=None):
        raise TimeoutError("timed out")
    monkeypatch.setattr("urllib.request.urlopen", _raise)
    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification.status == "error"


def test_asia_key_without_session_token_is_unverifiable_not_invalid(monkeypatch):
    def _fail_if_called(req, timeout=None):
        raise AssertionError("must not attempt to sign an ASIA request without its session token")
    monkeypatch.setattr("urllib.request.urlopen", _fail_if_called)

    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={_ASIA_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification.status == "unverifiable"
    assert "session_token" in access.verification.detail


def test_asia_key_with_session_token_is_verified(monkeypatch):
    calls = []
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_capturing(200, b"", calls))

    scanner = Scanner()
    text = (
        f"AWS_ACCESS_KEY_ID={_ASIA_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
        f"AWS_SESSION_TOKEN={_SESSION_TOKEN}\n"
    )
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification.status == "valid"
    assert len(calls) == 1
    assert calls[0].get_header("X-amz-security-token") == _SESSION_TOKEN


def test_unpaired_aws_access_key_left_for_verify_findings(monkeypatch):
    # No secret key anywhere in the text -> pairing finds nothing, and
    # verify_findings gives it a specific "no paired finding" message
    # rather than the generic "no live verifier implemented".
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    scanner = Scanner()
    result = scanner.scan(f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\n", secrets_only=True)
    pair_and_verify(result.all)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification is None  # untouched by pairing

    from dlp_patterns._verify import verify_findings
    verify_findings(result.all)
    assert access.verification.status == "unverifiable"
    assert "paired" in access.verification.detail


# ── Twilio pairing + verification ───────────────────────────────────────────

def test_twilio_pair_valid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    scanner = Scanner()
    text = f"TWILIO_ACCOUNT_SID={_TWILIO_SID}\nTWILIO_AUTH_TOKEN={_TWILIO_TOKEN}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    sid = next(f for f in result.all if f.type == "twilio_account_sid")
    assert sid.verification.status == "valid"


def test_twilio_pair_invalid(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen_http_error(401))
    scanner = Scanner()
    text = f"TWILIO_ACCOUNT_SID={_TWILIO_SID}\nTWILIO_AUTH_TOKEN={_TWILIO_TOKEN}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)
    token = next(f for f in result.all if f.type == "twilio_auth_token")
    assert token.verification.status == "invalid"


# ── Scope safety: never pair across files/commits ───────────────────────────

def test_verify_findings_does_not_overwrite_a_paired_result(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    scanner = Scanner()
    text = f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n"
    result = scanner.scan(text, secrets_only=True)
    pair_and_verify(result.all)

    access = next(f for f in result.all if f.type == "aws_access_key")
    paired_result_obj = access.verification
    assert paired_result_obj.status == "valid"

    from dlp_patterns._verify import verify_findings
    verify_findings(result.all)  # must not clobber the pairing result
    assert access.verification is paired_result_obj


def test_cli_never_pairs_across_files(tmp_path, monkeypatch):
    # The regression this whole scope-requirement exists to prevent: an
    # access key in one file must never be verified against a secret key
    # from a different file just because both ended up in the same pooled
    # findings list.
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))

    (tmp_path / "a.py").write_text(f'AWS_ACCESS_KEY_ID = "{_ACCESS_KEY}"\n')
    (tmp_path / "b.py").write_text(f'AWS_SECRET_ACCESS_KEY = "{_SECRET_KEY}"\n')

    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "-m", "dlp_patterns", "--secrets-only", "--verify", "--json", str(tmp_path)],
        capture_output=True, text=True,
    )
    data = json.loads(result.stdout)
    access_finding = data["findings_by_file"]["a.py"]["CRITICAL"][0]
    secret_finding = data["findings_by_file"]["b.py"]["CRITICAL"][0]
    # Neither could find a same-file partner -> both explicitly unverifiable,
    # never silently "valid" from a cross-file mismatch.
    assert access_finding["verification"]["status"] == "unverifiable"
    assert secret_finding["verification"]["status"] == "unverifiable"


# ── Top-level dlp_patterns.verify() runs pairing too ────────────────────────

def test_top_level_verify_runs_pairing(monkeypatch):
    monkeypatch.setattr("urllib.request.urlopen", _mock_urlopen(200))
    result = dlp_patterns.scan(
        f"AWS_ACCESS_KEY_ID={_ACCESS_KEY}\nAWS_SECRET_ACCESS_KEY={_SECRET_KEY}\n",
        secrets_only=True,
    )
    dlp_patterns.verify(result)
    access = next(f for f in result.all if f.type == "aws_access_key")
    assert access.verification.status == "valid"
