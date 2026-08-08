"""Tests for dlp-patterns."""
import json
import os
import subprocess
import sys

import pytest
import dlp_patterns
from dlp_patterns import Scanner, ScanResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def scanner():
    return Scanner()


# ── Credit card ───────────────────────────────────────────────────────────────

def test_credit_card_visa(scanner):
    r = scanner.scan("Payment: 4111 1111 1111 1111 exp 09/27")
    assert any(f.type == "credit_card" for f in r.critical)

def test_credit_card_mastercard(scanner):
    r = scanner.scan("card: 5500 0000 0000 0004")
    assert any(f.type == "credit_card" for f in r.critical)

def test_credit_card_invalid_luhn_rejected(scanner):
    r = scanner.scan("bad card: 4111 1111 1111 1112")
    assert not any(f.type == "credit_card" for f in r.critical)

def test_credit_card_test_number_flagged(scanner):
    # Luhn-valid test cards still detected (caller decides how to handle)
    r = scanner.scan("Luhn test card: 4111111111111111")
    assert any(f.type == "credit_card" for f in r.critical)


# ── SSN ───────────────────────────────────────────────────────────────────────

def test_ssn_valid(scanner):
    r = scanner.scan("SSN: 432-78-9012")
    assert any(f.type == "ssn" for f in r.critical)

def test_ssn_area_000_rejected(scanner):
    r = scanner.scan("SSN: 000-12-3456")
    assert not any(f.type == "ssn" for f in r.critical)

def test_ssn_area_666_rejected(scanner):
    r = scanner.scan("SSN: 666-12-3456")
    assert not any(f.type == "ssn" for f in r.critical)

def test_ssn_area_900_rejected(scanner):
    r = scanner.scan("SSN: 900-12-3456")
    assert not any(f.type == "ssn" for f in r.critical)

def test_ssn_repeated_digits_rejected(scanner):
    r = scanner.scan("SSN: 111-11-1111")
    assert not any(f.type == "ssn" for f in r.critical)


# ── AWS keys ──────────────────────────────────────────────────────────────────

def test_aws_access_key(scanner):
    r = scanner.scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
    assert any(f.type == "aws_access_key" for f in r.critical)

def test_aws_asia_prefix(scanner):
    # ASIA + exactly 16 uppercase/digit chars (total 20), followed by comma for word boundary
    r = scanner.scan("key: ASIAIOSFODNN7EXAMPLE,")
    assert any(f.type == "aws_access_key" for f in r.critical)


# ── GitHub token ─────────────────────────────────────────────────────────────

def test_github_pat(scanner):
    # ghp_ + exactly 36 alphanumeric chars (high entropy so entropy gate passes)
    token = "ghp_9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX"
    assert len(token) == 40  # ghp_(4) + 36
    r = scanner.scan(f"GITHUB_TOKEN={token}")
    assert any(f.type == "github_token" for f in r.critical)


# ── Email ─────────────────────────────────────────────────────────────────────

def test_email_detected(scanner):
    r = scanner.scan("Contact alice@company.com for details")
    assert any(f.type == "email" for f in r.medium)

def test_email_masked(scanner):
    r = scanner.scan("alice@company.com")
    f = next(x for x in r.medium if x.type == "email")
    assert "***" in f.value
    assert "@company.com" in f.value


# ── JWT ───────────────────────────────────────────────────────────────────────

def test_jwt_valid(scanner):
    # eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 = {"alg":"HS256","typ":"JWT"}
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    r = scanner.scan(f"Authorization: Bearer {token}")
    assert any(f.type in ("jwt_token", "bearer_token") for f in r.critical + r.high)

def test_jwt_invalid_structure_rejected(scanner):
    r = scanner.scan("eyJhbGciOiJub3Rh.broken")
    assert not any(f.type == "jwt_token" for f in r.all)


# ── Private keys ──────────────────────────────────────────────────────────────

def test_rsa_private_key(scanner):
    r = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----")
    assert any(f.type == "private_key" for f in r.critical)

def test_ssh_private_key(scanner):
    r = scanner.scan("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END OPENSSH PRIVATE KEY-----")
    assert any(f.type == "ssh_private_key" for f in r.critical)


# ── DB connection strings ─────────────────────────────────────────────────────

def test_postgres_connection_string(scanner):
    r = scanner.scan('DATABASE_URL = "postgresql://admin:s3cr3t@prod-db.internal:5432/mydb"')
    assert any(f.type == "db_connection_string" for f in r.critical)

def test_mongodb_connection_string(scanner):
    r = scanner.scan("uri = mongodb://root:password@mongo:27017/prod")
    assert any(f.type == "db_connection_string" for f in r.critical)


# ── Cloud keys ────────────────────────────────────────────────────────────────

def test_stripe_secret_key(scanner):
    r = scanner.scan("STRIPE_SECRET_KEY=" + "sk_live_" + "abcdefghijklmnopqrstuvwx")
    assert any(f.type == "stripe_secret_key" for f in r.critical)

def test_sendgrid_api_key(scanner):
    # SG. + 22+ chars + . + 43+ chars (pattern requirement)
    seg1 = "xK9mP2nQ4rT6vW8yZeJ3nA"   # 22 chars
    seg2 = "aB3cD5eF7gH9iJ1kL2mN4oP6qR8sT0uV3wX5yZ7bC9D"  # 43 chars
    key = f"SG.{seg1}.{seg2}"
    r = scanner.scan(f"SENDGRID_KEY={key}")
    assert any(f.type == "sendgrid_api_key" for f in r.critical)

def test_google_api_key(scanner):
    # AIza + exactly 35 chars = 39 total
    r = scanner.scan("GOOGLE_KEY=AIzaSyD3Kp9mQr7Wt2Xv5Nb8Hc1Jf4Le6Og0PuQ")
    assert any(f.type == "google_api_key" for f in r.critical)

def test_slack_token(scanner):
    r = scanner.scan("token = " + "xoxb-" + "123456789-abcdefghijklmnop")
    assert any(f.type == "slack_api_token" for f in r.critical)

def test_discord_webhook(scanner):
    url = "https://discord.com/api/webhooks/123456789012345678/" + "a" * 68
    r = scanner.scan(f"webhook = {url}")
    assert any(f.type == "discord_webhook" for f in r.high)

def test_azure_connection_string(scanner):
    cs = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 64
    r = scanner.scan(cs)
    assert any(f.type == "azure_connection_string" for f in r.critical)


# ── Healthcare ────────────────────────────────────────────────────────────────

def test_medical_record_number(scanner):
    r = scanner.scan("Patient ID: MRN 123456789")
    assert any(f.type == "medical_record" for f in r.critical)

def test_icd10_requires_context(scanner):
    r_no_ctx = scanner.scan("The code is E11.9")
    r_with_ctx = scanner.scan("Diagnosis ICD-10: E11.9 Type 2 Diabetes")
    # No context → should NOT fire (requires_context_keywords)
    assert not any(f.type == "icd10_code" for f in r_no_ctx.all)
    # With context → should fire
    assert any(f.type == "icd10_code" for f in r_with_ctx.all)


# ── Redaction ─────────────────────────────────────────────────────────────────

def test_redact_credit_card():
    result = dlp_patterns.redact("CC: 4111 1111 1111 1111")
    assert "4111" not in result
    assert "[REDACTED: Credit Card Number]" in result

def test_redact_email():
    result = dlp_patterns.redact("Email alice@corp.com for help")
    assert "alice@corp.com" not in result
    assert "REDACTED" in result

def test_redact_preserves_surrounding_text():
    result = dlp_patterns.redact("Hello, SSN 432-78-9012 is invalid")
    assert result.startswith("Hello, ")
    assert result.endswith(" is invalid")

def test_redact_no_overlap():
    # Multiple patterns in the same text — no doubled replacements
    text = "alice@corp.com CC 4111 1111 1111 1111"
    result = dlp_patterns.redact(text)
    assert result.count("REDACTED") >= 2


# ── Fuzz ──────────────────────────────────────────────────────────────────────

def test_fuzz_without_faker_falls_back():
    # Even without faker installed the function must not raise
    result = dlp_patterns.fuzz("SSN 432-78-9012")
    assert "432-78-9012" not in result

def test_fuzz_with_faker():
    pytest.importorskip("faker")
    original = "alice@corp.com"
    result = dlp_patterns.fuzz(original)
    assert original not in result


# ── Module-level API ──────────────────────────────────────────────────────────

def test_module_scan_returns_scan_result():
    r = dlp_patterns.scan("test@example.com")
    assert isinstance(r, ScanResult)

def test_scan_result_has_findings():
    r = dlp_patterns.scan("4111 1111 1111 1111")
    assert r.has_findings
    assert r.highest_severity == "CRITICAL"

def test_scan_result_empty():
    r = dlp_patterns.scan("The quick brown fox jumps over the lazy dog.")
    assert not r.has_findings
    assert r.highest_severity is None

def test_scan_result_to_dict():
    r = dlp_patterns.scan("4111 1111 1111 1111")
    d = r.to_dict()
    assert "CRITICAL" in d
    assert isinstance(d["CRITICAL"], list)

def test_secrets_only_skips_pii():
    text = "alice@corp.com AKIAIOSFODNN7EXAMPLE"
    r_all     = dlp_patterns.scan(text)
    r_secrets = dlp_patterns.scan(text, secrets_only=True)
    assert any(f.type == "email" for f in r_all.medium)
    assert not any(f.type == "email" for f in r_secrets.all)
    assert any(f.type == "aws_access_key" for f in r_secrets.critical)


# ── Context scoring ───────────────────────────────────────────────────────────

def test_context_score_boosted_near_production_keyword():
    scanner = Scanner()
    text = "production aws_access_key = AKIAIOSFODNN7EXAMPLE"
    r = scanner.scan(text)
    findings = [f for f in r.critical if f.type == "aws_access_key"]
    assert findings
    assert findings[0].context_score > 0.5

def test_context_score_penalised_in_docs():
    scanner = Scanner()
    text = "example placeholder: AKIAIOSFODNN7EXAMPLE (replace with your key)"
    r = scanner.scan(text)
    findings = [f for f in r.critical if f.type == "aws_access_key"]
    if findings:
        assert findings[0].context_score < 0.5


# ── Entropy gating ────────────────────────────────────────────────────────────

def test_low_entropy_secret_rejected():
    # aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa is 40 chars but no entropy
    r = dlp_patterns.scan("key = " + "a" * 40)
    assert not any(f.type == "aws_secret_key" for f in r.all)

def test_version_exported():
    assert dlp_patterns.__version__ == "0.4.0"


# ── CLI: directory scanning ─────────────────────────────────────────────────

def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "dlp_patterns", *args],
        capture_output=True, text=True,
    )


def test_cli_directory_finds_secret_in_nested_file(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    (tmp_path / "src" / "clean.py").write_text('print("hello")')

    result = _run_cli("--secrets-only", "--json", str(tmp_path))
    data = json.loads(result.stdout)

    assert result.returncode == 1
    assert data["mode"] == "directory"
    assert data["files_scanned"] == 2
    assert data["highest_severity"] == "CRITICAL"
    assert "src/config.py" in data["findings_by_file"]
    assert "src/clean.py" not in data["findings_by_file"]


def test_cli_directory_skips_lockfiles(tmp_path):
    # package-lock.json integrity hashes false-positive against secret
    # regexes (base64-looking strings) — must be skipped, not flagged.
    (tmp_path / "package-lock.json").write_text(
        '{"integrity": "sha512-UrcABB+4bUrFABwbluTIBErXwvbsU/V7TZWfmbgJfbkwiBuziS9gxdODUyuiecfdGQ85jglMW6juS3+z5TsKLw=="}'
    )
    result = _run_cli("--secrets-only", "--json", str(tmp_path))
    data = json.loads(result.stdout)

    assert result.returncode == 0
    assert data["files_scanned"] == 0
    assert data["findings_by_file"] == {}


def test_cli_directory_skips_common_vendor_dirs(tmp_path):
    (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
    (tmp_path / "node_modules" / "pkg" / "index.js").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')

    result = _run_cli("--secrets-only", "--json", str(tmp_path))
    data = json.loads(result.stdout)

    assert result.returncode == 0
    assert data["files_scanned"] == 0


def test_cli_directory_skips_binary_files(tmp_path):
    (tmp_path / "binary.bin").write_bytes(b"\x00\x01\x02AKIAIOSFODNN7EXAMPLE")
    result = _run_cli("--secrets-only", "--json", str(tmp_path))
    data = json.loads(result.stdout)

    assert result.returncode == 0
    assert data["files_scanned"] == 0


def test_cli_directory_clean_exits_zero(tmp_path):
    (tmp_path / "a.py").write_text('print("nothing sensitive")')
    result = _run_cli("--secrets-only", str(tmp_path))
    assert result.returncode == 0
    assert "No findings" in result.stdout


def test_cli_redact_rejects_directory(tmp_path):
    result = _run_cli("--redact", str(tmp_path))
    assert result.returncode == 2


def test_cli_single_file_still_works(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    result = _run_cli("--secrets-only", str(f))
    assert result.returncode == 1
    assert "aws_access_key" in result.stdout


# ── bearer_token minimum length ─────────────────────────────────────────────

def test_bearer_token_short_english_phrase_not_flagged(scanner):
    # "Bearer token" (12 chars incl. the word "token") used to slip past
    # entropy gating entirely (full match < _MIN_ENTROPY_LEN) and get
    # reported CRITICAL unconditionally.
    r = scanner.scan("Every request needs a Bearer token in the Authorization header.")
    assert not any(f.type == "bearer_token" for f in r.all)

def test_bearer_token_short_fixture_not_flagged(scanner):
    r = scanner.scan("Authorization: Bearer test-token")
    assert not any(f.type == "bearer_token" for f in r.all)

def test_bearer_token_real_length_still_flagged(scanner):
    # Built via concatenation (not one contiguous literal) so this fixture,
    # designed to score high enough to still trip a --min-confidence gate,
    # doesn't itself trip one when this file gets committed.
    token = "sk_live_" + "9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX"
    r = scanner.scan("Authorization: Bearer " + token)
    assert any(f.type == "bearer_token" for f in r.critical)


# ── raw/value use the capturing group, not the whole match ──────────────────
# A handful of patterns match a literal label around the secret itself
# ("Bearer ", "TWILIO_AUTH_TOKEN=", "api_key="). Using m.group(0) (the whole
# match, label included) as the value meant --verify would send the label
# text to the provider along with the real secret, and the masked `value`
# shown to users was junk like "Bearer...***" instead of a piece of the
# actual token.

def test_bearer_token_value_excludes_the_label(scanner):
    token = "sk_live_" + "9aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX"
    r = scanner.scan("Authorization: Bearer " + token, secrets_only=True)
    f = next(x for x in r.critical if x.type == "bearer_token")
    assert f.raw == token
    assert not f.raw.startswith("Bearer")
    assert not f.value.startswith("Bearer")

def test_twilio_auth_token_value_excludes_the_label(scanner):
    token = "0123456789abcdef0123456789abcdef"
    r = scanner.scan(f"TWILIO_AUTH_TOKEN={token}", secrets_only=True)
    f = next(x for x in r.critical if x.type == "twilio_auth_token")
    assert f.raw == token
    assert "TWILIO_AUTH_TOKEN" not in f.raw

def test_generic_api_key_value_excludes_the_label(scanner):
    value = "9aB3cD4eF5gH6iJ7kL8mN9oP0" + "qR1sT2uV3wXyZ01"
    r = scanner.scan(f'api_key = "{value}"', secrets_only=True)
    f = next(x for x in r.critical if x.type == "generic_api_key")
    assert f.raw == value

def test_aws_access_key_raw_unaffected_by_group_fix(scanner):
    # Sanity check the fix is a no-op for patterns with no separate label —
    # group(1) and group(0) were already identical there. Built via
    # concatenation so this doesn't itself trip a --min-confidence-gated
    # commit of this file.
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    r = scanner.scan(key, secrets_only=True)
    f = next(x for x in r.critical if x.type == "aws_access_key")
    assert f.raw == key


# ── sensitive_keyword skipped in secrets_only mode ──────────────────────────

def test_sensitive_keyword_skipped_in_secrets_only_mode():
    # secrets_only means "just check for credential values" — bare English
    # words like "token"/"secret"/"password" (and CRITICAL ones like
    # "private key"/"root password") aren't credential values, they're
    # compliance-document vocabulary, and are noise on any auth codebase.
    text = "This module handles password and token authorization for the private API."
    r_secrets = dlp_patterns.scan(text, secrets_only=True)
    r_full = dlp_patterns.scan(text, secrets_only=False)
    assert not any(f.type == "sensitive_keyword" for f in r_secrets.all)
    assert any(f.type == "sensitive_keyword" for f in r_full.all)


# ── CLI: --min-confidence gates the exit code on context_score ─────────────

def test_min_confidence_default_matches_old_any_critical_behavior(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    result = _run_cli("--secrets-only", str(f))
    assert result.returncode == 1  # unchanged from before --min-confidence existed

def test_min_confidence_suppresses_low_score_exit_code(tmp_path):
    f = tmp_path / "test_fixtures.py"
    f.write_text('# example placeholder for tests, not a real key\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # fake test fixture\n')
    default_result = _run_cli("--secrets-only", str(f))
    gated_result = _run_cli("--secrets-only", "--min-confidence", "0.6", str(f))
    assert default_result.returncode == 1
    assert gated_result.returncode == 0
    assert "aws_access_key" in gated_result.stdout  # still reported, just doesn't fail the exit code

def test_min_confidence_still_blocks_high_score(tmp_path):
    # Same reasoning as test_bearer_token_real_length_still_flagged above:
    # built via concatenation so this deliberately-high-scoring fixture
    # doesn't itself trip a --min-confidence-gated commit of this file.
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    f = tmp_path / "prod_config.py"
    f.write_text('production aws_access_key = "' + key + '"  # real deploy secret\n')
    result = _run_cli("--secrets-only", "--min-confidence", "0.5", str(f))
    assert result.returncode == 1

def test_min_confidence_directory_mode(tmp_path):
    (tmp_path / "fixture.py").write_text('# example placeholder\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # fake test\n')
    gated_result = _run_cli("--secrets-only", "--min-confidence", "0.9", str(tmp_path))
    assert gated_result.returncode == 0

def test_min_confidence_history_mode(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ, "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@example.com"}
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, env=env, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, env=env, check=True)
    subprocess.run(["git", "config", "user.name", "T"], cwd=repo, env=env, check=True)
    (repo / "fixture.py").write_text('# example placeholder for a fake test key\nAWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    subprocess.run(["git", "add", "."], cwd=repo, env=env, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "add example fixture"], cwd=repo, env=env, check=True)

    default_result = _run_cli("--history", str(repo))
    gated_result = _run_cli("--history", "--min-confidence", "0.9", str(repo))
    assert default_result.returncode == 1
    assert gated_result.returncode == 0
