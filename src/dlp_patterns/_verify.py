"""
Live secret verification — is this finding still an active credential?

Regex matching alone can't tell a live production key from one that's
already been rotated, or from a string that merely looks like a key. This
module makes a single, read-only API call per supported secret type and
reports whether the credential still authenticates — the "verified: this
secret is live" signal that tools like TruffleHog and GitGuardian lead with,
and the thing that turns "40 possible secrets" into "3 of these are real."

Design rules — read before adding a verifier:

1. **Opt-in only.** Nothing here is ever called from `scan()`. Verification
   makes a real network request using the extracted secret value — the CLI
   only does this behind an explicit `--verify` flag, and library callers
   must call `verify()` / `verify_findings()` themselves.
2. **Read-only, side-effect-free checks only.** Every verifier below hits a
   "who am I" / "list my scopes" style endpoint that authenticates the
   credential without taking any action. Never add a verifier whose request
   is itself an action a live secret could actually cause — this is why
   Slack/Discord *webhook* URLs are deliberately not verified: POSTing to a
   webhook sends a real message to someone's channel, which is not a check,
   it's a side effect. Same reasoning kept AWS/Twilio out for now: verifying
   either needs correlating two independently-matched findings (access key +
   secret key; account SID + auth token) that this scanner does not yet
   pair up, and guessing the pairing wrong risks trying real API calls
   against a mismatched value.
3. **A network error is not "invalid".** A timeout or DNS failure means we
   don't know — it goes in the "error" bucket, never "invalid". Only an
   explicit auth rejection from the provider counts as invalid.
4. Zero third-party dependencies — `urllib.request` from the standard
   library only, matching the rest of this package.
"""
from __future__ import annotations

import concurrent.futures
import json as _json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

_DEFAULT_TIMEOUT = 4.0
_USER_AGENT = "dlp-patterns-verify/1 (+https://github.com/spidercob/dlp-patterns)"


@dataclass
class VerificationResult:
    status: str          # "valid" | "invalid" | "unverifiable" | "error"
    detail: str
    checked_at: float

    def to_dict(self) -> dict:
        return {"status": self.status, "detail": self.detail, "checked_at": self.checked_at}


def _unverifiable(reason: str) -> VerificationResult:
    return VerificationResult("unverifiable", reason, time.time())


def _request(url: str, *, headers: Optional[dict] = None, timeout: float) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, headers={**(headers or {}), "User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - deliberate, read-only GET
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _bad(e: Exception) -> VerificationResult:
    return VerificationResult("error", f"network error: {e}", time.time())


# ── Individual verifiers ────────────────────────────────────────────────────
# Each takes (raw_value, timeout) and returns a VerificationResult. Keep
# these narrow and defensive — a provider changing their error format should
# degrade to "error", never to a false "invalid".

def _verify_github_token(value: str, timeout: float) -> VerificationResult:
    try:
        status, _ = _request("https://api.github.com/user",
                              headers={"Authorization": f"token {value}"}, timeout=timeout)
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "GitHub API accepted the token", time.time())
    if status == 401:
        return VerificationResult("invalid", "GitHub API rejected the token (401)", time.time())
    return VerificationResult("error", f"unexpected GitHub API status {status}", time.time())


def _verify_slack_token(value: str, timeout: float) -> VerificationResult:
    try:
        status, body = _request("https://slack.com/api/auth.test",
                                 headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
        data = _json.loads(body)
    except Exception as e:
        return _bad(e)
    if status == 200 and data.get("ok") is True:
        team = data.get("team", "unknown workspace")
        return VerificationResult("valid", f"Slack API confirmed token is active (team: {team})", time.time())
    if status == 200 and data.get("ok") is False:
        return VerificationResult("invalid", f"Slack API rejected token: {data.get('error', 'unknown')}", time.time())
    return VerificationResult("error", f"unexpected Slack API response (status {status})", time.time())


def _verify_stripe_key(value: str, timeout: float) -> VerificationResult:
    import base64 as _b64
    auth = _b64.b64encode(f"{value}:".encode()).decode()
    try:
        status, _ = _request("https://api.stripe.com/v1/balance",
                              headers={"Authorization": f"Basic {auth}"}, timeout=timeout)
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "Stripe API accepted the key", time.time())
    if status == 403:
        # Real, authenticated key — just lacking permission for this
        # particular endpoint (common for narrowly-scoped restricted keys).
        return VerificationResult("valid", "Stripe API authenticated the key (restricted scope, 403 on /balance)", time.time())
    if status == 401:
        return VerificationResult("invalid", "Stripe API rejected the key (401)", time.time())
    return VerificationResult("error", f"unexpected Stripe API status {status}", time.time())


def _verify_sendgrid_key(value: str, timeout: float) -> VerificationResult:
    try:
        status, _ = _request("https://api.sendgrid.com/v3/scopes",
                              headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "SendGrid API accepted the key", time.time())
    if status in (401, 403):
        return VerificationResult("invalid", f"SendGrid API rejected the key ({status})", time.time())
    return VerificationResult("error", f"unexpected SendGrid API status {status}", time.time())


def _verify_huggingface_token(value: str, timeout: float) -> VerificationResult:
    try:
        status, _ = _request("https://huggingface.co/api/whoami-v2",
                              headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "HuggingFace API accepted the token", time.time())
    if status == 401:
        return VerificationResult("invalid", "HuggingFace API rejected the token (401)", time.time())
    return VerificationResult("error", f"unexpected HuggingFace API status {status}", time.time())


def _verify_npm_token(value: str, timeout: float) -> VerificationResult:
    try:
        status, _ = _request("https://registry.npmjs.org/-/npm/v1/user",
                              headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "npm registry accepted the token", time.time())
    if status in (401, 403):
        return VerificationResult("invalid", f"npm registry rejected the token ({status})", time.time())
    return VerificationResult("error", f"unexpected npm registry status {status}", time.time())


def _verify_google_api_key(value: str, timeout: float) -> VerificationResult:
    # YouTube Data API's `search` endpoint is a well-known low-cost check:
    # a syntactically/actually-invalid key gets 400, a real key that simply
    # doesn't have this specific API enabled gets 403 with a distinct
    # "accessNotConfigured"/"keyInvalid" reason — only the latter means the
    # key itself is bad.
    url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&key={value}"
    try:
        status, body = _request(url, timeout=timeout)
        data = _json.loads(body) if body else {}
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "Google API accepted the key", time.time())
    reason = ""
    try:
        reason = data["error"]["errors"][0].get("reason", "")
    except Exception:
        pass
    if status == 400 or reason in ("keyInvalid", "badRequest"):
        return VerificationResult("invalid", "Google API rejected the key as invalid", time.time())
    if status == 403:
        return VerificationResult("valid", f"Google API authenticated the key (reason: {reason or 'restricted/not enabled for this API'})", time.time())
    return VerificationResult("error", f"unexpected Google API status {status}", time.time())


def _verify_telegram_token(value: str, timeout: float) -> VerificationResult:
    try:
        status, body = _request(f"https://api.telegram.org/bot{value}/getMe", timeout=timeout)
        data = _json.loads(body) if body else {}
    except Exception as e:
        return _bad(e)
    if status == 200 and data.get("ok") is True:
        return VerificationResult("valid", "Telegram API confirmed the bot token is active", time.time())
    if status == 401 or data.get("ok") is False:
        return VerificationResult("invalid", "Telegram API rejected the bot token", time.time())
    return VerificationResult("error", f"unexpected Telegram API status {status}", time.time())


def _verify_mailgun_key(value: str, timeout: float) -> VerificationResult:
    import base64 as _b64
    auth = _b64.b64encode(f"api:{value}".encode()).decode()
    try:
        status, _ = _request("https://api.mailgun.net/v3/domains",
                              headers={"Authorization": f"Basic {auth}"}, timeout=timeout)
    except Exception as e:
        return _bad(e)
    if status == 200:
        return VerificationResult("valid", "Mailgun API accepted the key", time.time())
    if status == 401:
        return VerificationResult("invalid", "Mailgun API rejected the key (401)", time.time())
    return VerificationResult("error", f"unexpected Mailgun API status {status}", time.time())


def _verify_cloudflare_token(value: str, timeout: float) -> VerificationResult:
    try:
        status, body = _request("https://api.cloudflare.com/client/v4/user/tokens/verify",
                                 headers={"Authorization": f"Bearer {value}"}, timeout=timeout)
        data = _json.loads(body) if body else {}
    except Exception as e:
        return _bad(e)
    if status == 200 and data.get("success") is True:
        return VerificationResult("valid", "Cloudflare API confirmed the token is active", time.time())
    if status in (400, 401, 403):
        return VerificationResult("invalid", f"Cloudflare API rejected the token ({status})", time.time())
    return VerificationResult("error", f"unexpected Cloudflare API status {status}", time.time())


_VERIFIERS: Dict[str, Callable[[str, float], VerificationResult]] = {
    "github_token": _verify_github_token,
    "slack_api_token": _verify_slack_token,
    "stripe_secret_key": _verify_stripe_key,
    "stripe_restricted_key": _verify_stripe_key,
    "sendgrid_api_key": _verify_sendgrid_key,
    "huggingface_token": _verify_huggingface_token,
    "npm_access_token": _verify_npm_token,
    "google_api_key": _verify_google_api_key,
    "telegram_bot_token": _verify_telegram_token,
    "mailgun_api_key": _verify_mailgun_key,
    "cloudflare_api_token": _verify_cloudflare_token,
}

# Secret-shaped finding types that --verify should give an explicit verdict
# for even when no live check exists — so "not checked" is always visible
# in the output rather than the finding just quietly having no verdict.
# Superset of _VERIFIERS; see rule 2 in the module docstring for why the
# extra entries here (webhooks, AWS, Twilio, raw private keys, ...) don't
# have a real checker.
_ANNOTATE_TYPES = frozenset(_VERIFIERS) | {
    "aws_access_key", "aws_secret_key", "aws_session_token",
    "twilio_auth_token", "twilio_account_sid",
    "slack_webhook", "discord_webhook",
    "private_key", "ssh_private_key", "pgp_private_key",
    "ed25519_private_key", "ecdsa_private_key",
    "db_connection_string", "docker_registry_auth", "azure_connection_string",
    "generic_api_key", "bearer_token", "jwt_token", "password_in_code",
    "stripe_publishable_key",
}


def verify_value(finding_type: str, value: str, *, timeout: float = _DEFAULT_TIMEOUT) -> VerificationResult:
    """Run a live check for a single (type, raw value) pair."""
    if not value:
        return _unverifiable("no raw value captured to verify")
    verifier = _VERIFIERS.get(finding_type)
    if verifier is None:
        return _unverifiable(f"no live verifier implemented for '{finding_type}'")
    return verifier(value, timeout)


def verify_findings(findings: List, *, timeout: float = _DEFAULT_TIMEOUT, max_workers: int = 8) -> None:
    """
    Verify a list of :class:`~dlp_patterns._engine.Finding` objects **in
    place**, setting ``finding.verification`` on each secret-shaped finding.

    Identical (type, raw value) pairs are checked only once even if they
    appear many times in *findings* (e.g. the same token found in five
    files, or the same secret reintroduced across many commits in
    :func:`dlp_patterns.scan_git_history`) — verification results are
    fanned back out to every matching Finding.

    Findings that aren't secret-shaped (PII, keywords, etc.) are left
    untouched (``verification`` stays ``None``) so they don't clutter
    ``--verify`` output with an irrelevant "unverifiable".
    """
    candidates = [f for f in findings if f.type in _ANNOTATE_TYPES]
    if not candidates:
        return

    unique: Dict[Tuple[str, str], List] = {}
    for f in candidates:
        unique.setdefault((f.type, f.raw), []).append(f)

    def _run(key: Tuple[str, str]) -> Tuple[Tuple[str, str], VerificationResult]:
        ftype, raw = key
        return key, verify_value(ftype, raw, timeout=timeout)

    keys = list(unique.keys())
    if len(keys) == 1:
        # Skip pool overhead for the common single-secret case.
        results = [_run(keys[0])]
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(max_workers, len(keys))) as ex:
            results = list(ex.map(_run, keys))

    for key, result in results:
        for f in unique[key]:
            f.verification = result
