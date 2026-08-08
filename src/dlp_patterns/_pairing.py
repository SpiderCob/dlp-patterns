"""
Paired-credential verification — AWS access/secret keys and Twilio SID/auth
tokens can't be verified from a single matched value the way a bearer token
can. An AWS access key ID alone doesn't authenticate anything; it needs its
secret key (and, for temporary STS credentials, a session token) alongside
it, signed together. Same idea for Twilio: an Account SID is public-ish
(it appears in URLs and client-side code), the Auth Token is the actual
secret, and verifying either one requires both.

This module finds two independently-matched findings that plausibly belong
together — because they're near each other in the *same source text* — and
verifies them as a pair with a single live check.

**Scope requirement, read before calling `pair_and_verify`:** the findings
passed in must all share one contiguous source text, because pairing is
done by comparing `Finding.position` char offsets, which are only
comparable within a single `scan()` call. Passing a list pooled across
multiple files (or multiple git commits) risks pairing an access key from
one file with an unrelated secret key from another — silently wrong, and
exactly the kind of mistake rule 2 in `_verify.py`'s module docstring warns
against. The CLI calls this once per file (directory mode) or once per
(commit, file) (history mode), never on a cross-file pooled list — see
`__main__.py`.

Same safety rules as `_verify.py`: read-only "who am I" calls only, a
network error is "error" never "invalid", zero third-party dependencies
(AWS SigV4 signing is implemented here with stdlib `hmac`/`hashlib` rather
than pulling in boto3).
"""
from __future__ import annotations

import base64 as _b64
import datetime
import hashlib
import hmac
import json as _json
import time
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from dlp_patterns._verify import VerificationResult, _bad, _unverifiable, _USER_AGENT

_MAX_PAIR_DISTANCE = 2000  # chars — generous enough for a few lines of a config/env file


def _start(finding) -> int:
    # Finding.position is "char {start}-{end}"; see _engine.py.
    return int(finding.position.split(" ")[1].split("-")[0])


def _pair_by_proximity(findings: List, type_a: str, type_b: str, max_distance: int = _MAX_PAIR_DISTANCE):
    """
    Greedily pair each *type_a* finding with its nearest not-yet-claimed
    *type_b* finding within *max_distance* characters. Findings that don't
    find a partner are left out of the result — the caller decides what
    "unpaired" means for its own reporting.
    """
    a_list = [f for f in findings if f.type == type_a and f.raw]
    b_list = [f for f in findings if f.type == type_b and f.raw]
    claimed = set()
    pairs = []
    for a in a_list:
        a_pos = _start(a)
        best_i, best_dist = None, None
        for i, b in enumerate(b_list):
            if i in claimed:
                continue
            dist = abs(_start(b) - a_pos)
            if dist <= max_distance and (best_dist is None or dist < best_dist):
                best_i, best_dist = i, dist
        if best_i is not None:
            claimed.add(best_i)
            pairs.append((a, b_list[best_i]))
    return pairs


def _nearest(candidates: List, anchor, max_distance: int = _MAX_PAIR_DISTANCE) -> Optional[object]:
    anchor_pos = _start(anchor)
    best, best_dist = None, None
    for c in candidates:
        if not c.raw:
            continue
        dist = abs(_start(c) - anchor_pos)
        if dist <= max_distance and (best_dist is None or dist < best_dist):
            best, best_dist = c, dist
    return best


# ── AWS: SigV4-signed STS GetCallerIdentity ─────────────────────────────────

def _aws_get_caller_identity(access_key: str, secret_key: str, session_token: Optional[str],
                              *, region: str = "us-east-1", timeout: float) -> VerificationResult:
    """
    The standard AWS "who am I" check, signed with AWS Signature Version 4.
    Implemented with stdlib hmac/hashlib rather than boto3 — this package
    stays at zero pip dependencies. us-east-1 is used purely as the signing
    region; STS GetCallerIdentity answers for the credential regardless of
    which region it actually belongs to.
    """
    method, service = "POST", "sts"
    host = f"sts.{region}.amazonaws.com"
    endpoint = f"https://{host}/"
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    payload = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()

    header_lines = [f"content-type:application/x-www-form-urlencoded", f"host:{host}", f"x-amz-date:{amz_date}"]
    signed_headers = "content-type;host;x-amz-date"
    if session_token:
        header_lines.append(f"x-amz-security-token:{session_token}")
        signed_headers = "content-type;host;x-amz-date;x-amz-security-token"
    canonical_headers = "\n".join(header_lines) + "\n"

    canonical_request = f"{method}\n/\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"{algorithm}\n{amz_date}\n{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
    )

    def _sign(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
        "User-Agent": _USER_AGENT,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token

    req = urllib.request.Request(endpoint, data=payload.encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - deliberate, read-only
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except Exception as e:
        return _bad(e)

    if status == 200:
        return VerificationResult("valid", "AWS STS GetCallerIdentity accepted the access key + secret key pair", time.time())

    text = body.decode(errors="replace")
    if status == 403 and "InvalidClientTokenId" in text:
        return VerificationResult("invalid", "AWS rejected the access key ID (InvalidClientTokenId — revoked or never valid)", time.time())
    if status == 403 and "SignatureDoesNotMatch" in text:
        return VerificationResult("invalid", "AWS rejected the secret key (SignatureDoesNotMatch — wrong pairing, or the secret was rotated)", time.time())
    if status == 403 and "TokenRefreshRequired" in text:
        return VerificationResult("invalid", "AWS rejected the session token (expired or invalid)", time.time())
    if status == 403:
        return VerificationResult("invalid", "AWS STS rejected the credential pair (403)", time.time())
    return VerificationResult("error", f"unexpected AWS STS status {status}", time.time())


def _verify_aws_pair(access: object, secret: object, session_tokens: List, *, timeout: float) -> VerificationResult:
    if access.raw.startswith("ASIA"):
        # Temporary STS credentials — signing without the session token
        # produces a signature AWS will reject even for a fully live
        # credential, which would misreport a real secret as "invalid".
        # Safer to say we can't check than to guess wrong.
        session = _nearest(session_tokens, access)
        if session is None:
            return _unverifiable(
                "ASIA-prefixed (temporary) access key requires a paired aws_session_token to verify; none found nearby"
            )
        return _aws_get_caller_identity(access.raw, secret.raw, session.raw, timeout=timeout)
    return _aws_get_caller_identity(access.raw, secret.raw, None, timeout=timeout)


# ── Twilio: Basic-auth "get account" check ──────────────────────────────────

def _verify_twilio_pair(sid: str, token: str, *, timeout: float) -> VerificationResult:
    auth = _b64.b64encode(f"{sid}:{token}".encode()).decode()
    req = urllib.request.Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json",
        headers={"Authorization": f"Basic {auth}", "User-Agent": _USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - deliberate, read-only GET
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except Exception as e:
        return _bad(e)

    if status == 200:
        return VerificationResult("valid", "Twilio API accepted the Account SID + Auth Token pair", time.time())
    if status == 401:
        return VerificationResult("invalid", "Twilio API rejected the SID/token pair (401)", time.time())
    return VerificationResult("error", f"unexpected Twilio API status {status}", time.time())


# ── Public entry point ───────────────────────────────────────────────────────

def pair_and_verify(findings: List, *, timeout: float = 4.0) -> None:
    """
    Find AWS access/secret key pairs and Twilio SID/auth-token pairs within
    *findings* and verify each pair with one live check, setting
    ``.verification`` **in place** on both findings in a pair.

    Only sets ``.verification`` on findings it successfully pairs — an
    access key with no nearby secret key (or vice versa) is left alone so
    :func:`dlp_patterns.verify_findings` can give it its own "no paired X
    found nearby" verdict afterward, rather than this function guessing.

    See the module docstring for the scope requirement: every finding
    passed in must come from the same source text.
    """
    session_tokens = [f for f in findings if f.type == "aws_session_token" and f.raw]

    for access, secret in _pair_by_proximity(findings, "aws_access_key", "aws_secret_key"):
        result = _verify_aws_pair(access, secret, session_tokens, timeout=timeout)
        access.verification = result
        secret.verification = result

    for sid, token in _pair_by_proximity(findings, "twilio_account_sid", "twilio_auth_token"):
        result = _verify_twilio_pair(sid.raw, token.raw, timeout=timeout)
        sid.verification = result
        token.verification = result
