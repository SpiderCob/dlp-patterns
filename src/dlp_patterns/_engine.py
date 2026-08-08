"""
DLP Pattern Engine — core scanning logic.
Extracted from the Spidercob DLP platform (https://spidercob.com).
"""
from __future__ import annotations

import base64
import collections
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

# ── Entropy constants ─────────────────────────────────────────────────────────
_ENTROPY_WINDOW    = 32    # sliding window width (chars)
_MIN_ENTROPY_LEN   = 16    # skip entropy check for shorter strings
_ENTROPY_THRESHOLD = 3.5   # below this → likely not a secret
_COMMENT_PENALTY   = 4.2   # raise threshold when match is inside a comment

_BASE64_RE       = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
_BLOCK_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)


@dataclass
class Finding:
    type: str
    description: str
    value: str           # masked
    position: str
    severity: str
    context: str
    context_score: float
    context_score_reasons: List[str] = field(default_factory=list)
    context_keywords_found: List[str] = field(default_factory=list)
    # Unmasked matched text. Kept off of repr() and out of to_dict() on
    # purpose — this exists only so an explicit, opt-in verification pass
    # (see dlp_patterns._verify) has something to check against. Nothing in
    # this package ever prints, logs, or serializes `raw` on its own.
    raw: str = field(default="", repr=False, compare=False)
    # Populated only when a verification pass has actually run (see
    # dlp_patterns.verify / --verify). None means "not checked", not "safe".
    verification: Optional["object"] = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "description": self.description,
            "value": self.value,
            "position": self.position,
            "severity": self.severity,
            "context": self.context,
            "context_score": self.context_score,
            "context_score_reasons": self.context_score_reasons,
            "context_keywords_found": self.context_keywords_found,
        }
        if self.verification is not None:
            d["verification"] = self.verification.to_dict()
        return d


@dataclass
class ScanResult:
    """Structured result returned by :meth:`Scanner.scan`."""
    critical: List[Finding] = field(default_factory=list)
    high:     List[Finding] = field(default_factory=list)
    medium:   List[Finding] = field(default_factory=list)
    low:      List[Finding] = field(default_factory=list)
    info:     List[Finding] = field(default_factory=list)
    elapsed_ms: float = 0.0

    @property
    def all(self) -> List[Finding]:
        return self.critical + self.high + self.medium + self.low + self.info

    @property
    def has_findings(self) -> bool:
        return bool(self.all)

    @property
    def highest_severity(self) -> Optional[str]:
        for sev, lst in (("CRITICAL", self.critical), ("HIGH", self.high),
                         ("MEDIUM", self.medium), ("LOW", self.low)):
            if lst:
                return sev
        return None

    def to_dict(self) -> dict:
        return {
            "CRITICAL": [f.to_dict() for f in self.critical],
            "HIGH":     [f.to_dict() for f in self.high],
            "MEDIUM":   [f.to_dict() for f in self.medium],
            "LOW":      [f.to_dict() for f in self.low],
            "INFO":     [f.to_dict() for f in self.info],
            "elapsed_ms": self.elapsed_ms,
        }


class Scanner:
    """
    Regex-based DLP pattern scanner with:
    - 50+ pattern categories (PII, secrets, cloud keys, healthcare, crypto)
    - Luhn / SSN / JWT validators to reduce false positives
    - Shannon entropy gating for generic secret patterns
    - Context-window scoring (proximity boost + code-block penalty)
    """

    def __init__(self) -> None:
        self._patterns: Dict[str, dict] = self._build_patterns()
        self._sensitive_keywords: Dict[str, List[str]] = {
            "CRITICAL": [
                "confidential", "top secret", "classified", "secret clearance",
                "private key", "master password", "root password", "admin password",
            ],
            "HIGH": [
                "internal use only", "not for distribution", "proprietary",
                "trade secret", "sensitive data", "do not share",
            ],
            "MEDIUM": [
                "password", "credential", "authentication", "authorization",
                "token", "secret", "private",
            ],
        }
        # Patterns that require entropy gating
        self._secret_types = {
            "aws_access_key", "aws_secret_key", "github_token", "generic_api_key",
            "bearer_token", "jwt_token", "db_connection_string", "password_in_code",
            "slack_api_token", "google_api_key", "aws_session_token",
            "stripe_secret_key", "stripe_publishable_key", "stripe_restricted_key",
            "sendgrid_api_key", "twilio_auth_token", "twilio_account_sid",
            "huggingface_token", "npm_access_token", "cloudflare_api_token",
        }

    # ── Pattern registry ──────────────────────────────────────────────────────

    def _build_patterns(self) -> Dict[str, dict]:
        p: Dict[str, dict] = {}

        # Financial
        p["credit_card"] = dict(
            pattern=r'\b(?:\d{4}[-\s]?){3}\d{4}\b', severity="CRITICAL",
            description="Credit Card Number", validator=self._validate_credit_card,
        )
        p["ssn"] = dict(
            pattern=r'\b\d{3}-\d{2}-\d{4}\b', severity="CRITICAL",
            description="Social Security Number", validator=self._validate_ssn,
        )
        p["bank_account"] = dict(
            pattern=r'\b\d{8,17}\b', severity="HIGH",
            description="Bank Account Number",
        )
        p["iban"] = dict(
            pattern=r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
            severity="HIGH", description="IBAN Number",
        )
        p["routing_number"] = dict(
            pattern=r'\b\d{9}\b', severity="HIGH",
            description="Bank Routing Number",
        )

        # Personal identifiers
        p["email"] = dict(
            pattern=r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            severity="MEDIUM", description="Email Address",
        )
        p["phone_us"] = dict(
            pattern=r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
            severity="MEDIUM", description="US Phone Number",
        )
        p["passport"] = dict(
            pattern=r'\b[A-Z]{1,2}\d{6,9}\b', severity="CRITICAL",
            description="Passport Number",
        )
        p["drivers_license"] = dict(
            pattern=r'\b[A-Z]{1,2}\d{5,8}\b', severity="HIGH",
            description="Driver's License",
        )
        p["medical_record"] = dict(
            pattern=(r'\b(?:MRN|MR#|Medical Record(?:\s+(?:No|Number|#))?'
                     r'|Patient\s+(?:ID|#|Account)|Pt\.?\s+(?:ID|#))[\s:#-]*(\d{6,12})\b'),
            severity="CRITICAL", description="Medical Record / Patient ID",
        )
        p["dob"] = dict(
            pattern=r'\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12][0-9]|3[01])[/-](?:19|20)\d{2}\b',
            severity="MEDIUM", description="Date of Birth (MM/DD/YYYY)",
        )

        # Healthcare / HIPAA
        p["npi_number"] = dict(
            pattern=r'\b(?:NPI|National Provider(?:\s+Identifier)?)[\s:#-]*(\d{10})\b',
            severity="HIGH", description="National Provider Identifier (NPI)",
            context_keywords=["npi", "provider", "physician", "prescriber", "clinic", "hospital"],
        )
        p["icd10_code"] = dict(
            pattern=r'\b[A-Z]\d{2}(?:\.\d{1,4})?\b', severity="HIGH",
            description="ICD-10 Diagnosis Code",
            context_keywords=["diagnosis", "icd", "icd-10", "icd10", "dx", "condition",
                              "disease", "disorder", "admit", "discharge"],
            requires_context_keywords=True,
        )
        p["dea_number"] = dict(
            pattern=r'\b[A-Z]{2}\d{7}\b', severity="HIGH",
            description="DEA Registration Number",
            context_keywords=["dea", "drug enforcement", "schedule", "controlled",
                              "prescriber", "prescription", "registrant"],
            requires_context_keywords=True,
        )
        p["ndc_code"] = dict(
            pattern=r'\b\d{4,5}-\d{3,4}-\d{1,2}\b', severity="MEDIUM",
            description="National Drug Code (NDC)",
            context_keywords=["ndc", "drug", "medication", "pharmacy", "rx",
                              "prescription", "dispensed", "dose", "tablet", "capsule"],
            requires_context_keywords=True,
        )

        # Network / infrastructure
        p["ipv4"] = dict(
            pattern=(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                     r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                     r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                     r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
            severity="LOW", description="IPv4 Address",
        )
        p["ipv6"] = dict(
            pattern=r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
            severity="LOW", description="IPv6 Address",
        )
        p["mac_address"] = dict(
            pattern=r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b',
            severity="MEDIUM", description="MAC Address",
        )

        # Secrets / API keys
        p["aws_access_key"] = dict(
            pattern=r'\b((?:AKIA|ASIA)[0-9A-Z]{16})\b', severity="CRITICAL",
            description="AWS Access Key ID",
            context_keywords=["aws", "access_key", "secret", "boto", "credentials", "amazon"],
        )
        p["aws_secret_key"] = dict(
            pattern=r'\b[A-Za-z0-9/+=]{40}\b', severity="CRITICAL",
            description="AWS Secret Access Key",
        )
        p["aws_session_token"] = dict(
            pattern=r'\b(FQoGZXRfYXJj[a-zA-Z0-9/+=]{20,})\b', severity="HIGH",
            description="AWS Session Token",
            context_keywords=["aws", "session", "token", "credentials"],
        )
        p["github_token"] = dict(
            pattern=r'\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b',
            severity="CRITICAL", description="GitHub Personal Access Token",
        )
        p["generic_api_key"] = dict(
            pattern=r'\b(?:api[_-]?key|apikey)[\s=:]+["\']?([a-zA-Z0-9_\-]{20,})["\']?\b',
            severity="CRITICAL", description="Generic API Key",
        )
        p["slack_api_token"] = dict(
            pattern=r'\b(xox[baprs]-[a-zA-Z0-9-]{10,})\b', severity="CRITICAL",
            description="Slack API Token",
        )
        p["slack_webhook"] = dict(
            pattern=r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
            severity="CRITICAL", description="Slack Webhook URL",
        )
        p["google_api_key"] = dict(
            pattern=r'\b(AIza[0-9A-Za-z_-]{35})\b', severity="CRITICAL",
            description="Google API Key",
        )
        p["bearer_token"] = dict(
            # {20,} (not the old unbounded +) keeps the *whole* match — "Bearer "
            # plus the captured token — comfortably above _MIN_ENTROPY_LEN, so
            # short matches can no longer slip past entropy gating entirely.
            # Without this, case-insensitive "bearer" plus any short run of
            # word characters (English prose like "a bearer token grant", or a
            # doc/test fixture like "Bearer test-token") matched and reported
            # CRITICAL unconditionally.
            pattern=r'\bBearer\s+([a-zA-Z0-9\-._~+/]{20,}=*)\b', severity="CRITICAL",
            description="Bearer Token",
        )
        p["jwt_token"] = dict(
            pattern=r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b',
            severity="HIGH", description="JWT Token", validator=self._validate_jwt,
        )

        # Cryptographic materials
        p["private_key"] = dict(
            pattern=r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            severity="CRITICAL", description="Private Key (PEM)",
        )
        p["ssh_private_key"] = dict(
            pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
            severity="CRITICAL", description="SSH Private Key",
        )
        p["pgp_private_key"] = dict(
            pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            severity="CRITICAL", description="PGP Private Key",
        )
        p["ed25519_private_key"] = dict(
            pattern=r'-----BEGIN (?:ED25519 )?PRIVATE KEY-----',
            severity="CRITICAL", description="Ed25519 Private Key",
        )
        p["ecdsa_private_key"] = dict(
            pattern=r'-----BEGIN EC PRIVATE KEY-----',
            severity="CRITICAL", description="ECDSA Private Key",
        )
        p["certificate"] = dict(
            pattern=r'-----BEGIN CERTIFICATE-----',
            severity="MEDIUM", description="X.509 Certificate",
        )

        # Database credentials
        p["db_connection_string"] = dict(
            pattern=r'(?:postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[\w.-]+(?::\d+)?/[\w-]+',
            severity="CRITICAL", description="Database Connection String",
        )
        p["password_in_code"] = dict(
            pattern=r'(?:password|passwd|pwd)[\s=:]+["\']([^"\']{4,})["\']',
            severity="HIGH", description="Hardcoded Password",
        )

        # Cloud / SaaS keys
        p["stripe_secret_key"] = dict(
            pattern=r'\b(sk_(?:live|test)_[0-9a-zA-Z]{24,})\b', severity="CRITICAL",
            description="Stripe Secret Key",
            context_keywords=["stripe", "payment", "billing", "charge", "invoice"],
        )
        p["stripe_publishable_key"] = dict(
            pattern=r'\b(pk_(?:live|test)_[0-9a-zA-Z]{24,})\b', severity="HIGH",
            description="Stripe Publishable Key",
            context_keywords=["stripe", "payment", "publishable"],
        )
        p["stripe_restricted_key"] = dict(
            pattern=r'\b(rk_(?:live|test)_[0-9a-zA-Z]{24,})\b', severity="CRITICAL",
            description="Stripe Restricted Key",
            context_keywords=["stripe", "restricted"],
        )
        # In _secret_types (below) even though a SID alone isn't secret —
        # Twilio's actual secret is the paired auth token, but --verify's
        # AWS/Twilio pairing (dlp_patterns._pairing) needs the SID to be
        # found at all. Excluding it from secrets_only scans would mean a
        # leaked auth token could never be verified in the one CLI mode
        # (--secrets-only) most CI usage actually runs.
        p["twilio_account_sid"] = dict(
            pattern=r'\b(AC[a-f0-9]{32})\b', severity="HIGH",
            description="Twilio Account SID",
            context_keywords=["twilio", "account_sid", "sms", "call"],
        )
        p["twilio_auth_token"] = dict(
            pattern=r'\b(?:twilio[_\s]?auth[_\s]?token|authtoken)[\s=:\"\']+([a-f0-9]{32})\b',
            severity="CRITICAL", description="Twilio Auth Token",
            context_keywords=["twilio", "auth_token", "authtoken"],
            requires_context_keywords=True,
        )
        p["sendgrid_api_key"] = dict(
            pattern=r'\b(SG\.[a-zA-Z0-9_-]{22,}\.[a-zA-Z0-9_-]{43,})\b',
            severity="CRITICAL", description="SendGrid API Key",
        )
        p["mailgun_api_key"] = dict(
            pattern=r'\b(key-[a-f0-9]{32})\b', severity="CRITICAL",
            description="Mailgun API Key",
            context_keywords=["mailgun", "api_key", "mg.", "smtp"],
            requires_context_keywords=True,
        )
        p["huggingface_token"] = dict(
            pattern=r'\b(hf_[a-zA-Z0-9]{37,})\b', severity="HIGH",
            description="HuggingFace Access Token",
        )
        p["npm_access_token"] = dict(
            pattern=r'\b(npm_[a-zA-Z0-9]{36,})\b', severity="HIGH",
            description="NPM Access Token",
        )
        p["cloudflare_api_token"] = dict(
            pattern=r'\b(cf_[a-zA-Z0-9]{37,}|[A-Za-z0-9_-]{40})\b', severity="HIGH",
            description="Cloudflare API Token",
            context_keywords=["cloudflare", "cf_token", "x-auth-key", "x-auth-email"],
            requires_context_keywords=True,
        )
        p["azure_sas_token"] = dict(
            pattern=r'\b(?:SharedAccessSignature|sig=[a-zA-Z0-9%+/]{20,}[&;])',
            severity="CRITICAL", description="Azure SAS Token",
            context_keywords=["azure", "blob", "queue", "servicebus", "sas", "sig="],
        )
        p["azure_connection_string"] = dict(
            pattern=r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{64,}',
            severity="CRITICAL", description="Azure Storage Connection String",
        )

        # Webhooks / notifications
        p["discord_webhook"] = dict(
            pattern=r'https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[a-zA-Z0-9_-]{60,}',
            severity="HIGH", description="Discord Webhook URL",
        )
        p["telegram_bot_token"] = dict(
            pattern=r'\b(\d{8,10}:[a-zA-Z0-9_-]{35})\b', severity="CRITICAL",
            description="Telegram Bot Token",
            context_keywords=["telegram", "bot", "botfather", "sendmessage"],
            requires_context_keywords=True,
        )
        p["docker_registry_auth"] = dict(
            pattern=r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"', severity="CRITICAL",
            description="Docker Registry Auth (base64 credentials)",
            context_keywords=["docker", "registry", "auths", "dockerconfigjson"],
            requires_context_keywords=True,
        )

        # Cryptocurrency
        p["bitcoin_address"] = dict(
            pattern=r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', severity="MEDIUM",
            description="Bitcoin Address",
        )
        p["ethereum_address"] = dict(
            pattern=r'\b0x[a-fA-F0-9]{40}\b', severity="MEDIUM",
            description="Ethereum Address",
        )

        return p

    # ── Validators ────────────────────────────────────────────────────────────

    def _luhn(self, number: str) -> bool:
        digits = [int(d) for d in re.sub(r'\D', '', number)]
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0

    def _validate_credit_card(self, number: str) -> bool:
        d = re.sub(r'\D', '', number)
        if not (13 <= len(d) <= 19):
            return False
        valid_prefix = (
            d[0] == '4'
            or d[:2] in ('34', '37')
            or (len(d) >= 2 and 51 <= int(d[:2]) <= 55)
            or (len(d) >= 4 and 2221 <= int(d[:4]) <= 2720)
            or d[:4] == '6011' or d[:2] in ('64', '65')
            or (len(d) >= 3 and 300 <= int(d[:3]) <= 305)
            or d[:2] in ('36', '38')
            or (len(d) >= 4 and 3528 <= int(d[:4]) <= 3589)
        )
        return valid_prefix and self._luhn(number)

    def _validate_ssn(self, ssn: str) -> bool:
        digits = re.sub(r'\D', '', ssn)
        if len(digits) != 9:
            return False
        area, group, serial = int(digits[:3]), int(digits[3:5]), int(digits[5:])
        if area == 0 or area == 666 or area >= 900:
            return False
        if group == 0 or serial == 0:
            return False
        if len(set(digits)) == 1 or digits == '123456789':
            return False
        return True

    def _validate_jwt(self, token: str) -> bool:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        try:
            padded = parts[0] + '=' * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(padded))
            return isinstance(header, dict) and ('alg' in header or 'typ' in header)
        except Exception:
            return False

    # ── Entropy helpers ───────────────────────────────────────────────────────

    def _entropy(self, data: str) -> float:
        if not data:
            return 0.0
        c = collections.Counter(data)
        n = len(data)
        return -sum((v / n) * math.log(v / n, 2) for v in c.values())

    def _max_window_entropy(self, data: str, window: int = _ENTROPY_WINDOW) -> float:
        if len(data) <= window:
            return self._entropy(data)
        return max(self._entropy(data[i:i + window]) for i in range(len(data) - window + 1))

    def _is_common_base64(self, value: str) -> bool:
        if not _BASE64_RE.match(value):
            return False
        try:
            decoded = base64.b64decode(value + '==').decode('utf-8', errors='strict')
            printable = sum(c.isprintable() and ord(c) < 128 for c in decoded)
            return printable / max(len(decoded), 1) > 0.85
        except Exception:
            return False

    def _in_code_comment(self, text: str, pos: int) -> bool:
        line_start = text.rfind('\n', 0, pos)
        line_start = 0 if line_start == -1 else line_start + 1
        if re.search(r'(?://|#\s*|--\s*)', text[line_start:pos]):
            return True
        return any(m.start() <= pos < m.end() for m in _BLOCK_COMMENT_RE.finditer(text))

    # ── Context scoring ───────────────────────────────────────────────────────

    def _score_context(self, pattern_name: str, context: str) -> tuple:
        ctx = context.lower()
        score = 0.5
        reasons: List[str] = []

        prod_kw = {"production", "prod", "live", "real", "secret", "private",
                   "api_key", "access_key", "token", "credential", "password",
                   "authorization", "authenticate", "config", "env", "deploy",
                   "deployed", "server", "database", "connection"}
        hits = [k for k in prod_kw if k in ctx]
        if hits:
            boost = round(min(0.30, len(hits) * 0.06), 3)
            score += boost
            reasons.append(f"proximity_boost({','.join(hits[:3])})+{boost}")

        doc_kw = {"example", "sample", "placeholder", "dummy", "fake", "test",
                  "mock", "demo", "tutorial", "docs", "documentation", "readme",
                  "your_", "_here", "replace_", "xxx", "todo"}
        phits = [k for k in doc_kw if k in ctx]
        code_fence = ctx.count("```") >= 2 or ctx.count("~~~") >= 2
        if phits or code_fence:
            penalty = round(min(0.40, len(phits) * 0.07 + (0.15 if code_fence else 0)), 3)
            score -= penalty
            desc = ','.join(phits[:3]) + (",code_fence" if code_fence else "")
            reasons.append(f"code_block_penalty({desc})-{penalty}")

        fin_types = {"credit_card", "bank_account", "iban", "routing_number"}
        if pattern_name in fin_types:
            fin_kw = {"payment", "billing", "invoice", "transaction", "charge",
                      "purchase", "order", "checkout", "card", "bank", "financial",
                      "amount", "total", "price", "customer", "merchant", "receipt"}
            fhits = [k for k in fin_kw if k in ctx]
            if fhits:
                boost = round(min(0.25, len(fhits) * 0.05), 3)
                score += boost
                reasons.append(f"financial_ctx_boost({','.join(fhits[:3])})+{boost}")

            med_kw = {"patient", "diagnosis", "physician", "doctor", "hospital",
                      "clinic", "medical", "prescription", "icd", "npi", "healthcare"}
            mhits = [k for k in med_kw if k in ctx]
            if len(mhits) >= 2:
                penalty = round(min(0.35, len(mhits) * 0.07), 3)
                score -= penalty
                reasons.append(f"medical_ctx_penalty({','.join(mhits[:3])})-{penalty}")

        return round(max(0.0, min(1.0, score)), 3), reasons

    def _word_window(self, text: str, start: int, end: int, window: int = 50) -> str:
        slack = window * 9
        pre  = text[max(0, start - slack):start].split()[-window:]
        post = text[end:min(len(text), end + slack)].split()[:window]
        return ' '.join(pre) + ' ' + text[start:end] + ' ' + ' '.join(post)

    # ── Masking ───────────────────────────────────────────────────────────────

    def _mask(self, value: str, pattern_name: str) -> str:
        if pattern_name in ("credit_card", "ssn", "bank_account"):
            return f"{value[:4]}...{value[-4:]}" if len(value) > 8 else "***"
        if pattern_name in ("aws_secret_key", "github_token", "bearer_token",
                            "password_in_code", "slack_api_token", "google_api_key"):
            return f"{value[:6]}...***" if len(value) > 10 else "***"
        if pattern_name == "email":
            parts = value.split('@')
            if len(parts) == 2:
                return f"{parts[0][:2]}***@{parts[1]}"
        return value[:10] + "..." if len(value) > 10 else value

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self, text: str, *, secrets_only: bool = False) -> ScanResult:
        """
        Scan *text* for sensitive data and secrets.

        Parameters
        ----------
        text:
            The text to scan.
        secrets_only:
            When True, only scan for API keys / secrets (skip PII patterns).
            Useful for scanning source code files.

        Returns
        -------
        ScanResult
            Structured findings grouped by severity with timing info.
        """
        t0 = time.monotonic()
        buckets: Dict[str, List[Finding]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": [],
        }

        for name, info in self._patterns.items():
            if secrets_only and name not in self._secret_types:
                continue

            for m in re.finditer(info["pattern"], text, re.IGNORECASE):
                # Prefer the capturing group over the whole match: several
                # patterns (bearer_token, twilio_auth_token, generic_api_key,
                # password_in_code) match a literal label/prefix — "Bearer ",
                # "TWILIO_AUTH_TOKEN=" — around the secret itself, and
                # m.group(0) is that whole span, prefix included. Using it
                # as `raw` meant the masked value shown to users was
                # "Bearer...***" instead of a piece of the actual token, and
                # anything that verifies the raw value (dlp_patterns.verify,
                # AWS/Twilio pairing) would have sent the label text to the
                # provider along with — or instead of — the real secret.
                # `m.lastindex` is None for patterns with no capturing group
                # (or only non-capturing `(?:...)` groups) — group(0) is
                # correct there, since the whole match already *is* the
                # value with nothing extra attached (aws_access_key,
                # db_connection_string, PEM headers, ...).
                grp = 1 if m.lastindex else 0
                raw = m.group(grp)

                # Gate 1 — custom validator
                validator: Optional[Callable] = info.get("validator")
                if validator and not validator(raw):
                    continue

                # Gate 2 — entropy (secrets only)
                if name in self._secret_types:
                    if self._is_common_base64(raw):
                        continue
                    if len(raw) >= _MIN_ENTROPY_LEN:
                        threshold = (
                            _COMMENT_PENALTY if self._in_code_comment(text, m.start(grp))
                            else _ENTROPY_THRESHOLD
                        )
                        if self._max_window_entropy(raw) < threshold:
                            continue

                # Context
                ctx_raw = text[max(0, m.start(grp) - 100): min(len(text), m.end(grp) + 100)]
                ww = self._word_window(text, m.start(grp), m.end(grp))
                ctx_score, ctx_reasons = self._score_context(name, ww)

                finding = Finding(
                    type=name,
                    description=info["description"],
                    value=self._mask(raw, name),
                    position=f"char {m.start(grp)}-{m.end(grp)}",
                    severity=info["severity"],
                    context=ctx_raw,
                    context_score=ctx_score,
                    context_score_reasons=ctx_reasons,
                    raw=raw,
                )

                # Gate 3 — required context keywords
                if "context_keywords" in info:
                    ctx_lo = ctx_raw.lower()
                    matched_kw = [k for k in info["context_keywords"] if k in ctx_lo]
                    if matched_kw:
                        finding.context_keywords_found = matched_kw
                    elif info.get("requires_context_keywords"):
                        continue

                sev = info["severity"]
                buckets.setdefault(sev, []).append(finding)

        # Sensitive keyword scan — bare English words ("password", "token",
        # "confidential", ...) with no co-occurrence or entropy requirement.
        # Meant for flagging compliance-relevant *documents* (an HR file
        # containing "confidential" or "do not share"). It has no business
        # running in secrets_only mode: on any real auth/security codebase,
        # words like "token"/"secret"/"authorization" appear constantly and
        # legitimately, and secrets_only's whole point is "just check for
        # credential values" — this pass finds neither a credential nor PII,
        # just vocabulary, so it's pure noise there (worse, several of these
        # are CRITICAL severity, e.g. "private key"/"root password", so they
        # were contributing to secrets_only's exit code too).
        if not secrets_only:
            for sev, keywords in self._sensitive_keywords.items():
                for kw in keywords:
                    if re.search(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE):
                        buckets[sev].append(Finding(
                            type="sensitive_keyword",
                            description="Sensitive Keyword",
                            value=kw,
                            position="multiple",
                            severity=sev,
                            context="",
                            context_score=0.5,
                        ))

        elapsed = (time.monotonic() - t0) * 1000
        return ScanResult(
            critical=buckets["CRITICAL"],
            high=buckets["HIGH"],
            medium=buckets["MEDIUM"],
            low=buckets["LOW"],
            info=buckets.get("INFO", []),
            elapsed_ms=round(elapsed, 2),
        )

    def redact(self, text: str) -> str:
        """Return *text* with all detected sensitive values replaced by ``[REDACTED: <type>]``."""
        matches = []
        for name, info in self._patterns.items():
            for m in re.finditer(info["pattern"], text, re.IGNORECASE):
                validator: Optional[Callable] = info.get("validator")
                if validator and not validator(m.group(0)):
                    continue
                matches.append((m.start(), m.end(), f"[REDACTED: {info['description']}]"))
        for sev, keywords in self._sensitive_keywords.items():
            for kw in keywords:
                for m in re.finditer(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE):
                    matches.append((m.start(), m.end(), "[REDACTED: Sensitive Keyword]"))

        matches.sort(key=lambda x: x[0])
        parts, idx = [], 0
        for start, end, repl in matches:
            if start < idx:
                continue
            parts.append(text[idx:start])
            parts.append(repl)
            idx = end
        parts.append(text[idx:])
        return "".join(parts)

    def fuzz(self, text: str) -> str:
        """
        Replace sensitive data with realistic fake values (requires ``faker``).
        Falls back to :meth:`redact` when ``faker`` is not installed.
        Useful for generating safe test datasets from production data.
        """
        try:
            from faker import Faker  # type: ignore[import]
            fake = Faker()
        except ImportError:
            return self.redact(text)

        _fakers: Dict[str, Callable] = {
            "credit_card": fake.credit_card_number,
            "ssn":         fake.ssn,
            "email":       fake.email,
            "phone_us":    fake.phone_number,
            "ipv4":        fake.ipv4,
            "bank_account": lambda: str(fake.random_int(min=10_000_000, max=9_999_999_999)),
        }

        matches = []
        for name, info in self._patterns.items():
            for m in re.finditer(info["pattern"], text, re.IGNORECASE):
                validator: Optional[Callable] = info.get("validator")
                if validator and not validator(m.group(0)):
                    continue
                gen = _fakers.get(name, lambda n=name: f"[FAKE-{n.upper()}]")
                matches.append((m.start(), m.end(), gen()))
        for sev, keywords in self._sensitive_keywords.items():
            for kw in keywords:
                for m in re.finditer(r'\b' + re.escape(kw) + r'\b', text, re.IGNORECASE):
                    matches.append((m.start(), m.end(), "[FAKE-SECRET]"))

        matches.sort(key=lambda x: x[0])
        parts, idx = [], 0
        for start, end, repl in matches:
            if start < idx:
                continue
            parts.append(text[idx:start])
            parts.append(repl)
            idx = end
        parts.append(text[idx:])
        return "".join(parts)
