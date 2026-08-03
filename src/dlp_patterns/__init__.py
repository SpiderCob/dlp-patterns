"""
dlp-patterns — fast, zero-dependency DLP pattern scanner.

Quick start::

    import dlp_patterns

    result = dlp_patterns.scan("My SSN is 432-78-9012 and CC 4111 1111 1111 1111")
    print(result.highest_severity)   # CRITICAL
    print(result.critical[0].type)   # credit_card

    clean = dlp_patterns.redact("Email alice@corp.com CC 4111111111111111")
    # "Email [REDACTED: Email Address] CC [REDACTED: Credit Card Number]"

    fuzzed = dlp_patterns.fuzz("alice@corp.com")
    # "random.fake@example.com"

Full docs: https://github.com/spidercob/dlp-patterns
"""

from dlp_patterns._engine import Scanner, ScanResult, Finding

__version__ = "0.2.0"
__all__ = ["scan", "redact", "fuzz", "Scanner", "ScanResult", "Finding", "__version__"]

_default = Scanner()


def scan(text: str, *, secrets_only: bool = False) -> ScanResult:
    """
    Scan *text* for PII, secrets, and sensitive data.

    Parameters
    ----------
    text:
        Plain text, source code, log output, document content, etc.
    secrets_only:
        Limit scanning to API keys / credentials only (skip PII).
        Faster for CI secret-scanning use cases.

    Returns
    -------
    ScanResult
        Findings grouped by severity (critical / high / medium / low).

    Examples
    --------
    >>> import dlp_patterns
    >>> r = dlp_patterns.scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE")
    >>> r.has_findings
    True
    >>> r.critical[0].type
    'aws_access_key'
    """
    return _default.scan(text, secrets_only=secrets_only)


def redact(text: str) -> str:
    """
    Return *text* with all detected sensitive values replaced by
    ``[REDACTED: <description>]``.

    Examples
    --------
    >>> dlp_patterns.redact("Call me at 415-555-0100")
    'Call me at [REDACTED: US Phone Number]'
    """
    return _default.redact(text)


def fuzz(text: str) -> str:
    """
    Replace sensitive data with realistic fake values using ``faker``.
    Falls back to :func:`redact` when ``faker`` is not installed.

    Useful for generating safe test datasets from production data.

    Examples
    --------
    >>> dlp_patterns.fuzz("alice@corp.com")  # doctest: +SKIP
    'angie.smith@example.net'
    """
    return _default.fuzz(text)
