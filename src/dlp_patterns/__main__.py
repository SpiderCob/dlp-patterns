"""
CLI entry point — dlp-scan

Usage:
    dlp-scan "text to scan"
    echo "my text" | dlp-scan
    dlp-scan --secrets-only path/to/file.py
    dlp-scan --redact path/to/document.txt
"""
from __future__ import annotations

import argparse
import json
import sys

from dlp_patterns import scan, redact, __version__


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dlp-scan",
        description="Scan text for PII, secrets, and sensitive data.",
    )
    parser.add_argument("input", nargs="?", help="Text or file path to scan (reads stdin if omitted)")
    parser.add_argument("--secrets-only", action="store_true", help="Only scan for API keys / secrets")
    parser.add_argument("--redact", action="store_true", dest="do_redact", help="Print redacted text instead of findings")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output findings as JSON")
    parser.add_argument("--version", action="version", version=f"dlp-patterns {__version__}")
    args = parser.parse_args()

    # Read input
    if args.input and not _is_file(args.input):
        text = args.input
    elif args.input and _is_file(args.input):
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    if args.do_redact:
        print(redact(text))
        return

    result = scan(text, secrets_only=args.secrets_only)

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    if not result.has_findings:
        print("No findings.")
        sys.exit(0)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        findings = getattr(result, sev.lower())
        if not findings:
            continue
        print(f"\n[{sev}]")
        for f in findings:
            print(f"  {f.type:<30} {f.description}")
            print(f"  {'':30} value={f.value}  pos={f.position}")

    total = len(result.all)
    print(f"\n{total} finding(s) in {result.elapsed_ms:.1f}ms")
    sys.exit(1 if result.critical else 0)


def _is_file(path: str) -> bool:
    import os
    return os.path.isfile(path)


if __name__ == "__main__":
    main()
