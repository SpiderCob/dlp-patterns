"""
CLI entry point — dlp-scan

Usage:
    dlp-scan "text to scan"
    echo "my text" | dlp-scan
    dlp-scan --secrets-only path/to/file.py
    dlp-scan --secrets-only path/to/directory
    dlp-scan --redact path/to/document.txt
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from dlp_patterns import scan, redact, __version__

# Auto-generated files that are never a realistic place for a real leaked
# credential, but routinely false-positive against secret regexes (e.g. AWS
# secret keys matching base64 integrity hashes) — always skipped in
# directory mode.
_SKIP_FILENAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "Cargo.lock", "poetry.lock", "Pipfile.lock", "go.sum", "composer.lock",
}
_SKIP_DIRNAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".tox",
}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dlp-scan",
        description="Scan text for PII, secrets, and sensitive data.",
    )
    parser.add_argument("input", nargs="?", help="Text, file path, or directory path to scan (reads stdin if omitted)")
    parser.add_argument("--secrets-only", action="store_true", help="Only scan for API keys / secrets")
    parser.add_argument("--redact", action="store_true", dest="do_redact", help="Print redacted text instead of findings")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output findings as JSON")
    parser.add_argument("--version", action="version", version=f"dlp-patterns {__version__}")
    args = parser.parse_args()

    if args.input and os.path.isdir(args.input):
        if args.do_redact:
            print("--redact is not supported in directory mode; run it against individual files.", file=sys.stderr)
            sys.exit(2)
        _scan_directory(args.input, args)
        return

    # Read input
    if args.input and os.path.isfile(args.input):
        with open(args.input, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    elif args.input:
        text = args.input
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

    _print_findings(result)

    total = len(result.all)
    print(f"\n{total} finding(s) in {result.elapsed_ms:.1f}ms")
    sys.exit(1 if result.critical else 0)


def _iter_scannable_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRNAMES]
        for name in filenames:
            if name in _SKIP_FILENAMES:
                continue
            path = os.path.join(dirpath, name)
            if _looks_binary(path):
                continue
            yield path


def _looks_binary(path: str, sniff_bytes: int = 8192) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(sniff_bytes)
    except OSError:
        return True
    return b"\x00" in chunk


def _scan_directory(root: str, args: argparse.Namespace) -> None:
    findings_by_file: "dict[str, dict]" = {}
    files_scanned = 0
    total_elapsed = 0.0
    highest_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    highest_severity = None

    for path in _iter_scannable_files(root):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue

        files_scanned += 1
        result = scan(text, secrets_only=args.secrets_only)
        total_elapsed += result.elapsed_ms

        if result.has_findings:
            rel = os.path.relpath(path, root)
            findings_by_file[rel] = result.to_dict()
            sev = result.highest_severity
            if sev and (highest_severity is None or highest_rank[sev] < highest_rank[highest_severity]):
                highest_severity = sev

    if args.as_json:
        print(json.dumps({
            "mode": "directory",
            "path": root,
            "files_scanned": files_scanned,
            "files_with_findings": len(findings_by_file),
            "highest_severity": highest_severity,
            "findings_by_file": findings_by_file,
            "elapsed_ms": total_elapsed,
        }, indent=2))
    else:
        if not findings_by_file:
            print(f"No findings. ({files_scanned} file(s) scanned)")
        else:
            for rel, file_result in findings_by_file.items():
                print(f"\n=== {rel} ===")
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    for f in file_result.get(sev, []):
                        print(f"  {f['type']:<30} {f['description']}")
                        print(f"  {'':30} value={f['value']}  pos={f['position']}")
            total = sum(len(v) for r in findings_by_file.values() for v in r.values() if isinstance(v, list))
            print(f"\n{total} finding(s) across {len(findings_by_file)} file(s) ({files_scanned} scanned) in {total_elapsed:.1f}ms")

    sys.exit(1 if highest_severity == "CRITICAL" else 0)


def _print_findings(result) -> None:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        findings = getattr(result, sev.lower())
        if not findings:
            continue
        print(f"\n[{sev}]")
        for f in findings:
            print(f"  {f.type:<30} {f.description}")
            print(f"  {'':30} value={f.value}  pos={f.position}")


if __name__ == "__main__":
    main()
