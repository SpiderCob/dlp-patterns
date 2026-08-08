"""
CLI entry point — dlp-scan

Usage:
    dlp-scan "text to scan"
    echo "my text" | dlp-scan
    dlp-scan --secrets-only path/to/file.py
    dlp-scan --secrets-only path/to/directory
    dlp-scan --redact path/to/document.txt
    dlp-scan --history path/to/repo
    dlp-scan --verify --secrets-only path/to/file.py
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from dlp_patterns import scan, redact, __version__
from dlp_patterns._verify import verify_findings

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
    parser.add_argument("--history", action="store_true",
                         help="Scan full git history (all commits, all branches) instead of the working tree — "
                              "finds secrets that were committed and later removed. 'input' is a path to/inside a git repo (default: .)")
    parser.add_argument("--max-commits", type=int, default=None, help="With --history, only scan the N most recent commits")
    parser.add_argument("--include-merges", action="store_true", help="With --history, include merge commits (excluded by default)")
    parser.add_argument("--full-scan", action="store_true",
                         help="With --history, also scan for PII, not just secrets (off by default — PII noise across full history is high)")
    parser.add_argument("--verify", action="store_true",
                         help="Attempt live verification of found secrets against their provider's API (opt-in — makes real "
                              "network requests; see README for exactly what this does and doesn't send)")
    parser.add_argument("--verify-timeout", type=float, default=4.0, help="Per-secret network timeout in seconds for --verify (default: 4.0)")
    parser.add_argument("--min-confidence", type=float, default=0.0, dest="min_confidence",
                         help="Only fail the exit code for CRITICAL findings whose context_score is >= this value "
                              "(0.0-1.0, default: 0.0 — any CRITICAL fails, same as before this flag existed). "
                              "Findings are still reported regardless; this only changes what the exit code reacts "
                              "to. Per the dlp-triage rule of thumb: context_score > 0.6 is high-confidence real, "
                              "< 0.3 usually means a doc/test fixture (nearby 'example'/'test'/'placeholder').")
    parser.add_argument("--version", action="version", version=f"dlp-patterns {__version__}")
    args = parser.parse_args()

    if args.history:
        _scan_history(args.input or ".", args)
        return

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

    if args.verify:
        _verify_cli(result.all, args)

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return

    if not result.has_findings:
        print("No findings.")
        sys.exit(0)

    _print_findings(result)

    total = len(result.all)
    print(f"\n{total} finding(s) in {result.elapsed_ms:.1f}ms")
    sys.exit(1 if _has_blocking_critical(result.critical, args.min_confidence) else 0)


def _has_blocking_critical(findings, min_confidence: float) -> bool:
    """
    Whether *findings* contains a CRITICAL whose context_score clears
    min_confidence — the actual exit-code decision, everywhere the CLI can
    fail a build. Ungated severity-only blocking was the CLI's biggest gap:
    the engine already computes context_score specifically to separate real
    secrets from doc/test fixtures (see the dlp-triage skill this same
    ecosystem ships), but the CLI threw it away and blocked on severity
    alone. Default min_confidence=0.0 keeps that old behavior unless a
    caller opts into a threshold via --min-confidence (context_score is
    always in [0, 1], so >= 0.0 matches every CRITICAL).
    """
    return any(f.severity == "CRITICAL" and f.context_score >= min_confidence for f in findings)


_VERIFY_WARNED = False


def _verify_cli(findings: list, args: argparse.Namespace) -> None:
    """Shared --verify entry point for text/file, directory, and history modes."""
    global _VERIFY_WARNED
    if not _VERIFY_WARNED:
        print(
            "warning: --verify makes a live, read-only API call per secret to its own "
            "provider (GitHub, Slack, Stripe, ...) to confirm whether it's still active. "
            "Only requests that credential's own provider would normally receive are sent — "
            "see the dlp-patterns README for the exact list of what's checked and how.",
            file=sys.stderr,
        )
        _VERIFY_WARNED = True
    verify_findings(findings, timeout=args.verify_timeout)


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
    results_by_file: "dict[str, object]" = {}
    files_scanned = 0
    total_elapsed = 0.0
    highest_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    highest_severity = None
    has_blocking = False

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
            results_by_file[rel] = result
            sev = result.highest_severity
            if sev and (highest_severity is None or highest_rank[sev] < highest_rank[highest_severity]):
                highest_severity = sev
            if _has_blocking_critical(result.critical, args.min_confidence):
                has_blocking = True

    if args.verify and results_by_file:
        # One pooled verify pass across every file — an identical secret
        # repeated across many files is checked against its provider once,
        # not once per file it happens to appear in.
        all_findings = [f for result in results_by_file.values() for f in result.all]
        _verify_cli(all_findings, args)

    findings_by_file = {rel: result.to_dict() for rel, result in results_by_file.items()}

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
                        _print_verification_line(f.get("verification"))
            total = sum(len(v) for r in findings_by_file.values() for v in r.values() if isinstance(v, list))
            print(f"\n{total} finding(s) across {len(findings_by_file)} file(s) ({files_scanned} scanned) in {total_elapsed:.1f}ms")

    sys.exit(1 if has_blocking else 0)


def _print_findings(result) -> None:
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        findings = getattr(result, sev.lower())
        if not findings:
            continue
        print(f"\n[{sev}]")
        for f in findings:
            print(f"  {f.type:<30} {f.description}")
            print(f"  {'':30} value={f.value}  pos={f.position}")
            if f.verification is not None:
                v = f.verification
                print(f"  {'':30} verify={v.status.upper()} ({v.detail})")


def _print_verification_line(v: "dict | None") -> None:
    if v is not None:
        print(f"  {'':30} verify={v['status'].upper()} ({v['detail']})")


def _scan_history(repo_path: str, args: argparse.Namespace) -> None:
    from dlp_patterns._history import scan_git_history, NotAGitRepoError, GitNotFoundError

    if args.do_redact:
        print("--redact is not supported with --history; run it against individual files.", file=sys.stderr)
        sys.exit(2)

    try:
        result = scan_git_history(
            repo_path,
            secrets_only=not args.full_scan,
            max_commits=args.max_commits,
            include_merges=args.include_merges,
        )
    except (NotAGitRepoError, GitNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.verify and result.has_findings:
        _verify_cli([hf.finding for hf in result.findings], args)

    has_blocking = _has_blocking_critical((hf.finding for hf in result.findings), args.min_confidence)

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
        sys.exit(1 if has_blocking else 0)

    if not result.has_findings:
        print(f"No findings across history. ({result.commits_scanned} commit(s) scanned)")
        sys.exit(0)

    for hf in result.findings:
        f = hf.finding
        print(f"\n[{f.severity}] {f.type} — {hf.file}")
        print(f"  commit {hf.short_commit}  {hf.author}  {hf.date}")
        print(f"  {hf.subject!r}")
        print(f"  value={f.value}  pos={f.position}")
        if f.verification is not None:
            v = f.verification
            print(f"  verify={v.status.upper()} ({v.detail})")

    print(f"\n{len(result.findings)} finding(s) across {result.commits_scanned} commit(s) in {result.elapsed_ms:.1f}ms")
    sys.exit(1 if has_blocking else 0)


if __name__ == "__main__":
    main()
