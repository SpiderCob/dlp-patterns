# dlp-patterns

**Fast, zero-dependency DLP pattern scanner for Python.**

Detects PII, secrets, and sensitive data in any text — documents, logs, source code, emails. Built from the scanning engine that powers [Spidercob](https://spidercob.com), an enterprise DLP platform.

```python
import dlp_patterns

result = dlp_patterns.scan("My SSN is 432-78-9012 and CC 4111 1111 1111 1111")
print(result.highest_severity)   # CRITICAL
print(result.critical[0].type)   # credit_card

clean = dlp_patterns.redact("Send to alice@corp.com with CC 4111 1111 1111 1111")
# "Send to [REDACTED: Email Address] with [REDACTED: Credit Card Number]"
```

## Install

```bash
pip install dlp-patterns
```

No external dependencies. Python 3.9+.

## What it detects

| Category | Patterns |
|---|---|
| **Financial** | Credit cards (Luhn + BIN), SSN, IBAN, bank account, routing number |
| **PII** | Email, US phone, passport, driver's license, date of birth |
| **Healthcare** | Medical record numbers, ICD-10 codes, NPI, DEA numbers, NDC codes |
| **Secrets** | AWS keys, GitHub PATs, Slack tokens, Google API keys, Bearer tokens, JWTs |
| **Cloud / SaaS** | Stripe, SendGrid, Mailgun, Twilio, HuggingFace, NPM, Cloudflare, Azure |
| **Infrastructure** | DB connection strings, hardcoded passwords, Docker registry auth |
| **Crypto** | RSA/EC/SSH/PGP private keys, X.509 certs |
| **Webhooks** | Slack webhooks, Discord webhooks, Telegram bot tokens |
| **Cryptocurrency** | Bitcoin addresses, Ethereum addresses |

50+ pattern categories total.

## Features

- **Validators** — Luhn check for credit cards, FICA rules for SSNs, JSON decode for JWTs. Reduces false positives before they reach you.
- **Entropy gating** — Shannon entropy + sliding-window analysis rejects low-entropy matches (e.g. `aaaaaaa...`) from generic secret patterns.
- **Context scoring** — Each finding gets a `context_score` (0–1) based on surrounding words. Proximity to `production`, `secret`, `deploy` boosts the score; proximity to `example`, `placeholder`, `test` lowers it.
- **Required context keywords** — Patterns like ICD-10 codes and Telegram tokens only fire when relevant keywords appear nearby.
- **`secrets_only` mode** — Scan just for API keys and credentials, skipping PII. Faster for CI/CD secret scanning.
- **`redact()`** — Replace all findings with `[REDACTED: <type>]`.
- **`fuzz()`** — Replace findings with realistic fake values (requires `faker`). Useful for building safe test datasets from production data.
- **CLI** — `dlp-scan` command for shell pipelines and CI.

## Usage

### Python API

```python
import dlp_patterns

# Scan
result = dlp_patterns.scan(text)

result.has_findings          # bool
result.highest_severity      # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | None
result.critical              # list[Finding]
result.all                   # all findings across severities
result.elapsed_ms            # scan time in milliseconds

# Each Finding:
f = result.critical[0]
f.type                       # "credit_card"
f.description                # "Credit Card Number"
f.value                      # masked: "4111...1111"
f.severity                   # "CRITICAL"
f.position                   # "char 10-29"
f.context                    # surrounding text (±100 chars)
f.context_score              # float 0.0–1.0
f.context_keywords_found     # ["payment", "billing"]

# Secrets only (faster for source code scanning)
result = dlp_patterns.scan(code, secrets_only=True)

# Redact
clean = dlp_patterns.redact(text)

# Fuzz (pip install dlp-patterns[fuzz])
safe = dlp_patterns.fuzz(text)

# JSON output
result.to_dict()
```

### CLI

```bash
# Scan a string
dlp-scan "My SSN is 432-78-9012"

# Scan a file
dlp-scan path/to/document.txt

# Scan a directory recursively
dlp-scan path/to/project/

# Pipe from stdin
cat logfile.txt | dlp-scan

# JSON output
dlp-scan --json document.txt

# Redact in place (files only, not directories)
dlp-scan --redact document.txt > clean.txt

# Secrets only (for source code)
dlp-scan --secrets-only src/config.py

# Exit code: 1 if CRITICAL findings, 0 otherwise — useful in CI
dlp-scan --secrets-only . && echo "clean"
```

#### Directory scanning

`dlp-scan <directory>` walks recursively and scans every text file it finds.
It automatically skips:

- Version control and vendor directories: `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`, `build`, `.mypy_cache`, `.pytest_cache`, `.tox`
- Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `composer.lock`, `npm-shrinkwrap.json`) — these are auto-generated and full of base64 integrity hashes that false-positive against secret regexes
- Binary files (detected by a null-byte sniff on the first 8KB)

`--json` output for a directory scan has a different shape than a single-file scan — findings are grouped by file:

```json
{
  "mode": "directory",
  "path": "src/",
  "files_scanned": 42,
  "files_with_findings": 2,
  "highest_severity": "CRITICAL",
  "findings_by_file": {
    "config.py": { "CRITICAL": [...], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": [], "elapsed_ms": 1.2 }
  },
  "elapsed_ms": 38.4
}
```

Exit code is still `1` if any file has a CRITICAL finding, `0` otherwise.

### Pre-commit hook

Block commits containing secrets automatically using [dlp-pre-commit](https://github.com/SpiderCob/dlp-pre-commit):

```yaml
repos:
  - repo: https://github.com/SpiderCob/dlp-pre-commit
    rev: v1.0.0
    hooks:
      - id: dlp-scan-secrets-only
```

```bash
pip install pre-commit
pre-commit install
```

### Use in CI (GitHub Actions)

The easiest way is the official [dlp-scan-action](https://github.com/SpiderCob/dlp-scan-action):

```yaml
- name: DLP Secret Scan
  uses: spidercob/dlp-scan-action@v1
  with:
    secrets-only: 'true'
    fail-on: 'critical'
```

Or run the CLI directly:

```yaml
- name: DLP secret scan
  run: |
    pip install dlp-patterns
    dlp-scan --secrets-only --json src/ | tee dlp-report.json
```

## Advanced — use `Scanner` directly

```python
from dlp_patterns import Scanner

scanner = Scanner()

# Reuse the same instance (compiled patterns cached)
for text in documents:
    result = scanner.scan(text)
    if result.has_findings:
        print(result.to_dict())
```

## Enterprise

Need a full DLP platform with dashboards, audit logs, ICAP proxy integration, Gmail/Slack scanning, compliance reports, and AI-powered analysis?

→ **[Spidercob](https://spidercob.com)** — the enterprise DLP platform this library is extracted from.

## License

Apache 2.0 — free for commercial use.
