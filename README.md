# Secret Sentinel

Secret Sentinel is a lightweight local secret scanner for Git repositories. It helps catch hardcoded secrets before they are committed, using built-in pattern checks and entropy-based detection.

It is designed to work without requiring a cloud API or environment variables for normal usage.

## What it does

- scans staged files before commit
- scans selected files or folders manually
- looks for common secret formats and high-entropy strings
- can optionally use AI validation when available
- can be installed as a Git pre-commit hook

## Install

From the project root:

```bash
python -m pip install .
```

Or install directly from GitHub:

```bash
python -m pip install "git+https://github.com/tajamul-wani/secret-sentinel.git"
```

## Run it locally

Scan staged changes:

```bash
secret-sentinel --staged
```

Scan a specific file or folder:

```bash
secret-sentinel .
secret-sentinel src/
secret-sentinel .env.example
```

Scan commit history reachable from the current `HEAD`:

```bash
secret-sentinel --git-history
secret-sentinel --git-history --format sarif --output history-results.sarif

# Include local branches, remote-tracking refs, and tags
secret-sentinel --git-history --all-refs
```

The history scan includes commits in the current branch's ancestry, including
commits that were later removed from the working tree. It does not scan commits
that are only reachable from other local branches or remote-tracking refs.
Use `--all-refs` to include commits reachable from any local Git ref, including
branches, remote-tracking refs, and tags. Remote refs are scanned only if they
have already been fetched into the local repository.
Findings identify the earliest commit and file where a match appears. Configured
ignore paths apply, binary files are skipped, and AI validation is not used.
Scanning a long history can take time. This reports findings; it does not
rewrite commits or remove secrets from repository history.

Skip AI validation:

```bash
secret-sentinel --staged --no-ai
```

### Risk Scoring

Each detected secret is assigned a severity level based on its type:

- **CRITICAL**: AWS keys, API tokens (Stripe, GitHub, Slack, Google), Twilio keys, Private keys, Database connection URIs, OpenAI / Anthropic / HuggingFace / PyPI / NPM tokens
- **HIGH**: JWT tokens, generic secret assignments
- **MEDIUM**: High-entropy strings detected via pattern matching
- **LOW**: Other potential secrets

The overall severity of a scan is determined by the highest severity issue found.

### Responding to Findings

Text, JSON, and SARIF reports include remediation guidance for detected
credential types. If a finding may be real, revoke or rotate the credential
first, investigate provider activity for misuse, and move any replacement into
a secrets manager. Removing a value from the working tree does not invalidate
it; history cleanup should follow revocation and may require coordination with
repository collaborators.

### Configurable Failure Threshold

Configure which severity level blocks commits or causes CI to fail:

```bash
# Block only on HIGH or CRITICAL severity, warning on MEDIUM/LOW
secret-sentinel --staged --fail-on HIGH

# Default behavior: blocks on any detected issue (LOW or higher)
secret-sentinel --staged --fail-on LOW
```

### Baseline Existing Findings

If a repository already contains findings, record them once and then check only
for newly introduced findings:

```bash
# Capture findings from the selected scan (here, the whole working tree)
secret-sentinel --update-baseline .

# Later scans ignore matching baseline findings and fail on new ones
secret-sentinel --baseline .
```

The baseline is stored at `.secret-sentinel/baseline.json`. It contains
HMAC-SHA-256 fingerprints of each finding's path, rule, and detected value—not
the secret value itself. Baseline operations require the same independently
generated key in `SECRET_SENTINEL_BASELINE_KEY` on every machine and CI job that
uses the baseline. Generate a key with
`python -c "import secrets; print(secrets.token_hex(32))"` and store it as a
local environment variable or CI secret; never commit it. The keyed fingerprints
prevent offline guessing from the committed baseline and prevent contributors
without the key from adding valid suppressions.

`--update-baseline` intentionally replaces the baseline with findings from that
scan, so review new findings before refreshing it. Commit the baseline file if
the team should share it. Baseline checks also work with staged scans and
`--git-history`.

### GitHub Actions

The included workflow tests the package, scans the repository, and uploads a
SARIF report to GitHub Code Scanning. To make it ignore known findings, add the
same key used to create the baseline as a repository Actions secret named
`SECRET_SENTINEL_BASELINE_KEY` (Settings → Secrets and variables → Actions).
The key is only passed to trusted pushes on `main`; pull requests are scanned
without a baseline so untrusted PR code never receives the key. If the key or
baseline file is unavailable on a push, the workflow scans without a baseline.

### Output Formats

Export scan results in different formats for terminal view, script parsing, or CI/CD integration:

```bash
# Standard terminal output (default)
secret-sentinel . --format text

# Machine-readable JSON output
secret-sentinel . --format json

# SARIF v2.1.0 output for GitHub Code Scanning
secret-sentinel . --format sarif --output results.sarif
```

### Inline Ignore Directives

Suppress false positives or intentional test fixtures directly in source code:

```python
# Ignore finding on the current line
api_key = "dummy_mock_key"  # secret-sentinel: ignore reason: synthetic fixture

# Ignore finding on the subsequent line
# secret-sentinel: disable-next-line reason: generated test data; expires: 2027-01-31
api_key = "dummy_mock_key"
```

C-style comments (`// secret-sentinel: ignore` or `/* secret-sentinel: ignore */`)
are also supported. Reasons and expiry dates are optional, and existing bare
directives remain supported. Use `expires: YYYY-MM-DD` to make a suppression
temporary; expired or invalid dates no longer suppress findings.

### Using with the `pre-commit` Framework

You can add Secret Sentinel to your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/tajamul-wani/secret-sentinel
    rev: main
    hooks:
      - id: secret-sentinel
```

### History and Statistics

Track scan results over time:

```bash
# View recent scans (last 10 by default)
secret-sentinel --history

# View more history records
secret-sentinel --history --history-limit 20

# View aggregated statistics
secret-sentinel --stats

# Clear scan history
secret-sentinel --clear-history
```

History is stored locally in `.secret-sentinel/scan_history.jsonl` and includes timestamps, issue counts, and severity breakdowns.

### Installing Git Hook

Install the Git pre-commit hook:

```bash
secret-sentinel --install-hook
```

Remove the hook:

```bash
secret-sentinel --uninstall-hook
```

The installer will not overwrite an existing hook unless it is marked as managed
by Secret Sentinel. Uninstalling removes only a Secret Sentinel-managed hook.

## Use inside another project

1. Install the tool in the target repo.
2. Run the hook installer once:

```bash
secret-sentinel --install-hook
```

3. Commit normally. The tool will scan staged files before the commit is accepted.

If you want to test manually without a hook:

```bash
secret-sentinel --staged
```

## Configuration

Create a `.secret-sentinel.ini` in the repository root:

```ini
[secret-sentinel]
ignore_paths = tests/*, docs/*
ai_enabled = false
ai_cloud_enabled = false
fail_on = HIGH
```

AI validation is disabled by default. To enable local AI validation through
Ollama, set `ai_enabled = true`. Cloud Gemini validation is a separate opt-in:
set both `ai_enabled = true` and `ai_cloud_enabled = true`, and configure
`GEMINI_API_KEY`. Detected secret values are redacted before context is sent to
either AI validator; cloud validation is attempted only when explicitly enabled.

### Using `.secretignore`

You can also create a `.secretignore` file in your repository root to ignore specific paths or mock data:

```text
# Exclude test fixture data
tests/fixtures/*
mock_data/*.json
```

## Safety model

- built-in scanning is local and does not require environment variables
- AI validation is optional and only used if enabled
- the default experience is safe and offline-friendly

## Optional AI validation

If you want stronger validation, you can enable AI checking through a local Ollama setup or a configured Gemini integration. This is optional and not required for the core scanner to work.
