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

Or, in a project you want to protect:

```bash
python -m pip install "git+https://github.com/your-org/secret-sentinel.git"
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

### Configurable Failure Threshold

Configure which severity level blocks commits or causes CI to fail:

```bash
# Block only on HIGH or CRITICAL severity, warning on MEDIUM/LOW
secret-sentinel --staged --fail-on HIGH

# Default behavior: blocks on any detected issue (LOW or higher)
secret-sentinel --staged --fail-on LOW
```

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
api_key = "dummy_mock_key"  # secret-sentinel: ignore

# Ignore finding on the subsequent line
# secret-sentinel: disable-next-line
api_key = "dummy_mock_key"
```

C-style comments (`// secret-sentinel: ignore` or `/* secret-sentinel: ignore */`) are also supported.

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

## Contributing

Contributions are welcome. Keep changes focused, keep the tool safe by default, and avoid adding internal notes or private metadata to public project files.
