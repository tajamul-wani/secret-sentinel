# Secret Sentinel

A local secret scanner for Git repositories. It finds hardcoded credentials
in files, staged changes, and commit history before they reach a remote.

- Runs offline with no runtime dependencies
- Works as a pre-commit hook, a pre-push hook, or a GitHub Action
- Never prints detected values; reports are always redacted
- Requires Python 3.10 or later

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Scan modes](#scan-modes)
- [Git hooks](#git-hooks)
- [CI](#ci)
- [Configuration](#configuration)
- [Suppressing findings](#suppressing-findings)
- [Baseline](#baseline)
- [Detection](#detection)
- [AI validation](#ai-validation)
- [Development](#development)

## Install

```bash
pipx install secret-sentinel
```

Or with pip:

```bash
python -m pip install secret-sentinel
```

## Quick start

Run these from the root of your repository.

```bash
secret-sentinel --setup
secret-sentinel .
secret-sentinel --doctor
```

| Command | What it does |
|---|---|
| `--setup` | Guided setup for hooks, baseline, and CI |
| `.` | Scans the working tree |
| `--doctor` | Checks the repository, config, and hooks |

## Scan modes

```bash
secret-sentinel .
secret-sentinel src/ config.yaml
secret-sentinel --staged
secret-sentinel --diff origin/main
secret-sentinel --commit-range origin/main HEAD
secret-sentinel --git-history
```

| Mode | Scans |
|---|---|
| paths | Files and folders on disk |
| `--staged` | The Git index (default when no paths are given) |
| `--diff BASE` | Lines added since `BASE` |
| `--commit-range BASE HEAD` | Every commit in the range, including secrets added and later removed |
| `--git-history` | All commits reachable from `HEAD` (add `--all-refs` for all branches) |

### Output

```bash
secret-sentinel . --format json
secret-sentinel . --format sarif --output results.sarif
secret-sentinel . --coverage
```

- `--format` accepts `text` (default), `json`, or `sarif`.
- `--coverage` lists scanned and skipped file counts for path scans.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above the threshold |
| `1` | Findings at or above the threshold, or a scan error |
| `2` | Invalid arguments or configuration |

## Git hooks

```bash
secret-sentinel --install-hook
secret-sentinel --install-pre-push-hook
```

- The pre-commit hook scans staged changes.
- The pre-push hook scans commits that are not yet on the remote.
- Remove them with `--uninstall-hook` and `--uninstall-pre-push-hook`.
- Existing hooks that Secret Sentinel did not create are never replaced.

### pre-commit framework

```yaml
repos:
  - repo: https://github.com/tajamul-wani/secret-sentinel
    rev: v0.2.0
    hooks:
      - id: secret-sentinel
```

## CI

Add the GitHub Action to a workflow:

```yaml
on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: tajamul-wani/secret-sentinel@v0.2.0
```

Optional inputs:

| Input | Default | Description |
|---|---|---|
| `fail-on` | `LOW` | Minimum severity that fails the job |
| `sarif` | `false` | Send results to code scanning (needs `security-events: write`) |

What the action scans:

| Event | Scan |
|---|---|
| Pull request | All commits between the base branch and `HEAD` |
| Push | The pushed commits |
| New branch or force push | The working tree |

Notes:

- Shallow checkouts are handled automatically.
- The action installs Python 3.12, which later steps in the job will use.
- Make the scan a required status check. Local hooks can be skipped with
  `--no-verify`; CI cannot.
- The baseline key is only passed to trusted pushes on `main`;
  pull-request scans run without it.

## Configuration

Create `.secret-sentinel.ini` in the repository root:

```ini
[secret-sentinel]
fail_on = HIGH
ignore_paths = tests/fixtures/*, docs/*.md

[custom_rules]
Internal Token = CRITICAL | \bcorp_[A-Za-z0-9]{32}\b
```

| Setting | Description |
|---|---|
| `fail_on` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. Default `LOW`. Override with `--fail-on`. |
| `ignore_paths` | Comma-separated globs, relative to the repository root |
| `custom_rules` | One rule per line: `NAME = SEVERITY \| REGEX` |

You can also list ignore globs in `.secretignore`, one per line.

Ignored by default:

- `.git`, `node_modules`, `venv`, `.venv`, and `__pycache__` at any depth
- `env/` and `.env/` at the repository root
- Minified bundles and source maps: `*.min.js`, `*.min.css`, `*.map`

Lockfiles are still scanned because registry URLs can contain tokens.

## Suppressing findings

Add a comment on the same line:

```python
key = "..."  # secret-sentinel: ignore reason: fixture
```

Or on the line before:

```python
# secret-sentinel: disable-next-line reason: fixture
key = "..."
```

- Add `expires: YYYY-MM-DD` to make a suppression temporary.
- `#`, `//`, and `/* */` comments are supported.
- Run `secret-sentinel --audit-suppressions` to find suppressions that are
  missing a reason, expired, or no longer needed.

## Baseline

Use a baseline to accept existing findings and fail only on new ones.

```bash
secret-sentinel --update-baseline .
secret-sentinel --baseline .
```

- Fingerprints are stored in `.secret-sentinel/baseline.json`. Secret
  values are never stored.
- Baseline commands need a shared key of at least 32 bytes in
  `SECRET_SENTINEL_BASELINE_KEY`. Store it as a CI secret and never
  commit it.
- Renaming a file makes its findings appear as new.

Generate a key:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Detection

| Severity | Detects |
|---|---|
| Critical | Cloud and SaaS keys: AWS, Google, Azure Storage, Stripe, GitHub, GitLab, Slack, Twilio, SendGrid, Shopify, DigitalOcean, Databricks, OpenAI, Anthropic, Hugging Face, PyPI, npm |
| Critical | Private keys, database URLs with passwords, `.netrc`, `.pgpass`, Docker registry auth |
| High | JWTs, Slack webhooks, Telegram bot tokens, Mailchimp keys |
| High | Generic `key`, `token`, `secret`, and `password` assignments |
| Medium | AWS access key IDs and high-entropy values in secret fields |

How scanning works:

- Base64 values in secret fields are decoded and checked again.
- Placeholders such as `${VAR}`, `<value>`, and `your_key_here` are skipped.
- Binary files are skipped. UTF-8 and Latin-1 text files are scanned.
- Files larger than 5 MB are skipped and counted in `--coverage`.

## AI validation

AI validation is optional and disabled by default. When enabled, a model can
discard generic findings that look like test data. Provider-specific matches,
such as a GitHub token, are always kept.

```ini
[secret-sentinel]
ai_enabled = true
```

| Backend | Setup |
|---|---|
| Ollama (local) | Install Ollama. Optional: `OLLAMA_MODEL`, `OLLAMA_TIMEOUT` |
| Gemini (cloud) | Also set `ai_cloud_enabled = true` and `GEMINI_API_KEY` |

- Detected values are redacted before any context is sent.
- If the model is unavailable or unclear, the finding is kept.
- Use `--no-ai` to skip validation for a single run.

## Development

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests
python tests/run_coverage.py
```

The coverage check fails below 80%.

To release a new version:

1. Update `__version__` in `secret_sentinel/__init__.py`.
2. Push a tag that matches it, for example `v0.2.0`.

The release workflow tests, builds, and publishes to PyPI, then creates a
GitHub release.

## License

MIT
