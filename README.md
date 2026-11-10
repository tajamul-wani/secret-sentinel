# Secret Sentinel

Local secret scanner for Git repositories. It uses regex and entropy detection and has no runtime dependencies. Python 3.10+.

```bash
python -m pip install .                    # or: pip install "git+https://github.com/tajamul-wani/secret-sentinel.git"
python -m pip install -e ".[dev]"          # dev tooling
```

## Usage

```bash
secret-sentinel .                          # scan working tree (or any files/dirs)
secret-sentinel --staged                   # scan the Git index (default when no paths given)
secret-sentinel --diff origin/main         # added lines in working tree vs a base ref
secret-sentinel --commit-range BASE HEAD   # every commit in BASE..HEAD, incl. secrets later removed
secret-sentinel --git-history [--all-refs] # all commits reachable from HEAD (or all refs)
```

Output: `--format text|json|sarif`, `--output FILE`. Use `--coverage` (path scans only) to report scanned and skipped file counts.

Exit codes: `0` clean, `1` findings at or above the threshold (or a runtime error), `2` invalid usage or config.

Findings are always redacted in output, history and baselines.

## Hooks

```bash
secret-sentinel --install-hook             # pre-commit: scans the index
secret-sentinel --install-pre-push-hook    # pre-push: scans commits not yet on the remote ref
secret-sentinel --uninstall-hook | --uninstall-pre-push-hook
secret-sentinel --init [--yes]             # pre-commit install with confirmation
secret-sentinel --setup                    # interactive setup
secret-sentinel --doctor                   # check repo, config, hooks, baseline
```

The installers never overwrite a hook that Secret Sentinel did not create.

pre-commit framework:

```yaml
repos:
  - repo: https://github.com/tajamul-wani/secret-sentinel
    rev: <tag-or-sha>   # pin; do not track main
    hooks:
      - id: secret-sentinel   # runs: --staged --no-ai
```

## Configuration

`.secret-sentinel.ini` at the repo root:

```ini
[secret-sentinel]
fail_on = HIGH                  # LOW | MEDIUM | HIGH | CRITICAL (default LOW); CLI: --fail-on
ignore_paths = tests/fixtures/creds.json, docs/*.md
ai_enabled = false
ai_cloud_enabled = false

[custom_rules]
Internal API Token = CRITICAL | \bcorp_[A-Za-z0-9]{32}\b
```

- **Ignoring paths.** `.secretignore` takes one glob per line, and `#` starts a comment. Globs are matched with `fnmatch` against repo-relative paths, so `*` also matches `/`. Default ignores cover `.git`, `__pycache__`, `node_modules` and `venv`/`.venv` at any depth, plus root-level `env/` and `.env/` directories.
- **Custom rules.** Each rule is `NAME = SEVERITY | REGEX`, and the reported value is the full match. An invalid severity, an invalid regex, a pattern that matches an empty string, or a name that clashes with a built-in rule exits with code `2`.

### Inline suppression

```python
key = "..."  # secret-sentinel: ignore reason: test fixture expires: 2026-12-31
# secret-sentinel: disable-next-line reason: rotated
key = "..."
```

`#`, `//` and `/* */` comments all work. A suppression whose expiry date has passed, or whose date is invalid, stops suppressing. Run `--audit-suppressions` to list suppressions that are missing a reason, expired or unused.

### Baseline

```bash
export SECRET_SENTINEL_BASELINE_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
secret-sentinel --update-baseline .        # record current findings
secret-sentinel --baseline .               # report only new findings
```

`.secret-sentinel/baseline.json` stores HMAC-SHA-256 fingerprints of `(path, rule, value)`, never the values themselves. Every machine and CI job needs the same key (at least 32 bytes), so keep it in a CI secret and never commit it. Renaming a file changes its fingerprints, so its findings show up as new. `--update-baseline` replaces the file rather than merging into it.

## Detection

Rule pack `3`. Every rule is matched one line at a time, except private keys, which are matched as whole blocks.

| Severity | Rules |
|---|---|
| CRITICAL | AWS secret key, Google API key, Google OAuth client secret, Stripe, GitHub (`ghp_ gho_ ghu_ ghs_ ghr_ github_pat_`), GitLab (`glpat- gldt- glptt- glrt-`), Slack token, Twilio, SendGrid, Azure Storage account key, Shopify, DigitalOcean, Databricks, OpenAI, Anthropic, Hugging Face, PyPI, npm, private keys, DB connection URIs with passwords, `.netrc`, `.pgpass`, Docker registry auth |
| HIGH | JWT, Slack webhook URL, Telegram bot token, Mailchimp, generic `key/token/secret/password = value` (16+ chars), password assignment (8+ chars, at least 2 character classes, quoted or `KEY=value` dotenv style) |
| MEDIUM | AWS access key ID, high-entropy quoted values (Shannon entropy ≥ 4.6, 24+ chars) |

- **Encoded secrets.** Base64 values found in secret-like fields are decoded and checked against the provider rules.
- **Placeholders.** Values like `${VAR}`, `{{x}}`, `<x>`, `your_key_here`, `change-me` and `xxx` are not reported.
- **What gets scanned.** A file counts as binary, and is skipped, if it contains a NUL byte or more than 5% control bytes. UTF-8 and Latin-1 text files are scanned.

## AI validation (optional, off by default)

This step can drop generic, password and entropy findings that a model judges to be false positives. Provider-specific matches are never sent to the model, and the scanned code can't talk it into dropping them.

- **Local.** Set `ai_enabled = true` to use the Ollama CLI. Env vars: `OLLAMA_MODEL` (default `llama3.2`), `OLLAMA_BIN`, `OLLAMA_TIMEOUT` (default 30s).
- **Cloud.** Set `ai_cloud_enabled = true` as well, plus `GEMINI_API_KEY`. Optional env vars: `GEMINI_MODEL` (default `gemini-2.5-flash`) and `GEMINI_API_URL`. Gemini is only tried when Ollama gives no answer.
- **Data sent.** Context is redacted before it leaves the process: three lines around each finding, with known patterns and the detected value removed.
- **Decision rule.** A finding is dropped only when the response is exactly `FALSE_POSITIVE`. Errors, timeouts and any other response keep it.
- Pass `--no-ai` to skip validation for a single run.

## History

```bash
secret-sentinel --history [--history-limit N] | --stats | --clear-history
```

Scan results are stored locally in `.secret-sentinel/scan_history.jsonl`: counts and severities only, no values.

## CI

Minimal PR scan:

```yaml
on:
  pull_request:
permissions:
  contents: read
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0          # range scans need full history
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: python -m pip install "git+https://github.com/tajamul-wani/secret-sentinel.git"
      - env:
          PR_BASE_REF: ${{ github.base_ref }}
        run: secret-sentinel --commit-range "origin/$PR_BASE_REF" HEAD --no-ai
```

The baseline key is only passed to trusted pushes on `main`; pull-request scans run without it. See [.github/workflows/python-app.yml](.github/workflows/python-app.yml) for the full setup: tests on Python 3.10–3.12, `--baseline` on push, and SARIF upload to code scanning.

## Development

```bash
python -m unittest discover -s tests       # or: pytest
python tests/run_coverage.py               # stdlib coverage, fails under 80%
python -m scripts.benchmark_leaky_repo /path/to/leaky-repo --revision <sha>
```

The detection quality tests (`tests/test_detection_quality.py`) run against a synthetic corpus and report precision and recall per rule. Because that corpus is maintained alongside the rules, use the Leaky Repo benchmark to see how detection holds up on outside data.

Layout:

- `scanner.py`: rules and scan modes
- `cli.py`: entry point and hooks
- `formatters.py`: text, JSON and SARIF output
- `config.py`: config loading
- `baseline.py`, `history.py`, `remediation.py`, `risk_scoring.py`, `ai_validator.py`

## License

MIT
