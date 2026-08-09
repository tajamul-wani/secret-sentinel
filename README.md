# secret-sentinel

`secret-sentinel` is a lightweight Python CLI tool and Git pre-commit hook that prevents hardcoded API keys and secrets from being committed to Git.

`secret-sentinel` is safe by default: built-in scanning runs locally without requiring any environment variables.

## Features

- Local regex-based secret detection
- Shannon entropy scanning for high-entropy strings
- Optional AI context validation using Ollama or Gemini
- Git pre-commit hook installer

## Installation

```bash
python -m pip install .
```

## Usage

Scan staged files:

```bash
secret-sentinel --staged
```

Scan specific files or folders:

```bash
secret-sentinel src/ tests/
```

Skip AI validation:

```bash
secret-sentinel --no-ai
```

Install Git hook:

```bash
secret-sentinel --install-hook
```

Uninstall Git hook:

```bash
secret-sentinel --uninstall-hook
```

Debug mode:

```bash
secret-sentinel --debug --staged
```

## Configuration

Create a `.secret-sentinel.ini` in your repository root to customize behavior.

Example:

```ini
[secret-sentinel]
ignore_paths = tests/*, docs/*
ai_enabled = false
```

## Safety and environment

`secret-sentinel` is safe to use by default and does not require any environment variables for its built-in scanning.

- Tier 1 scanning is completely local: regex patterns and entropy checks run on staged or selected files.
- AI context validation is optional.
- No environment variables are needed unless you want to use Gemini cloud validation.
- If you do use Gemini, set `GEMINI_API_KEY` in your environment.
- Local Ollama validation is also optional and only used when installed.

## AI Context Validation

If you have local Ollama installed, `secret-sentinel` will attempt to validate flagged findings with a local model.

For Gemini cloud validation, set `GEMINI_API_KEY` in your environment.
