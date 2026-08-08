# secret-sentinel

`secret-sentinel` is a lightweight Python CLI tool and Git pre-commit hook that prevents hardcoded API keys and secrets from being committed to Git.

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
secret-sentinel
```

Scan files or folders:

```bash
secret-sentinel src/ tests/
```

Install Git hook:

```bash
secret-sentinel --install-hook
```

## AI Context Validation

If you have local Ollama installed, `secret-sentinel` will attempt to validate flagged findings with a local model.

For Gemini cloud validation, set `GEMINI_API_KEY` in your environment.
