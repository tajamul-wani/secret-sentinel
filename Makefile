.PHONY: test coverage scan scan-staged install-hook uninstall-hook clean

PYTHON ?= python3

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py"

coverage:
	$(PYTHON) tests/run_coverage.py

scan:
	$(PYTHON) -m secret_sentinel.cli .

scan-staged:
	$(PYTHON) -m secret_sentinel.cli --staged

install-hook:
	$(PYTHON) -m secret_sentinel.cli --install-hook

uninstall-hook:
	$(PYTHON) -m secret_sentinel.cli --uninstall-hook

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[cod]" -delete
	rm -rf .coverage htmlcov .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info

