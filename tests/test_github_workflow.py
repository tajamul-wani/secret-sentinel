"""Contract tests for the documented and repository GitHub Actions scans."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "python-app.yml"
README_PATH = ROOT / "README.md"


class TestGitHubWorkflow(unittest.TestCase):
    """Keep CI scan safety and the README example aligned with the CLI."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read workflow and documentation sources once for contract tests."""
        cls.workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.readme = README_PATH.read_text(encoding="utf-8")

    def _workflow_step(self, name: str) -> str:
        """Return one named workflow step or fail if the step was removed."""
        match = re.search(
            rf"(?ms)^      - name: {re.escape(name)}\n(.*?)(?=^      - name:|\Z)",
            self.workflow,
        )
        self.assertIsNotNone(match, f"Workflow step not found: {name}")
        return match.group(0) if match else ""

    def test_workflow_runs_for_main_pushes_and_pull_requests(self) -> None:
        """The repository workflow should cover both main pushes and pull requests."""
        self.assertRegex(self.workflow, r"(?m)^  push:\n    branches: \[ main \]")
        self.assertRegex(
            self.workflow,
            r"(?m)^  pull_request:\n    branches: \[ main \]",
        )

    def test_pull_request_scan_uses_commit_range_without_baseline_key(self) -> None:
        """Untrusted pull requests scan commits without receiving secrets."""
        self.assertNotRegex(self.workflow, r"(?m)^(?:env| {4}env):")
        step = self._workflow_step(
            "Scan pull request commit range and generate SARIF report"
        )
        self.assertIn("if: github.event_name == 'pull_request'", step)
        self.assertIn("PR_BASE_REF: ${{ github.base_ref }}", step)
        self.assertIn(
            'secret-sentinel --commit-range "origin/$PR_BASE_REF" HEAD', step
        )
        self.assertIn("--format sarif --output results.sarif", step)
        self.assertNotIn("SECRET_SENTINEL_BASELINE_KEY", step)

    def test_push_baseline_key_is_scoped_to_push_scan(self) -> None:
        """The baseline key should only enter the trusted push scan step."""
        step = self._workflow_step("Scan push and generate SARIF report")
        self.assertIn("if: github.event_name == 'push'", step)
        self.assertIn(
            "SECRET_SENTINEL_BASELINE_KEY: ${{ secrets.SECRET_SENTINEL_BASELINE_KEY }}",
            step,
        )
        self.assertIn(
            '[[ -n "$SECRET_SENTINEL_BASELINE_KEY" && '
            "-f .secret-sentinel/baseline.json ]]",
            step,
        )
        self.assertIn("secret-sentinel --baseline . --format sarif", step)
        self.assertIn("secret-sentinel . --format sarif", step)

    def test_readme_workflow_example_scans_pr_range_without_credentials(self) -> None:
        """The copyable README workflow should implement the same safe PR scan."""
        section_start = self.readme.index("### GitHub Actions")
        section_end = self.readme.index("### Output Formats", section_start)
        section = self.readme[section_start:section_end]
        match = re.search(r"```yaml\n(.*?)\n```", section, re.DOTALL)
        self.assertIsNotNone(match, "README GitHub Actions YAML example is missing")
        example = match.group(1) if match else ""

        self.assertIn("pull_request:", example)
        self.assertIn("permissions:\n  contents: read", example)
        self.assertIn("fetch-depth: 0", example)
        self.assertIn("PR_BASE_REF: ${{ github.base_ref }}", example)
        self.assertIn(
            'secret-sentinel --commit-range "origin/$PR_BASE_REF" HEAD', example
        )
        self.assertNotIn("SECRET_SENTINEL_BASELINE_KEY", example)
        self.assertNotIn("secrets.", example)
        self.assertIn(
            "The baseline key is only passed to trusted pushes on `main`;",
            section,
        )
        self.assertIn("pull-request scans run without it.", section)


if __name__ == "__main__":
    unittest.main()
