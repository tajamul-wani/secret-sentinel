"""Tests for the aggregate-only Leaky Repo benchmark runner."""

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.benchmark_leaky_repo import (
    BenchmarkError,
    _parse_labels,
    evaluate_benchmark,
    main,
)


def _create_checkout(root: Path, files: Dict[str, bytes]) -> str:
    """Create a temporary benchmark repository and return its commit."""
    subprocess.run(["git", "init", "--quiet", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "Benchmark Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "benchmark@example.test"],
        check=True,
    )
    for relative_path, content in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(root), "commit", "--quiet", "-m", "Add benchmark fixtures"],
        check=True,
    )
    return subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


class TestLeakyRepoBenchmark(unittest.TestCase):
    """Check benchmark validation and aggregate-only reporting."""

    def test_evaluate_reports_count_coverage_without_samples(self) -> None:
        """Aggregate counts must not include matched credential values."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            metadata = (
                b"# file, risk, informative\n"
                b"config.env,1,0\n"
                b"notes.txt,2,0\n"
                b"binary.dat,1,0\n"
            )
            revision = _create_checkout(
                repository,
                {
                    ".leaky-meta/secrets.csv": metadata,
                    "config.env": b'API_TOKEN="sampletokenvalue123456"\n',
                    "notes.txt": b"no matching content\n",
                    "binary.dat": b"\x00binary",
                },
            )

            result = evaluate_benchmark(repository, revision)

        self.assertEqual(result.files_total, 3)
        self.assertEqual(result.files_scanned, 2)
        self.assertEqual(result.files_skipped, 1)
        self.assertEqual(result.files_with_findings, 1)
        self.assertEqual(result.expected_instances, 4)
        self.assertEqual(result.findings, 1)
        self.assertEqual(result.count_matches, 1)
        self.assertEqual(result.count_shortfall, 3)

    def test_main_prints_aggregate_metrics_only(self) -> None:
        """Command output must not contain any scanner sample values."""
        sample_value = "safeSyntheticValue0123456789"
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            revision = _create_checkout(
                repository,
                {
                    ".leaky-meta/secrets.csv": b"config.env,1,0\n",
                    "config.env": f'API_TOKEN="{sample_value}"\n'.encode(),
                },
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main([str(repository), "--revision", revision])

        self.assertEqual(exit_code, 0)
        self.assertIn("Count-based coverage estimate: 1/1", output.getvalue())
        self.assertNotIn(sample_value, output.getvalue())

    def test_rejects_checkout_at_a_different_revision(self) -> None:
        """A benchmark run must use the explicitly requested commit."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            repository = Path(temporary_directory)
            _create_checkout(
                repository,
                {
                    ".leaky-meta/secrets.csv": b"config.env,0,0\n",
                    "config.env": b"sample\n",
                },
            )

            with self.assertRaises(BenchmarkError):
                evaluate_benchmark(repository, "0" * 40)

    def test_rejects_unsafe_label_paths(self) -> None:
        """Label paths must not escape the benchmark repository."""
        with self.assertRaises(BenchmarkError):
            _parse_labels("../outside.txt,1,0\n")


if __name__ == "__main__":
    unittest.main()
