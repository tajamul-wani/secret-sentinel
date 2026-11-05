"""Measure count-based coverage against a local Leaky Repo checkout."""

import argparse
import csv
import io
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import List, Optional, Sequence, Tuple

from secret_sentinel.scanner import scan_text
from secret_sentinel.utils import is_text_bytes

_METADATA_PATH = ".leaky-meta/secrets.csv"
_REVISION_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class BenchmarkError(Exception):
    """Raised when the benchmark checkout or labels are invalid."""


@dataclass(frozen=True)
class BenchmarkResult:
    """Aggregate scanner counts for one pinned benchmark revision."""

    revision: str
    files_total: int
    files_scanned: int
    files_skipped: int
    files_with_findings: int
    expected_instances: int
    findings: int
    count_matches: int
    count_shortfall: int
    count_overage: int


def _git_output(repository: Path, arguments: Sequence[str]) -> bytes:
    """Return Git output without exposing repository content in errors."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise BenchmarkError("Unable to run Git for the benchmark checkout.") from error
    if result.returncode:
        raise BenchmarkError("Unable to read the pinned benchmark revision.")
    return result.stdout


def _parse_labels(raw_csv: str) -> List[Tuple[str, int]]:
    """Parse file-level expected instance counts from benchmark metadata."""
    labels: List[Tuple[str, int]] = []
    seen_paths: set[str] = set()
    try:
        rows = csv.reader(
            line
            for line in io.StringIO(raw_csv)
            if line.strip() and not line.lstrip().startswith("#")
        )
        for row in rows:
            if len(row) != 3:
                raise BenchmarkError("Benchmark labels have an invalid row format.")
            path, risk_count, informative_count = row
            relative_path = PurePosixPath(path)
            if (
                not path
                or relative_path.is_absolute()
                or not relative_path.parts
                or "\\" in path
                or ":" in path
                or any(part in {"", ".", ".."} for part in relative_path.parts)
                or path in seen_paths
            ):
                raise BenchmarkError("Benchmark labels contain an invalid file path.")
            expected = int(risk_count) + int(informative_count)
            if int(risk_count) < 0 or int(informative_count) < 0:
                raise BenchmarkError("Benchmark labels contain invalid counts.")
            labels.append((path, expected))
            seen_paths.add(path)
    except (csv.Error, ValueError) as error:
        message = "Benchmark labels contain invalid counts or CSV data."
        raise BenchmarkError(message) from error
    if not labels:
        raise BenchmarkError("Benchmark labels contain no file records.")
    return labels


def evaluate_benchmark(repository: Path, revision: str) -> BenchmarkResult:
    """Evaluate a pinned local checkout and return aggregate counts only."""
    if not _REVISION_PATTERN.fullmatch(revision):
        raise BenchmarkError("Provide the full 40-character benchmark commit.")
    repository = repository.resolve()
    if not repository.is_dir():
        raise BenchmarkError("The benchmark checkout is not a directory.")
    actual_revision = _git_output(repository, ["rev-parse", "HEAD"]).decode(
        "ascii",
        errors="replace",
    ).strip()
    if actual_revision.lower() != revision.lower():
        message = "The benchmark checkout does not match the requested commit."
        raise BenchmarkError(message)

    metadata = _git_output(repository, ["show", f"{actual_revision}:{_METADATA_PATH}"])
    labels = _parse_labels(metadata.decode("utf-8", errors="replace"))
    files_scanned = files_skipped = 0
    files_with_findings = expected_instances = findings = 0
    count_matches = count_shortfall = count_overage = 0

    for path, expected in labels:
        expected_instances += expected
        blob = _git_output(repository, ["show", f"{actual_revision}:{path}"])
        if not is_text_bytes(blob):
            files_skipped += 1
            count_shortfall += expected
            continue
        files_scanned += 1
        file_findings = len(
            scan_text(blob.decode("utf-8", errors="replace"), path)
        )
        findings += file_findings
        files_with_findings += file_findings > 0
        count_matches += min(file_findings, expected)
        count_shortfall += max(expected - file_findings, 0)
        count_overage += max(file_findings - expected, 0)

    return BenchmarkResult(
        revision=actual_revision,
        files_total=len(labels),
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        files_with_findings=files_with_findings,
        expected_instances=expected_instances,
        findings=findings,
        count_matches=count_matches,
        count_shortfall=count_shortfall,
        count_overage=count_overage,
    )


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Measure count-based coverage on a local Leaky Repo checkout."
    )
    parser.add_argument("repository", type=Path, help="Local benchmark checkout")
    parser.add_argument(
        "--revision",
        required=True,
        help="Full commit SHA checked out in the benchmark repository",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Run the benchmark and print aggregate metrics without sample findings."""
    parser = _build_parser()
    arguments = parser.parse_args(argv)
    try:
        result = evaluate_benchmark(arguments.repository, arguments.revision)
    except BenchmarkError as error:
        print(f"Benchmark failed: {error}", file=sys.stderr)
        return 2

    coverage = (
        result.count_matches / result.expected_instances
        if result.expected_instances
        else 0.0
    )
    print(f"Benchmark commit: {result.revision}")
    print(
        f"Files scanned: {result.files_scanned}/{result.files_total}; "
        f"files with findings: {result.files_with_findings}; "
        f"binary files skipped: {result.files_skipped}"
    )
    print(
        f"Count-based coverage estimate: {result.count_matches}/"
        f"{result.expected_instances} ({coverage:.1%})"
    )
    print(
        f"Raw findings: {result.findings}; count shortfall: "
        f"{result.count_shortfall}; count overage: {result.count_overage}"
    )
    print(
        "Counts are compared per file; they do not establish finding-level "
        "matches or precision and recall."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
