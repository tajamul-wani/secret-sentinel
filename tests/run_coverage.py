"""Stand-alone coverage runner for Secret Sentinel test suite.

Computes exact line coverage using Python's standard library bytecode line tables
and trace module to verify the >=80% coverage protocol requirement without
requiring external network access or third-party packages.
"""

import os
import sys
import trace
import unittest
from pathlib import Path


def get_code_lines(code) -> set:
    """Recursively collect executable line numbers from a code object.

    Args:
        code: Python code object.

    Returns:
        Set of line numbers.
    """
    lines = set()
    for _, _, line in code.co_lines():
        if line is not None:
            lines.add(line)
    for const in code.co_consts:
        if hasattr(const, "co_lines"):
            lines.update(get_code_lines(const))
    return lines


def run_with_coverage() -> int:
    """Run test suite under trace and calculate line coverage."""
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    package_dir = project_root / "secret_sentinel"

    # Reset any cached modules to trace module definitions from the start
    for mod in list(sys.modules.keys()):
        if "secret_sentinel" in mod or "test_" in mod:
            del sys.modules[mod]

    tracer = trace.Trace(
        count=1,
        trace=0,
    )

    def run_tests():
        loader = unittest.TestLoader()
        suite = loader.discover(str(project_root / "tests"), pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=1)
        return runner.run(suite)

    result = tracer.runfunc(run_tests)
    if not result.wasSuccessful():
        print("Tests failed!")
        return 1

    counts = tracer.results().counts

    print("\n" + "=" * 65)
    print("COVERAGE REPORT (secret_sentinel)")
    print("=" * 65)
    print(f"{'Module / File':<35} {'Executable':<12} {'Covered':<10} {'Coverage'}")
    print("-" * 65)

    total_executable = 0
    total_covered = 0

    source_files = [
        f for f in sorted(package_dir.glob("*.py"))
        if not f.name.startswith("__main__")
    ]

    for file_path in source_files:
        canonical_path = str(file_path.resolve())
        with open(file_path, "r", encoding="utf-8") as handle:
            code = compile(handle.read(), canonical_path, "exec")

        exec_lines = get_code_lines(code)
        # Filter line 0 or invalid markers
        exec_lines = {l for l in exec_lines if l > 0}

        executed = sum(1 for line in exec_lines if (canonical_path, line) in counts)

        pct = (executed / len(exec_lines) * 100) if exec_lines else 100.0
        total_executable += len(exec_lines)
        total_covered += executed

        display_name = file_path.name
        print(f"{display_name:<35} {len(exec_lines):<12} {executed:<10} {pct:.1f}%")

    print("-" * 65)
    overall_pct = (total_covered / total_executable * 100) if total_executable else 100.0
    print(f"{'TOTAL':<35} {total_executable:<12} {total_covered:<10} {overall_pct:.1f}%")
    print("=" * 65)

    if overall_pct < 80.0:
        print(f"FAILED: Test coverage ({overall_pct:.1f}%) is below the required 80.0% threshold.")
        return 1

    print(f"PASSED: Test coverage ({overall_pct:.1f}%) meets the >=80% requirement.")
    return 0


if __name__ == "__main__":
    sys.exit(run_with_coverage())
