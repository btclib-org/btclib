# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Re-derive tests/python_arm_authority_test.py's `_AUTHORITY`, monthly.

That file's docstring documents the measurement by hand: per third-party
test module, in an environment with no bindings installed,

    uv sync --no-default-groups --group harness
    pytest <one module> --cov=btclib --cov-report=json --cov-fail-under=0

reading back which lines of each Python arm ran, the `def` line excluded
since it runs at import regardless of whether the function is ever
called. `_AUTHORITY`'s entries were built that way once and are re-run by
nothing -- issue #1003: a test module that stops exercising an arm keeps
the arm's entry, and the claim goes stale on an otherwise green suite.

This repeats the measurement, module by module over every module named in
`_THIRD_PARTY_VECTORS`, and diffs the result against `_AUTHORITY` in both
directions plus the one `_WITHOUT_AN_AUTHORITY` exists to notice:

- an entry claims a module whose run no longer reaches the arm --
  STALE, the harmful direction, an entry that outlived what made it true;
- a module's run reaches an arm its entry does not name -- UNDERSTATED,
  benign and still worth a line, since the entry is not wrong, only
  incomplete;
- something now reaches an arm in `_WITHOUT_AN_AUTHORITY` -- NEW
  AUTHORITY, the good news that set exists to pick up.

Reuses `tests/python_arm_authority_test.py`'s own `_arm_locations` for
where each arm's body lives rather than re-walking the AST: one parser,
one definition of "arm", read by the shape tests, the content tests and
this script alike.

    uv sync --no-default-groups --group harness
    python .github/scripts/check_python_arm_authority.py

Not a gate: `.github/workflows/python-arm-authority.yml` runs this on a
schedule, with no branch rule attached, for the reason `vendored-vectors`
and `published` already establish -- every module under coverage is
minutes, and it answers a question no pull request introduces.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

from tests.python_arm_authority_test import (  # noqa: E402
    _AUTHORITY,
    _THIRD_PARTY_VECTORS,
    _WITHOUT_AN_AUTHORITY,
    _arm_locations,
)


def _run_coverage(module: str, report_path: Path) -> dict[str, set[int]]:
    """Run tests/<module> under coverage and return its executed lines by file.

    The exact command the docstrings of this file and
    tests/python_arm_authority_test.py both give, `--cov-report` pointed
    at a file of its own so each module's run leaves the others untouched.
    `check=True`: a test module failing outright is not a disagreement
    this script is built to phrase, and is worth a loud traceback rather
    than a silently empty coverage report.
    """
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            f"tests/{module}",
            "--cov=btclib",
            f"--cov-report=json:{report_path}",
            "--cov-fail-under=0",
        ],
        cwd=_ROOT,
        check=True,
    )
    data = json.loads(report_path.read_text(encoding="utf-8"))
    return {file: set(info["executed_lines"]) for file, info in data["files"].items()}


def _reached(
    executed_by_file: dict[str, set[int]],
    locations: dict[str, tuple[Path, int, int]],
) -> set[str]:
    """Return every arm this one run's coverage reached, `def` line excluded."""
    reached = set()
    for arm, (path, start, end) in locations.items():
        rel = str(path.relative_to(_ROOT))
        if executed_by_file.get(rel, set()) & set(range(start, end + 1)):
            reached.add(arm)
    return reached


def measure() -> dict[str, frozenset[str]]:
    """Return, for every arm, the third-party modules that actually reach it.

    One coverage run per module named in `_THIRD_PARTY_VECTORS`, each
    against a fresh report file so one module's measurement cannot leak
    into another's.
    """
    locations = _arm_locations()
    actual: dict[str, set[str]] = {arm: set() for arm in locations}
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        for index, module in enumerate(sorted(_THIRD_PARTY_VECTORS)):
            print(f"measuring {module} ...")
            executed = _run_coverage(module, tmp_path / f"{index}.json")
            for arm in _reached(executed, locations):
                actual[arm].add(module)
    return {arm: frozenset(modules) for arm, modules in actual.items()}


def compare(actual: dict[str, frozenset[str]]) -> list[str]:
    """Return one line per arm whose measured reach disagrees with `_AUTHORITY`.

    Each line is prefixed STALE, UNDERSTATED or NEW AUTHORITY, the three
    directions this file's own docstring names.
    """
    mismatches = []
    for arm, claimed in sorted(_AUTHORITY.items()):
        found = actual.get(arm, frozenset())
        stale = set(claimed) - found
        understated = found - set(claimed)
        if stale:
            mismatches.append(
                f"STALE: {arm} claims {sorted(stale)}, whose run no longer reaches it"
            )
        if understated:
            label = "NEW AUTHORITY" if arm in _WITHOUT_AN_AUTHORITY else "UNDERSTATED"
            mismatches.append(
                f"{label}: {arm} is reached by {sorted(understated)},"
                " not named in its entry"
            )
    return mismatches


def main() -> int:
    """Measure, compare, print, and fail on any disagreement found."""
    mismatches = compare(measure())
    for line in mismatches:
        print(line)
    if mismatches:
        print(f"{len(mismatches)} disagreement(s) with a fresh measurement.")
        return 1
    print("Every _AUTHORITY entry matches a fresh no-bindings measurement.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
