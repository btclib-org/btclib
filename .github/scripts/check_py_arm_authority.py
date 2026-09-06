# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Re-derive tests/py_arm_authority_test.py's `_AUTHORITY`, weekly.

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

Reuses `tests/py_arm_authority_test.py`'s own `_arm_locations` for
where each arm's body lives rather than re-walking the AST: one parser,
one definition of "arm", read by the shape tests, the content tests and
this script alike.

A disagreement is reported twice: this exits non-zero, which is what
makes the run red, and it opens or updates a tracking issue under the
title it is given, closing that issue with a comment once a measurement
agrees again. The two are not alternatives. A failed scheduled run
notifies the last person to have touched the cron, once, and
`tests/py_arm_authority_test.py` reads the table's shape and never its
values -- so an entry claiming a reach the suite no longer has leaves
every other check in the tree green, and the open issue is what still
says otherwise.

The title is the caller's rather than a constant here, which is what
`check_vendored_vectors.py` beside it does: what an issue this
repository files is called then sits in the workflow that files it,
beside the trigger and the permission that let it, rather than in a
script the workflow only names.

    uv sync --no-default-groups --group harness
    python .github/scripts/check_py_arm_authority.py "<issue title>"

Not a gate: `.github/workflows/py-arm-authority.yml` runs this on a
schedule, with no branch rule attached, for the reason `vendored-vectors`
and `pypi-install` already establish -- every module under coverage is
minutes, and it answers a question no pull request introduces.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

# resolved once: S607 is what a bare "gh" in a subprocess list would be,
# a partial executable path relying on PATH's own search order rather
# than naming what actually runs
_GH = shutil.which("gh") or "gh"

from tests.py_arm_authority_test import (  # noqa: E402
    _AUTHORITY,
    _THIRD_PARTY_VECTORS,
    _WITHOUT_AN_AUTHORITY,
    _arm_locations,
)


def _run_coverage(module: str, report_path: Path) -> dict[str, set[int]]:
    """Run tests/<module> under coverage and return its executed lines by file.

    The exact command the docstrings of this file and
    tests/py_arm_authority_test.py both give, `--cov-report` pointed
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


def _issue_body(mismatches: list[str]) -> str:
    """Return the issue body: the lines stdout carries, and where to look.

    The same strings `compare` built, rather than a second phrasing of
    them: one description of a disagreement, printed by the run and read
    by whoever opens the issue.
    """
    return "\n".join(
        [
            (
                "A fresh no-bindings measurement disagrees with"
                " `tests/py_arm_authority_test.py`'s `_AUTHORITY`."
            ),
            (
                "The run that measured it is red as well, and stays red"
                " until the table and the measurement agree."
            ),
            "",
            *(f"- {line}" for line in mismatches),
        ]
    )


def _open_issue_number(title: str) -> str | None:
    result = subprocess.run(  # noqa: S603
        [
            _GH,
            "issue",
            "list",
            "--state",
            "open",
            "--search",
            f'"{title}" in:title',
            "--json",
            "number",
        ],
        capture_output=True,
        check=True,
        encoding="utf-8",
    )
    issues = json.loads(result.stdout)
    return str(issues[0]["number"]) if issues else None


def report(title: str, mismatches: list[str]) -> None:
    """Open, update, or close this census's tracking issue, whichever applies.

    The title is the search term that finds an issue already open as
    well as the title a new one is created under, so it is a caller's
    argument: the workflow above this script is where what this run
    files is named.
    """
    number = _open_issue_number(title)
    if not mismatches:
        if number is not None:
            subprocess.run(  # noqa: S603
                [
                    _GH,
                    "issue",
                    "close",
                    number,
                    "--comment",
                    (
                        "Re-measured: every _AUTHORITY entry matches a fresh"
                        " no-bindings measurement."
                    ),
                ],
                check=True,
            )
        return
    body = _issue_body(mismatches)
    if number is None:
        subprocess.run(  # noqa: S603
            [_GH, "issue", "create", "--title", title, "--body", body],
            check=True,
        )
    else:
        subprocess.run(  # noqa: S603
            [_GH, "issue", "edit", number, "--body", body], check=True
        )


def main() -> int:
    """Measure, compare, print, report, and fail on any disagreement found.

    The title names the issue this run opens, updates or closes. It is
    required, which is what makes it a positional: a default would name
    the issue in the one place a reader of the workflow does not look.
    The one option here is a boolean, so what reads it is the filter
    below rather than a parser.

    --dry-run skips opening, updating or closing that issue: what the
    pull_request trigger of py-arm-authority.yml passes, so a change to
    this script, to the workflow or to the table is exercised without
    the run editing whatever tracking issue happens to be open at the
    time.

    `report` runs before the non-zero return rather than after it: the
    exit code is what makes the run red, and the issue is what outlives
    the notification that run sends.
    """
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry_run = len(args) != len(sys.argv) - 1
    if len(args) != 1:
        # a human running this by hand is the only way here, the workflow
        # passing the title every time: without this check, the unpacking
        # below would answer with a ValueError naming a list instead
        print(
            f"usage: {Path(sys.argv[0]).name} <issue title> [--dry-run]",
            file=sys.stderr,
        )
        return 2
    (title,) = args
    mismatches = compare(measure())
    for line in mismatches:
        print(line)
    if mismatches:
        print(f"{len(mismatches)} disagreement(s) with a fresh measurement.")
    else:
        print("Every _AUTHORITY entry matches a fresh no-bindings measurement.")
    if not dry_run:
        report(title, mismatches)
    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
