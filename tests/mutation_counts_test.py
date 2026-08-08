# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the mutation session counter of `.github/scripts`.

The script is what the `mutation` workflow prints, and what it prints is the
only thing anybody reads on Monday: a wrong denominator, or an outcome left
out of the line, is a session that measured less than it appears to. Neither
is visible in a green run, so it is tested here instead.

Sessions are built with the schema Cosmic Ray creates, recorded below from a
real one -- `cosmic-ray init` on any profile under `.github/mutation` is what
re-derives it. A synthetic session is what lets a test hold the rows a real
run only produces when something goes wrong: an INCOMPETENT mutant, a worker
that raised, a session with nothing in it at all.

The script is loaded by path, `.github/scripts` being no package: the
standalone client test does the same for the same reason.
"""

from __future__ import annotations

import importlib.util
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "mutation_counts.py"

# the three tables `cosmic-ray init` creates, as it creates them. Only two are
# read here; `mutation_specs` is recorded so that a session built by this file
# is one the real tools could also open, rather than the subset one script
# happens to need
_SCHEMA = """
CREATE TABLE work_items (job_id VARCHAR NOT NULL, PRIMARY KEY (job_id));
CREATE TABLE mutation_specs (
    module_path VARCHAR, operator_name VARCHAR, operator_args JSON,
    occurrence INTEGER, start_pos_row INTEGER, start_pos_col INTEGER,
    end_pos_row INTEGER, end_pos_col INTEGER, definition_name VARCHAR,
    job_id VARCHAR NOT NULL, PRIMARY KEY (job_id),
    FOREIGN KEY(job_id) REFERENCES work_items (job_id)
);
CREATE TABLE work_results (
    worker_outcome VARCHAR(9), output TEXT, test_outcome VARCHAR(11),
    diff TEXT, job_id VARCHAR NOT NULL, PRIMARY KEY (job_id),
    FOREIGN KEY(job_id) REFERENCES work_items (job_id)
);
"""


@pytest.fixture(scope="module")
def counter() -> ModuleType:
    """Return the script, imported by path."""
    spec = importlib.util.spec_from_file_location("mutation_counts", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def session(
    path: Path, results: list[tuple[str | None, str]], pending: int = 0
) -> Path:
    """Write a session holding these results, and `pending` mutants with none.

    Each result is the pair the script reads: the test outcome, which is None
    for a mutant no suite judged, and the worker outcome beside it.
    """
    db = sqlite3.connect(path)
    with db:
        db.executescript(_SCHEMA)
        for index, (test_outcome, worker_outcome) in enumerate(results):
            job_id = f"job-{index}"
            db.execute("INSERT INTO work_items VALUES (?)", (job_id,))
            db.execute(
                "INSERT INTO work_results"
                " (worker_outcome, output, test_outcome, diff, job_id)"
                " VALUES (?, NULL, ?, NULL, ?)",
                (worker_outcome, test_outcome, job_id),
            )
        for index in range(pending):
            db.execute("INSERT INTO work_items VALUES (?)", (f"pending-{index}",))
    db.close()
    return path


def test_the_rate_is_over_the_mutants_that_ran(
    counter: ModuleType, tmp_path: Path
) -> None:
    """Skipped mutants are not kills, and are not in the denominator.

    The shape of the profile this script was written for: an operator filter
    excludes a family before anything runs it, so the session holds three
    kinds of row and only two of them are verdicts. `cr-rate` counts the
    skipped as killed and divides by all of them, which is the whole reason
    this exists -- 7 survivors of 532 read as 0.97% rather than 1.32%.
    """
    results: list[tuple[str | None, str]] = [("KILLED", "NORMAL")] * 525
    results += [("SURVIVED", "NORMAL")] * 7
    results += [(None, "SKIPPED")] * 187
    line, sound = counter.report(
        counter.counts(session(tmp_path / "s.sqlite", results)), 719
    )
    assert sound
    assert "killed 525, survived 7, skipped 187" in line
    assert "over the 532 executed: 1.32%" in line


def test_an_outcome_that_is_no_verdict_is_named_and_is_not_sound(
    counter: ModuleType, tmp_path: Path
) -> None:
    """INCOMPETENT, EXCEPTION, ABNORMAL and NO_TEST are the measurement failing.

    `cosmic-ray exec` can finish with a zero exit having recorded them, so
    nothing else says they happened. Counting them as killed would flatter the
    rate, counting them as executed would deflate it, and leaving them out of
    the line publishes a session that measured less than it appears to: the
    only honest answer is to name them and be red.
    """
    results: list[tuple[str | None, str]] = [
        ("KILLED", "NORMAL"),
        ("SURVIVED", "NORMAL"),
        (None, "SKIPPED"),
        # the pair Cosmic Ray actually writes when `mutate_and_test` raises:
        # one row carrying both, where a `COALESCE(test_outcome,
        # worker_outcome)` answers INCOMPETENT and never names the exception
        ("INCOMPETENT", "EXCEPTION"),
        ("INCOMPETENT", "NORMAL"),
        (None, "ABNORMAL"),
        (None, "NO_TEST"),
    ]
    line, sound = counter.report(
        counter.counts(session(tmp_path / "s.sqlite", results, pending=1)), 8
    )
    assert not sound
    assert "killed 1, survived 1, skipped 1, never run 1" in line
    # named one by one, and `no-test` in the spelling of the enum rather than
    # of the column. The exception is there rather than hidden behind the
    # INCOMPETENT its own row also carries
    assert "No verdict on the suite: abnormal 1, exception 1, incompetent 1" in line
    assert "no-test 1" in line


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(
            "session?copy.sqlite",
            marks=pytest.mark.skipif(
                sys.platform == "win32",
                reason="NTFS refuses `?` in a filename, so there is none to write",
            ),
        ),
        "session#copy.sqlite",
    ],
)
def test_a_session_whose_name_is_not_a_uri(
    counter: ModuleType, tmp_path: Path, name: str
) -> None:
    """A path is not a URI, and `?` and `#` are ordinary in a filename.

    Interpolated into `file:{path}?mode=ro`, the first of those names the
    database `session` and reads the rest as query parameters: the wrong file,
    `no such table`, and a `session` created beside it -- the `mode=ro` that
    would have forbidden the creation having been parsed as part of the name.
    A downloaded session artifact is exactly where a `?` in a name comes from.

    Skipped for `?` on Windows: NTFS refuses that character in a filename, so
    the fixture has no file to write there, and `#` alone still exercises the
    same escaping on that platform.
    """
    line, sound = counter.report(
        counter.counts(session(tmp_path / name, [("KILLED", "NORMAL")] * 2)), 2
    )
    assert sound
    assert "killed 2" in line
    # nothing was created beside it, which is the half `mode=ro` promises
    assert sorted(path.name for path in tmp_path.iterdir()) == [name]


def test_a_session_nothing_has_run_says_so(counter: ModuleType, tmp_path: Path) -> None:
    """No executed mutant is no rate, and dividing by it would be worse."""
    line, sound = counter.report(
        counter.counts(session(tmp_path / "s.sqlite", [], pending=12)), 12
    )
    assert sound
    assert "never run 12" in line
    assert "no mutant ran" in line


def test_the_script_reads_a_session_and_exits_on_an_unsound_one(
    tmp_path: Path,
) -> None:
    """End to end, as the workflow runs it: a path in, a line out, a status.

    The exit status is the half the workflow acts on, and the only case it is
    allowed to be red for -- a survival rate is a test nobody has written yet,
    where this is Cosmic Ray not having measured.
    """
    sound = session(tmp_path / "sound.sqlite", [("KILLED", "NORMAL")] * 3)
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(_SCRIPT), str(sound)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "killed 3, survived 0, skipped 0" in done.stdout

    broken = session(tmp_path / "broken.sqlite", [(None, "EXCEPTION")])
    failed = subprocess.run(  # noqa: S603
        [sys.executable, str(_SCRIPT), str(broken)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert failed.returncode == 1
    assert "exception 1" in failed.stdout
