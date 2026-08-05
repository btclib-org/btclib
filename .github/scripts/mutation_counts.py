# Copyright (C) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Count a Cosmic Ray session by outcome, the skipped mutants left out.

`cr-rate` answers the wrong question for a filtered session, and not by a
little: `WorkResult.is_killed` is `test_outcome != SURVIVED`, so every mutant
the operator filter marked SKIPPED is counted as a kill, and the rate divides
by all of them. On the measured RPC session that reads 0.97% where the
executed mutants are 1.32% -- 7 survivors of 532 run, not of 719 enumerated
-- and a session the budget cut short is diluted further, every mutant that
never ran counting as killed too. `cr-report`'s summary line uses the same
two functions and is wrong the same way.

So the numbers are counted here, and printed rather than reduced to one:
killed, survived, skipped, and the rate over what actually ran. A rate alone
cannot say whether a session was complete, and completeness is the first
thing to know about one that had a timeout.

**Every outcome is printed, and one that is not a verdict makes this exit
non-zero.** A mutant can come back INCOMPETENT, or with a worker outcome of
EXCEPTION, ABNORMAL or NO-TEST: the mutated tree would not run, or the runner
would not run it, and `cosmic-ray exec` can finish with a zero exit having
recorded them. None of those says anything about the suite, so counting them
silently anywhere -- as killed, as executed, or by leaving them out of the
line -- publishes a session that measured less than it appears to. This is
the one thing the mutation workflow may be red about: a survivor is a test
nobody has written yet, where these are the measurement itself not working.

Read from the session file with `sqlite3`, which is a coupling worth stating.
`cosmic-ray dump` is the documented interchange and would have been the
honest input, but it cannot read these sessions at all: `result_to_dict` does
`d["test_outcome"].value`, a SKIPPED result has no test outcome, and the
command dies with `AttributeError: 'NoneType' object has no attribute
'value'` at the first one -- after printing the records before it, so its
output is both short and truncated mid-line. The three columns read below
are the whole of what this needs.

    python .github/scripts/mutation_counts.py session.sqlite
"""

from __future__ import annotations

import sqlite3
import sys
from collections import Counter
from contextlib import closing
from pathlib import Path

# `closing` and not `with sqlite3.connect(...)` alone: that context manager
# commits a transaction and leaves the connection open, so a read-only query
# through it is a `ResourceWarning: unclosed database` at whatever later
# moment the collector notices -- which under this suite's
# `filterwarnings = ["error"]` fails a test that has nothing to do with it

# how Cosmic Ray spells the two verdicts and the one non-verdict a session is
# meant to hold: a skipped mutant is one the operator filter excluded before
# anything ran it, so it is deliberate rather than a failure. Everything else
# that is neither verdict is a failure -- see the module docstring.
#
# Compared after `_normalized`, because the enum members and what the session
# stores agree on neither case nor the separator in `no-test`
_KILLED = "killed"
_SURVIVED = "survived"
_SKIPPED = "skipped"
_NORMAL = "normal"


def _normalized(outcome: object) -> str:
    """Return an outcome as one word, whichever spelling it was stored in."""
    return str(outcome).strip().lower().replace("_", "-")


def _outcome(test_outcome: object, worker_outcome: object) -> str:
    """Return the one word for a result, the worker's failure winning.

    Not `COALESCE(test_outcome, worker_outcome)`, which reads as if the two
    columns were alternatives and is wrong on the row that matters most: when
    `mutate_and_test` raises, Cosmic Ray stores `worker_outcome=EXCEPTION`
    *and* `test_outcome=INCOMPETENT` in the same row, so coalescing always
    answers INCOMPETENT and the exception is never named. INCOMPETENT there is
    the consequence -- no suite judged the mutant -- and the exception is what
    happened, so a worker outcome that is not NORMAL is the answer.
    """
    worker = _normalized(worker_outcome)
    return _normalized(test_outcome) if worker == _NORMAL else worker


def _read_only(session: Path) -> str:
    """Return the sqlite URI of that file, opened for reading and nothing else.

    Built with `as_uri`, because a path is not a URI: `?` and `#` are ordinary
    characters in a POSIX filename and delimiters here, so `session?copy
    .sqlite` interpolated into `file:{path}?mode=ro` names the database
    `session` with the rest read as query parameters -- which opens the wrong
    file, reports `no such table`, and creates a `session` on the way, the
    `mode=ro` that would have forbidden it having been parsed as part of the
    name.
    """
    return f"{session.resolve().as_uri()}?mode=ro"


def counts(session: Path) -> dict[str, int]:
    """Return how many results the session holds, by what happened to them."""
    query = "SELECT test_outcome, worker_outcome FROM work_results"
    with closing(sqlite3.connect(_read_only(session), uri=True)) as db:
        return Counter(_outcome(*row) for row in db.execute(query))


def enumerated_mutants(session: Path) -> int:
    """Return how many mutants the session enumerated, run or not."""
    with closing(sqlite3.connect(_read_only(session), uri=True)) as db:
        return int(db.execute("SELECT COUNT(*) FROM work_items").fetchone()[0])


def report(by_outcome: dict[str, int], enumerated: int) -> tuple[str, bool]:
    """Return the line worth reading, and whether the session measured soundly.

    Unsound is an outcome that is neither verdict nor deliberate skip, and the
    line names each of them with its count: a number nobody can interpret is
    worse than a red step, so the step is red for it.
    """
    killed = by_outcome.get(_KILLED, 0)
    survived = by_outcome.get(_SURVIVED, 0)
    skipped = by_outcome.get(_SKIPPED, 0)
    executed = killed + survived
    pending = enumerated - sum(by_outcome.values())
    failed = {
        outcome: count
        for outcome, count in sorted(by_outcome.items())
        if outcome not in (_KILLED, _SURVIVED, _SKIPPED)
    }

    line = f"killed {killed}, survived {survived}, skipped {skipped}"
    if pending:
        line += f", never run {pending}"
    rate = f"{survived / executed * 100:.2f}%" if executed else "no mutant ran"
    line += f"; survival rate over the {executed} executed: {rate}"
    if failed:
        named = ", ".join(f"{outcome} {count}" for outcome, count in failed.items())
        line += f". No verdict on the suite: {named}"
    return line, not failed


def main() -> None:
    """Print the counts of the session named on the command line.

    A second argument is a label to print the line under, which is what the
    workflow passes instead of piping this through `sed`: a pipeline's status
    is its last command's, and GitHub runs a `run` step as `bash -e` without
    `pipefail`, so the exit code below would have been thrown away by the very
    step that reads it.
    """
    session = Path(sys.argv[1])
    label = f"{sys.argv[2]}: " if len(sys.argv) > 2 else ""
    line, sound = report(counts(session), enumerated_mutants(session))
    print(f"{label}{line}")
    if not sound:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
