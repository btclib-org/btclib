#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
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
from pathlib import Path

# how Cosmic Ray spells the two verdicts and the non-verdict, as they are
# stored: a skipped mutant is one the operator filter excluded before
# anything ran it, and it has a worker outcome and no test outcome
_KILLED = "KILLED"
_SURVIVED = "SURVIVED"
_SKIPPED = "SKIPPED"


def counts(session: Path) -> dict[str, int]:
    """Return how many results the session holds, by what happened to them."""
    query = """
        SELECT COALESCE(test_outcome, worker_outcome), COUNT(*)
        FROM work_results GROUP BY 1
    """
    with sqlite3.connect(f"file:{session}?mode=ro", uri=True) as db:
        return {str(outcome): int(count) for outcome, count in db.execute(query)}


def report(by_outcome: dict[str, int], enumerated: int) -> str:
    """Return the one line worth reading in a workflow log."""
    killed = by_outcome.get(_KILLED, 0)
    survived = by_outcome.get(_SURVIVED, 0)
    skipped = by_outcome.get(_SKIPPED, 0)
    executed = killed + survived
    pending = enumerated - sum(by_outcome.values())
    rate = f"{survived / executed * 100:.2f}%" if executed else "no mutant ran"
    line = f"killed {killed}, survived {survived}, skipped {skipped}"
    if pending:
        line += f", never run {pending}"
    return f"{line}; survival rate over the {executed} executed: {rate}"


def enumerated_mutants(session: Path) -> int:
    """Return how many mutants the session enumerated, run or not."""
    with sqlite3.connect(f"file:{session}?mode=ro", uri=True) as db:
        return int(db.execute("SELECT COUNT(*) FROM work_items").fetchone()[0])


def main() -> None:
    """Print the counts of the session named on the command line."""
    session = Path(sys.argv[1])
    print(report(counts(session), enumerated_mutants(session)))


if __name__ == "__main__":
    main()
