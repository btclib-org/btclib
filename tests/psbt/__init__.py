# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Non-regression tests for btclib.psbt.

The vector loaders live here rather than in one of the test modules
because two of them read the same files: `psbt_test.py` holds the object
model to the published psbts, and `psbt_view_test.py` holds the streaming
reader to the object model over the very same list. `tests/__init__.py`
says why shared test code is a package `__init__` at every level.
"""

from typing import Any

import pytest

from tests import load, vector_id


def psbt_cases(fname: str, kind: str) -> list[dict[str, Any]]:
    """Return the `kind` cases of a psbt vector file, as they are written.

    What each case holds depends on the kind: an encoded psbt always, an
    error message where the case is one to refuse, the lock time BIP370
    publishes for it where the case is about that.
    """
    cases: list[dict[str, Any]] = load("psbt", "_data", fname)[kind]
    return cases


def psbt_vectors(fname: str, kind: str) -> list[Any]:
    """Return those cases as parametrize arguments, named by description.

    The description is the id because a bare "case 7 failed" is not a
    report: as a test id it is there for free, with no print-and-raise
    wrapper around the decode and no interpolation into the message of
    every assert -- and for the cases that pass as well.
    """
    return [
        pytest.param(test_vector, id=vector_id(index, test_vector["description"]))
        for index, test_vector in enumerate(psbt_cases(fname, kind), 1)
    ]
