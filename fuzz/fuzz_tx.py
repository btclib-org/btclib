# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.tx.tx.Tx.parse`.

A transaction is parsed wherever one is handled -- out of a block, out of
a psbt's own non-witness utxo, out of a file, out of an rpc answer -- and
none of those has checked a signature first. That is
btclib-org/.github#342's own second rank rather than its first: reached
once a transaction is already in hand rather than straight off a peer
connection, and still a stranger's own choice of octets.

`fuzz/fuzz_p2p_data.py` fuzzes `TxPayload.parse`, which wraps this with
no octet of its own in front, and the two targets differ in what reaches
them: that one is what a `tx` message carries, this one what every caller
holding a transaction with no connection behind it passes.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding or validating in between. `parse`'s own contract is
to answer malformed input with `BTClibException`, so that family is
caught below as the expected outcome. An `IndexError`, a `RecursionError`
or an uncaught assertion is not, and propagates to atheris as the finding
it is.

The seed corpus is the vendored segwit transaction `tests/tx/_data` holds,
written in both of the encodings BIP144's marker distinguishes: witness
and stripped, one object and two serializations.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.tx.tx import Tx

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.tx.tx:Tx.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a transaction.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        Tx.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
