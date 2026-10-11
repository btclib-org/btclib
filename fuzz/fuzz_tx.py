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

The seeds are the segwit transaction `tests/tx/_data/<txid>.bin`, written
in both of the encodings BIP144's marker distinguishes (witness and
stripped, one object and two serializations), and rust-bitcoin's
huge-witness transaction, `tests/tx/_data/huge_witness.bin`.

Each of BIP144's two serializations has one encoding.
`serialize(include_witness=True)` writes the marker only where some input
has a witness, and `parse` refuses a marker over empty witnesses and a flag
above 1. So what `parse` accepts must serialize back to `data` itself. An
input that does not was misread by `parse`, and the `AssertionError` reaches
atheris as the finding it is.
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.tx.tx import Tx

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.tx.tx:Tx.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a transaction.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    try:
        tx = Tx.parse(data)
    except BTClibException:
        return
    assert tx.serialize(include_witness=True) == data


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
