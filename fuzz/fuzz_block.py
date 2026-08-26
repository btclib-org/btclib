# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.block.block.Block.parse`.

A block is a header, a transaction count, and that many transactions
read out of one stream: where each transaction ends is where the next one
is read from, so a length inside any of them decides how every octet
after it is taken. `fuzz/fuzz_tx.py` fuzzes one transaction on its own;
this is the container that drives `Tx.parse` again and again at offsets
the octets choose, and `assert_no_trailing` is what asks whether the last
one ended where the block did. That places it in btclib-org/.github#342's
second rank -- reached once a block is being handled rather than straight
off a peer connection -- with the same untrusted octets in front of it.

The count is bounded before any of it, at
`MAX_BLOCK_WEIGHT // MIN_SERIALIZABLE_TRANSACTION_WEIGHT` rather than at
`var_int`'s own `MAX_SIZE`, which is `src/btclib/block/block.py`'s own
reasoning and issue #569's. What no bound decides is what the octets
behind the count are, which is what this harness varies.

`fuzz/fuzz_p2p_data.py` fuzzes `BlockPayload.parse`, which wraps this with
no octet of its own in front; this target is what a caller reading a
block from a file or an rpc answer reaches instead.

A crash here on hostile bytes is a defect in `parse` itself, never in
this harness: `data` is unconstrained bytes handed straight to `parse`,
with nothing decoding or validating in between. Proof of work and merkle
root are `assert_valid`'s, which `parse` runs after the octets are read
and which answers a wrong one with `BTClibException` like every other
refusal, so the whole of the parse is exercised whatever the header
declares. An `IndexError`, a `RecursionError` or an uncaught assertion is
not caught below, and propagates to atheris as the finding it is.

The seed corpus is the two smallest vendored blocks `tests/block/_data`
holds, whose own hashes `tests/_data/README.md` records: the block after
genesis, whose only transaction is its coinbase, and block 170, which
carries one that is not.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.block.block import Block
from btclib.exceptions import BTClibException

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.block.block:Block.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a block.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        Block.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
