# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.compact_blocks`'s payload parsers.

`sendcmpct`, `cmpctblock`, `getblocktxn` and `blocktxn` are reached
behind `Message.parse`'s envelope and ahead of any signature check --
BIP152's whole point being to relay a block before it is fully validated.
`fuzz/fuzz_handshake.py`'s own docstring is where the absence of a
dispatch table is argued; the same reasoning puts each of the module's
`parse` classmethods here, reached directly on `message.payload` once a
caller has read `message.command`.

The module has four `Payload` subclasses -- `SendCmpct`, `CmpctBlock`,
`GetBlockTxn` and `BlockTxn` -- so this harness runs all four `parse`
methods against the same bytes. `PrefilledTransaction.parse` and
`Tx.parse` are not fuzzed on their own here: they are not `Payload`
either, only what `CmpctBlock.parse` and `BlockTxn.parse` already call
on the octets this harness feeds them, `Tx.parse` besides being out of
this issue's scope (btclib-org/btclib#1361's own second list).
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.compact_blocks import BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file. Its own
# cross-check derives this same list from the for loop's own tuple
# below instead of resolving a callee name, cls being a loop variable
# rather than one
ENTRY_POINTS = (
    "btclib.p2p.compact_blocks:SendCmpct.parse",
    "btclib.p2p.compact_blocks:CmpctBlock.parse",
    "btclib.p2p.compact_blocks:GetBlockTxn.parse",
    "btclib.p2p.compact_blocks:BlockTxn.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` under each of the module's four commands in turn.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    for cls in (SendCmpct, CmpctBlock, GetBlockTxn, BlockTxn):
        with contextlib.suppress(BTClibException):
            cls.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
