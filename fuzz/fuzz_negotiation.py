# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.negotiation`'s payload parsers.

`getaddr`, `mempool`, `sendheaders`, `wtxidrelay`, `sendtxrcncl`,
`feefilter` and `feature` are reached behind `Message.parse`'s envelope
and ahead of any signature check, `wtxidrelay`, `sendtxrcncl` and
`feature` being the ones that belong between the `version` and the
`verack`.
`fuzz/fuzz_handshake.py`'s own docstring is where the absence of a
dispatch table is argued; the same reasoning puts each of the module's
`parse` classmethods here, reached directly on `message.payload` once a
caller has read `message.command`.

Every `Payload` subclass the module defines is run against the same
bytes rather than one of them being picked.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.negotiation import (
    Feature,
    FeeFilter,
    GetAddr,
    Mempool,
    SendHeaders,
    SendTxRcncl,
    WtxidRelay,
)

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file. Its own
# cross-check derives this same list from the for loop's own tuple
# below instead of resolving a callee name, cls being a loop variable
# rather than one
ENTRY_POINTS = (
    "btclib.p2p.negotiation:GetAddr.parse",
    "btclib.p2p.negotiation:Mempool.parse",
    "btclib.p2p.negotiation:SendHeaders.parse",
    "btclib.p2p.negotiation:WtxidRelay.parse",
    "btclib.p2p.negotiation:SendTxRcncl.parse",
    "btclib.p2p.negotiation:FeeFilter.parse",
    "btclib.p2p.negotiation:Feature.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` under each of the module's commands in turn.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    for cls in (
        GetAddr,
        Mempool,
        SendHeaders,
        WtxidRelay,
        SendTxRcncl,
        FeeFilter,
        Feature,
    ):
        with contextlib.suppress(BTClibException):
            cls.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
