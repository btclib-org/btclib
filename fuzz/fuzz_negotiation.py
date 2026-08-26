# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.negotiation`'s payload parsers.

`getaddr`, `mempool`, `sendheaders`, `wtxidrelay` and `feefilter` are
reached behind `Message.parse`'s envelope and ahead of any signature
check, `sendheaders` and `wtxidrelay` being part of the handshake itself.
`fuzz/fuzz_handshake.py`'s own docstring is where the absence of a
dispatch table is argued; the same reasoning puts each of the module's
`parse` classmethods here, reached directly on `message.payload` once a
caller has read `message.command`.

The module has five `Payload` subclasses, so this harness runs all five
`parse` methods against the same bytes rather than picking one.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.negotiation import FeeFilter, GetAddr, Mempool, SendHeaders, WtxidRelay

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
    "btclib.p2p.negotiation:FeeFilter.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` under each of the module's five commands in turn.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    for cls in (GetAddr, Mempool, SendHeaders, WtxidRelay, FeeFilter):
        with contextlib.suppress(BTClibException):
            cls.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
