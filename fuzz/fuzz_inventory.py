# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.inventory`'s payload parsers.

`inv`, `getdata`, `notfound`, `getblocks`, `getheaders` and `headers` are
reached behind `Message.parse`'s envelope and ahead of any signature
check -- `getheaders`/`headers` most of all, an initial block download
running on nothing else. `fuzz/fuzz_handshake.py`'s own docstring is
where the absence of a dispatch table is argued; the same reasoning puts
each of the module's `parse` classmethods here, reached directly on
`message.payload` once a caller has read `message.command`.

This module has six concrete `Payload` subclasses -- `Inv`, `GetData`
and `NotFound` sharing one body, `GetBlocks` and `GetHeaders` sharing
another, and `Headers` on its own -- so this harness runs all six
`parse` methods against the same bytes rather than picking one.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.inventory import GetBlocks, GetData, GetHeaders, Headers, Inv, NotFound

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file. Its own
# cross-check derives this same list from the for loop's own tuple
# below instead of resolving a callee name, cls being a loop variable
# rather than one
ENTRY_POINTS = (
    "btclib.p2p.inventory:Inv.parse",
    "btclib.p2p.inventory:GetData.parse",
    "btclib.p2p.inventory:NotFound.parse",
    "btclib.p2p.inventory:GetBlocks.parse",
    "btclib.p2p.inventory:GetHeaders.parse",
    "btclib.p2p.inventory:Headers.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` under each of the module's six commands in turn.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    for cls in (Inv, GetData, NotFound, GetBlocks, GetHeaders, Headers):
        with contextlib.suppress(BTClibException):
            cls.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
