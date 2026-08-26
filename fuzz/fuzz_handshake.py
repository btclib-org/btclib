# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.handshake`'s payload parsers.

`version` and `verack` are reached behind `Message.parse`'s envelope and
ahead of any signature check -- `version` is the first message a peer
ever sends, before a handshake has completed at all -- which is
btclib-org/btclib#1361's own ranking, extending
`fuzz/fuzz_p2p_message.py`'s to the deserializers `Message.parse` never
calls itself: this package holds no dispatch table (`btclib.p2p.payload`
states why), so a caller reaches `Version.parse` or `Verack.parse`
directly on `message.payload` once it has read `message.command`.

The module has two `Payload` subclasses and therefore two entry points,
not one -- `Version.parse` and `Verack.parse` -- so this harness runs
both against the same bytes rather than picking one, the same
`data -> object` shape either way.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.handshake import Verack, Version

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = (
    "btclib.p2p.handshake:Version.parse",
    "btclib.p2p.handshake:Verack.parse",
)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a `version` payload, then as a `verack` payload.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    with contextlib.suppress(BTClibException):
        Version.parse(data)
    with contextlib.suppress(BTClibException):
        Verack.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
