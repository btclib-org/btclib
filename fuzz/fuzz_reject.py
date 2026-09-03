# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.reject`'s payload parser.

`reject` is reached behind `Message.parse`'s envelope, ahead of any
signature check, and unlike every other payload this package holds it is
one a peer sends and this library never does: `fuzz/fuzz_handshake.py`'s
own docstring is where the absence of a dispatch table is argued, and the
same reasoning puts `Reject.parse` here, reached directly on
`message.payload` once a caller has read `message.command`.

One `Payload` subclass and therefore one entry point, `Reject.parse`.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.reject import Reject

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, never by
# importing the module -- atheris below is CI-only and undeclared in
# pyproject.toml, so the test must not execute this file
ENTRY_POINTS = ("btclib.p2p.reject:Reject.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a `reject` payload.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        Reject.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
