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

The format has one encoding, so what `parse` accepts must `serialize` back
to `data` itself. An input that does not was misread by `parse` or
miswritten by `serialize`, and the `AssertionError` reaches atheris as the
finding it is.
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.reject import Reject

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.p2p.reject:Reject.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a `reject` payload.

    A `BTClibException` from `parse` is its refusal of malformed input and
    is swallowed. Any other exception, and any exception from `serialize`,
    propagates: that is how atheris tells a defect from the input `parse`
    already rejects.
    """
    try:
        reject = Reject.parse(data)
    except BTClibException:
        return
    assert reject.serialize() == data


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
