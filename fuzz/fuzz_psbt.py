# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.psbt.psbt.Psbt`'s two decoders.

A psbt travels between wallets that do not trust each other -- that is
what it is for -- and every one of them parses what the last one wrote
before any signature in it has been looked at. Its own maps are
length-prefixed keys and values whose types decide how the value is read,
which is a deserializer taking a stranger's own numbers, and BIP174's
file form wraps the whole of it in base64 that anybody can paste.

`parse` is the octets and `b64decode` is the armor in front of them, so
this harness runs both against the same input: neither is reachable from
the other, `b64decode` refusing what is not canonical base64 before
`parse` ever sees it.

A crash here on hostile bytes is a defect in the parser, never in this
harness: `data` is unconstrained bytes handed straight to each entry
point, `b64decode` taking bytes as the ascii it decodes them from.
`BTClibException` is what both answer malformed input with, so that
family is caught below as the expected outcome. An `IndexError`, a
`RecursionError` or an uncaught assertion is not, and propagates to
atheris as the finding it is.

The seed corpus is one of the BIP174 vectors
`tests/psbt/_data/bip174_test_vectors.json` carries, in both forms: the
octets `serialize` writes, and the base64 the vector itself is published
as.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.psbt.psbt import Psbt


def fuzz_target(data: bytes) -> None:
    """Parse `data` as psbt octets, then as the base64 armor of some.

    `BTClibException` is swallowed as each entry point's own refusal of
    malformed input; any other exception propagates, which is how atheris
    tells a defect in the parser from the domain of input it already
    rejects.
    """
    with contextlib.suppress(BTClibException):
        Psbt.parse(data)
    with contextlib.suppress(BTClibException):
        Psbt.b64decode(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
