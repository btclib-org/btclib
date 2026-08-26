# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.ecc.ecies.Envelope`'s two decoders.

A BIE1 envelope is written by whoever sends it and read by whoever
receives it, and the MAC that says which of the two it is comes last:
`parse` cuts the octets at BIE1's fixed offsets, checks the magic, and
puts the ephemeral public key on the curve before `assert_valid_mac` has
been given a key at all. So the whole of the framing is read on a
stranger's own octets, which is what this harness is for.

`parse` is the octets and `b64decode` is the armor in front of them, an
envelope being copied and pasted as often as it is read from a socket, so
this harness runs both against the same input: `b64decode` refuses what
is not canonical base64 before `parse` ever sees it, so neither is
reachable from the other.

A crash here on hostile bytes is a defect in the decoder, never in this
harness: `data` is unconstrained bytes handed straight to each entry
point, `b64decode` taking bytes as the ascii it decodes them from.
`BTClibException` is what both answer a wrong magic, a field of the wrong
size, a point off the curve and a ciphertext that is not whole blocks
with, so that family is caught below as the expected outcome. An
`IndexError`, a `RecursionError` or an uncaught assertion is not, and
propagates to atheris as the finding it is.

No cipher is involved and none is needed: the ciphertext is opaque octets
to this class, which is what lets an envelope be framed, parsed and
MAC-checked by code that has no AES -- `src/btclib/ecc/ecies.py`'s own
docstring is where that is argued. The seed corpus is one envelope built
that way, in both forms: the octets `serialize` writes, and the base64
`b64encode` armors them in.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.ecc.ecies import Envelope
from btclib.exceptions import BTClibException


def fuzz_target(data: bytes) -> None:
    """Parse `data` as envelope octets, then as the base64 armor of some.

    `BTClibException` is swallowed as each entry point's own refusal of
    malformed input; any other exception propagates, which is how atheris
    tells a defect in the decoder from the domain of input it already
    rejects.
    """
    with contextlib.suppress(BTClibException):
        Envelope.parse(data)
    with contextlib.suppress(BTClibException):
        Envelope.b64decode(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
