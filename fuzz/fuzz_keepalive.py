# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.keepalive`'s payload parsers.

`ping` and `pong` are reached behind `Message.parse`'s envelope and
ahead of any signature check, on every open connection rather than only
during a handshake. `fuzz/fuzz_handshake.py`'s own docstring is where
the absence of a dispatch table is argued; the same reasoning puts
`Ping.parse` and `Pong.parse` here, reached directly on
`message.payload` once a caller has read `message.command`.

The module has two `Payload` subclasses sharing one body
(`_NoncePayload`), so this harness runs both `parse` methods against the
same bytes.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.keepalive import Ping, Pong


def fuzz_target(data: bytes) -> None:
    """Parse `data` as a `ping` payload, then as a `pong` payload.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    with contextlib.suppress(BTClibException):
        Ping.parse(data)
    with contextlib.suppress(BTClibException):
        Pong.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
