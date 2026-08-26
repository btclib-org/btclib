# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.addrv2`'s payload parsers.

`addrv2` and `sendaddrv2` are reached behind `Message.parse`'s envelope
and ahead of any signature check, `sendaddrv2` being part of the
handshake itself (BIP155). `fuzz/fuzz_handshake.py`'s own docstring is
where the absence of a dispatch table is argued; the same reasoning puts
`AddrV2.parse` and `SendAddrV2.parse` here, reached directly on
`message.payload` once a caller has read `message.command`.

The module has two `Payload` subclasses -- `AddrV2` and `SendAddrV2` --
so this harness runs both `parse` methods against the same bytes.
`NetworkAddressV2.parse` is not fuzzed on its own: it is not a `Payload`,
only a component `AddrV2.parse` already calls on every entry of the
octets this harness feeds it.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.addrv2 import AddrV2, SendAddrV2


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an `addrv2` payload, then as a `sendaddrv2` payload.

    `BTClibException` is swallowed as each `parse`'s own refusal of
    malformed input; any other exception propagates, which is how
    atheris tells a defect in `parse` from the domain of input it
    already rejects.
    """
    with contextlib.suppress(BTClibException):
        AddrV2.parse(data)
    with contextlib.suppress(BTClibException):
        SendAddrV2.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
