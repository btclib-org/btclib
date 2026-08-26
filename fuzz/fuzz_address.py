# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing `btclib.p2p.address`'s payload parser.

`addr` is reached behind `Message.parse`'s envelope and ahead of any
signature check, gossip being one of the first things a connection does.
`fuzz/fuzz_handshake.py`'s own docstring is where the absence of a
dispatch table is argued; the same reasoning puts `Addr.parse` here,
reached directly on `message.payload` once a caller has read
`message.command`.

The module has one `Payload` subclass, `Addr`, whose own `parse` bounds
the address count against `MAX_ADDR_TO_SEND` before building anything --
`src/btclib/p2p/address.py`'s own docstring is where that check is
argued. `NetworkAddress` and `TimestampedNetworkAddress` are not fuzzed
on their own: neither is a `Payload`, both being components `Addr.parse`
already calls on every entry of the octets this harness feeds it.
"""

from __future__ import annotations

import contextlib
import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.address import Addr


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an `addr` payload.

    `BTClibException` is swallowed as `parse`'s own refusal of malformed
    input; any other exception propagates, which is how atheris tells a
    defect in `parse` from the domain of input it already rejects.
    """
    with contextlib.suppress(BTClibException):
        Addr.parse(data)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
