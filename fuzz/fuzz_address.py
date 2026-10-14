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

The format has one encoding, so what `parse` accepts must `serialize` back
to `data` itself. An input that does not was misread by `parse` or
miswritten by `serialize`, and the `AssertionError` reaches atheris as the
finding it is.
"""

from __future__ import annotations

import sys

import atheris

from btclib.exceptions import BTClibException
from btclib.p2p.address import Addr

# tests/fuzz_corpus_test.py reads this with ast.literal_eval.
# tests/fuzz_harness_test.py imports this file with an empty atheris,
# so atheris may be called only from main()
ENTRY_POINTS = ("btclib.p2p.address:Addr.parse",)


def fuzz_target(data: bytes) -> None:
    """Parse `data` as an `addr` payload.

    A `BTClibException` from `parse` is its refusal of malformed input and
    is swallowed. Any other exception, and any exception from `serialize`,
    propagates: that is how atheris tells a defect from the input `parse`
    already rejects.
    """
    try:
        addr = Addr.parse(data)
    except BTClibException:
        return
    assert addr.serialize() == data


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
