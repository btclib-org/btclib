# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`ping` and `pong`: a nonce out, and the same nonce back.

BIP31's two messages, and Bitcoin Core's `msg_ping` and `msg_pong`: eight
octets of nonce each, little-endian, and `net_processing.cpp` answers a
`ping` by writing the nonce it read straight back. The nonce is what
tells one round trip from the next -- BIP31's own reason, quoted in
Core's comment: without it a peer that pings every second and is answered
after five cannot tell which answer belongs to which question.

**The pre-BIP31 `ping` is not modelled, and that is a decision rather
than an omission.** Before protocol version 60001 a `ping` had no payload
at all, and Core still accepts one -- `if (pfrom.GetCommonVersion() >
BIP0031_VERSION)` is what guards the read. Nothing has sent one since
2012, and a `nonce` of `int | None` would put that on every caller of
`pong.nonce` forever. What answers such a peer is the envelope, which
round-trips a `ping` with an empty payload as `Message(magic, "ping")`
without this module being involved -- an unrecognized command and an
unmodelled shape of a recognized one are the same thing there, on
purpose.

`pong` has no such history: it is BIP31's, so it has carried a nonce from
the message's first version. Core reads it defensively all the same --
`ProcessPong` checks `nAvail >= sizeof(nonce)` and treats a short one as
a peer misbehaving rather than as a message -- which is a policy about
what to do with octets that do not decode, and this package holds none.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from btclib.alias import BinaryData
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "Ping",
    "Pong",
]

_NONCE_SIZE = 8
_MAX_NONCE = (1 << (8 * _NONCE_SIZE)) - 1

# so that `Ping.parse` answers a `Ping` and not the private base: the
# body is one and the two return types are not
_Nonce = TypeVar("_Nonce", bound="_NoncePayload")


@dataclass(frozen=True)
class _NoncePayload(Payload):
    """The eight octets `ping` and `pong` are, with the command left open.

    Private, and a base rather than one class with the command as a
    field: `Ping` and `Pong` are two message types that happen to have
    one body, and a field would let a caller build a `Ping` that
    serializes under "pong". The command is what tells them apart, so it
    is what the subclass sets and nothing else is.

    The generated `__eq__` compares `other.__class__ is self.__class__`,
    so a `Ping` and a `Pong` of one nonce are two objects however alike
    their octets -- which is the property that makes them two classes.
    """

    nonce: int

    def __init__(self, nonce: int = 0, *, check_validity: bool = True) -> None:
        object.__setattr__(self, "nonce", nonce)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a nonce no eight octets hold."""
        # a bool is an int and would read as the nonce one or zero, which
        # the range check cannot tell from a nonce whose value that is
        if not is_integer(self.nonce):
            err_msg = f"invalid nonce type: {type(self.nonce).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.nonce <= _MAX_NONCE:
            raise BTClibValueError(f"invalid nonce: {self.nonce}")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the eight octets of the nonce, little-endian."""
        if check_validity:
            self.assert_valid()

        return self.nonce.to_bytes(_NONCE_SIZE, byteorder="little", signed=False)

    @classmethod
    def parse(
        cls: type[_Nonce], data: BinaryData, *, check_validity: bool = True
    ) -> _Nonce:
        """Return the nonce the eight octets carry."""
        stream = bytesio_from_binarydata(data)

        nonce = int.from_bytes(
            read_exactly(stream, _NONCE_SIZE, "nonce"),
            byteorder="little",
            signed=False,
        )
        assert_no_trailing(data, stream, f"{cls.command} payload")

        return cls(nonce, check_validity=check_validity)


class Ping(_NoncePayload):
    """The `ping` message: a nonce a `pong` is expected to echo back.

    A nonce of zero is a nonce, which is worth saying because it is the
    one an implementation reading its own field for truth invents a
    replacement for -- and Core does send zero, `ProcessMessage`
    declaring `uint64_t nonce = 0` and writing back whatever it read.
    There is no default nonce here beyond the field's own: choosing one
    is drawing a random number, which is the caller's and `secrets`'.
    """

    command = "ping"


class Pong(_NoncePayload):
    """The `pong` message: the nonce of the `ping` it answers.

    Whether it is the nonce that was sent is the caller's question and
    not this codec's: matching an answer to a question is what a
    connection does, and this package holds no connection.
    """

    command = "pong"
