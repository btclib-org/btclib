# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.keepalive` module.

**No capture stands behind these, and there is none to be had**: the
Bitcoin Wiki's Protocol documentation publishes octets for `version`,
`verack` and `addr` and none for `ping` or `pong`, and Bitcoin Core
publishes no vector file for any of them. So what is here is btclib's own
round trips against BIP31 and Core's `msg_ping`/`msg_pong` read -- eight
octets of nonce, little-endian -- and nothing is claimed beyond that.

What makes the absence bearable is that there is nothing in this format a
capture would decide. The traps of `tests/p2p/address_test.py` are a
field whose byte order differs from the rest of the protocol and a
sixteen-octet address with a narrower one inside it; a nonce has neither.
It is the eight octets `Version.nonce` is, and that one *is* driven by a
captured message.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO

import pytest

from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import Message, Ping, Pong

_MAINNET = bytes.fromhex("f9beb4d9")


@pytest.mark.parametrize("cls", [Ping, Pong])
@pytest.mark.parametrize(
    "nonce",
    [0, 1, 0x0123456789ABCDEF, 2**64 - 1],
)
def test_the_nonce_round_trips(cls: type[Ping | Pong], nonce: int) -> None:
    """Eight octets, little-endian, and back.

    Zero among them, which is the value an implementation reading its own
    field for truth invents a replacement for -- and Core does send it,
    `ProcessMessage` declaring `uint64_t nonce = 0` and echoing whatever
    it read.
    """
    message = cls(nonce)
    assert len(message.serialize()) == 8
    assert cls.parse(message.serialize()) == message
    assert cls.parse(message.serialize()).nonce == nonce

    assert message.serialize() == nonce.to_bytes(8, "little")


def test_a_ping_and_a_pong_are_two_classes() -> None:
    """One body, two message types, and the command is which.

    A `command` field on one class would let a caller build a `Ping` that
    serializes under "pong"; two classes make that unsayable, and the
    generated `__eq__` compares the class, so one nonce is two objects.
    """
    assert Ping.command == "ping"
    assert Pong.command == "pong"

    # through `object`, because mypy refuses the direct comparison as
    # non-overlapping -- which is the property being asserted, said
    # statically; what runs here is the runtime half of it
    ping: object = Ping(1)
    assert ping != Pong(1)
    assert Ping(1).serialize() == Pong(1).serialize()
    assert len({Ping(1), Pong(1)}) == 2

    assert Ping(1).to_message(_MAINNET).command == "ping"
    assert Pong(1).to_message(_MAINNET).command == "pong"


def test_a_ping_is_answered_by_the_pong_of_its_nonce() -> None:
    """What the two are for, written as a caller writes it.

    The matching is the caller's: this package parses and serializes, and
    whether an answer belongs to a question is a connection's business.
    BIP31 is why the nonce is there at all -- a peer pinging every second
    and answered after five cannot otherwise tell which answer is which.
    """
    ping = Ping.parse(
        Message.parse(Ping(0xDEADBEEF).to_message(_MAINNET).serialize()).payload
    )
    pong = Pong(ping.nonce)

    assert pong.nonce == ping.nonce
    assert Pong.parse(pong.to_message(_MAINNET).payload) == pong


def test_the_pre_bip31_ping_is_the_envelopes_and_not_this_modules() -> None:
    """A `ping` with no payload is a message, and it is not a `Ping`.

    Core still accepts one -- `if (pfrom.GetCommonVersion() >
    BIP0031_VERSION)` guards the read -- and nothing has sent one since
    2012, so `nonce` is an `int` here rather than an `int | None` every
    caller of `pong.nonce` would carry forever. What answers such a peer
    is the envelope, which round-trips it without this module.
    """
    message = Message(_MAINNET, "ping")
    assert Message.parse(message.serialize()) == message
    assert message.payload == b""

    with pytest.raises(BTClibValueError, match="not enough data for the nonce"):
        Ping.parse(message.payload)


def test_what_no_eight_octets_hold_is_refused() -> None:
    """`assert_valid` at the object boundary, and the type rule with it."""
    with pytest.raises(BTClibValueError, match="invalid nonce"):
        Ping(-1)
    with pytest.raises(BTClibValueError, match="invalid nonce"):
        Pong(2**64)

    with pytest.raises(BTClibTypeError, match="invalid nonce type"):
        Ping(1.5)  # type: ignore[arg-type]
    # a bool is an int and would read as the nonce one or zero, which the
    # range check cannot tell from a nonce whose value that is
    with pytest.raises(BTClibTypeError, match="invalid nonce type"):
        Pong(True)
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Ping.parse(None)  # type: ignore[arg-type]

    # and what is refused at the object boundary is refused on the way
    # out too, an unchecked object being one a caller may hold
    unchecked = Ping(-1, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid nonce"):
        unchecked.serialize()


def test_the_octets_end_where_the_nonce_does() -> None:
    """A short read is a truncation and what follows is refused."""
    for size in range(8):
        with pytest.raises(BTClibValueError, match="not enough data for the nonce"):
            Ping.parse(bytes(size))

    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the ping payload"):
            Ping.parse(bytes(8) + trailing)
        with pytest.raises(BTClibValueError, match="bytes after the pong payload"):
            Pong.parse(bytes(8) + trailing)


def test_a_stream_is_the_callers() -> None:
    """The nonce is eight octets wide, so a stream reads one and stops."""
    stream = BytesIO(Ping(1).serialize() + b"junk")
    assert Ping.parse(stream) == Ping(1)
    assert stream.read() == b"junk"


def test_frozen() -> None:
    """Refuse assignment to the nonce: a message is a value."""
    ping = Ping(1)

    with pytest.raises(FrozenInstanceError):
        ping.nonce = 2  # type: ignore[misc]

    assert replace(ping, nonce=2) == Ping(2)
    assert isinstance(replace(ping, nonce=2), Ping)
    assert hash(ping) == hash(Ping(1))


def test_the_default_nonce_is_the_fields_own() -> None:
    """No random number is drawn here: choosing one is the caller's.

    Which is the other half of the zero case above -- an implementation
    that treats its own field as a request for a fresh nonce answers a
    `ping` of zero with a `pong` of something else.
    """
    assert Ping().nonce == 0
    assert Pong().nonce == 0
    assert Ping() == Ping(0)
