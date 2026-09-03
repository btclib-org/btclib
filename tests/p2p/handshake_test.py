# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.handshake` module.

**The authority is the envelope's, and no stronger**: Bitcoin Core
publishes no vector file for `version`, so what is here is btclib's own
round trips plus the `version` and `verack` the Bitcoin Wiki's Protocol
documentation publishes with their octets, cited by revision:
https://en.bitcoin.it/w/index.php?title=Protocol_documentation&oldid=68832

`tests/p2p/message_test.py` reads the same two as an envelope and says in
full why a wiki revision is weaker than a vendored file; this module
reads the payload of the first, field by field, and what makes it
evidence is the same thing -- the header's checksum recomputes from the
payload beside it.

**There is no captured `version` here that carries the relay flag**, and
that is worth saying rather than glossing: the one the wiki publishes is
a `/Satoshi:0.7.2/` node's, which stops after the start height. So the
flag's *presence* is driven by btclib's own round trips, and what stands
behind them is Core's source read rather than a message caught in the
wild -- `net_processing.cpp`, where `bool fRelay = true` is declared
before the message is read and assigned only inside `if
(!vRecv.empty())`. The absent case is the captured one, which is the half
that could not have been guessed: a real peer really does send a
`version` with no relay flag.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO

import pytest

from btclib import var_bytes
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.p2p import (
    Message,
    NetworkAddress,
    ServiceFlags,
    TimestampedNetworkAddress,
    Verack,
    Version,
)
from btclib.p2p.limits import MAX_SUBVERSION_LENGTH, PROTOCOL_VERSION

# The Bitcoin Wiki's Protocol documentation, "version" section: a message
# a Satoshi:0.7.2 node sent on mainnet, split at the field boundaries the
# page annotates. The same octets `tests/p2p/message_test.py` reads as an
# envelope, read here as the payload it is.
_VERSION_PAYLOAD = bytes.fromhex(
    "62ea0000"  # protocol version 60002
    "0100000000000000"  # services: NODE_NETWORK
    "11b2d05000000000"  # timestamp
    "010000000000000000000000000000000000ffff000000000000"  # addr_recv
    "010000000000000000000000000000000000ffff000000000000"  # addr_from
    "3b2eb35d8ce61765"  # nonce
    "0f2f5361746f7368693a302e372e322f"  # user agent "/Satoshi:0.7.2/"
    "c03e0300"  # start height 212672
    # and nothing here: this node predates BIP37's relay flag
)
_VERSION = (
    bytes.fromhex(
        "f9beb4d9"  # mainnet
        "76657273696f6e0000000000"  # "version", NUL padded to twelve
        "64000000"  # payload length, 100 little-endian
        "3b648d5a"  # checksum
    )
    + _VERSION_PAYLOAD
)

# the same page's "verack" section: the whole message is the header
_VERACK = bytes.fromhex("f9beb4d976657261636b000000000000000000005df6e0e2")

_MAINNET = bytes.fromhex("f9beb4d9")


def test_the_captured_version_payload_field_by_field() -> None:
    """Every field of a real `version`, and the octets written back."""
    version = Version.parse(_VERSION_PAYLOAD)

    assert version.version == 60002
    assert version.services == ServiceFlags.NODE_NETWORK
    assert version.timestamp == 0x50D0B211
    assert version.addr_recv == NetworkAddress(1, "::ffff:0.0.0.0", 0)
    assert version.addr_from == version.addr_recv
    assert version.nonce == 0x6517E68C5DB32E3B
    assert version.user_agent == b"/Satoshi:0.7.2/"
    assert version.start_height == 212672
    assert version.relay is None

    assert version.serialize() == _VERSION_PAYLOAD
    # and the whole message, which is what authenticates the payload: the
    # header's checksum is recomputed from these very octets
    assert version.to_message(_MAINNET).serialize() == _VERSION


def test_the_captured_version_carries_no_relay_flag() -> None:
    """The case that decides how the trailing field is modelled.

    A hundred octets, and the last four of them are the start height. A
    parser that requires the relay flag refuses this message; Core does
    not, and the peers that send one are real. `relay is None` is what
    says the octets ended here, which is different from saying the peer
    asked for no transactions.
    """
    assert len(_VERSION_PAYLOAD) == 100
    assert Version.parse(_VERSION_PAYLOAD).relay is None

    # requiring it would be refusing this message, and is not the shape
    # `parse` has: the flag is read where an octet is left
    assert Version.parse(_VERSION_PAYLOAD + b"\x01").relay is True
    assert Version.parse(_VERSION_PAYLOAD + b"\x00").relay is False


def test_an_absent_relay_flag_is_not_a_refusal_to_relay() -> None:
    """BIP37's default, which is `True` and not `False`.

    Bitcoin Core declares `bool fRelay = true` before it reads a
    `version` and assigns to it only where the field is present, so a
    peer that omits it is asking for transactions. `is_relay_requested`
    is that reading; `relay` is the field, and a caller reading the field
    for the answer says the opposite of the protocol for every peer that
    omitted it -- which is the bug btclib_node has, its
    `int.from_bytes(b"", "little")` answering zero.
    """
    assert Version(relay=None).is_relay_requested is True
    assert Version(relay=True).is_relay_requested is True
    assert Version(relay=False).is_relay_requested is False

    # the field says what the peer said, which is the other question and
    # the one the property does not answer
    assert Version(relay=None).relay is None


def test_the_relay_flag_makes_the_encoding_one_to_one() -> None:
    """Three payloads, three objects, each writing back its own octets.

    The property behind the decision: the encoding is not prefix-free --
    the hundred-octet payload is a prefix of the hundred-and-one-octet
    one -- but nothing is malleable, because the shorter buffer parses to
    an object that serializes to the shorter buffer. Two buffers mapping
    to one object is what `tests/parse_contract_test.py`'s generic
    property is against, and it is what does not happen here.
    """
    absent = Version.parse(_VERSION_PAYLOAD)
    off = Version.parse(_VERSION_PAYLOAD + b"\x00")
    on = Version.parse(_VERSION_PAYLOAD + b"\x01")

    assert absent != off
    assert off != on
    assert absent != on

    assert absent.serialize() == _VERSION_PAYLOAD
    assert off.serialize() == _VERSION_PAYLOAD + b"\x00"
    assert on.serialize() == _VERSION_PAYLOAD + b"\x01"


def test_a_version_with_no_explicit_field_announces_this_libraries_own() -> None:
    """`Version()`'s `version` defaults to `limits.PROTOCOL_VERSION`, not zero.

    A caller building one to send is building this library's own
    handshake, so what it announces with no argument is Core's own
    number rather than the field's former zero. `parse` is unaffected: a
    peer's own `version` is read off the octets, never off this default.
    """
    assert Version().version == PROTOCOL_VERSION
    assert Version(check_validity=False).version == PROTOCOL_VERSION

    version = Version(relay=True)
    assert version.version == PROTOCOL_VERSION
    assert Version.parse(version.serialize()).version == PROTOCOL_VERSION


def test_the_relay_flag_is_one_octet_of_two_values() -> None:
    """A departure from Core, with the reason this library always gives.

    Core's `Unserialize` for a bool reads an octet and answers `!= 0`, so
    `0x02` is true there and is written back as `0x01`: two payloads, one
    object, and only one of them serialized back. That is the
    malleability the envelope refuses a non-canonical command padding
    for, one layer down, and the same answer is given here.
    """
    for octet in (b"\x02", b"\x7f", b"\xff"):
        with pytest.raises(BTClibValueError, match="invalid relay flag"):
            Version.parse(_VERSION_PAYLOAD + octet)

    # and the two that are a flag, whatever check_validity says: this is
    # where the octets end, not what they mean
    for check_validity in (True, False):
        with pytest.raises(BTClibValueError, match="invalid relay flag"):
            Version.parse(_VERSION_PAYLOAD + b"\x02", check_validity=check_validity)


def test_no_prefix_of_a_version_is_a_version_except_the_relay_flag() -> None:
    """The generic property, driven where it holds and named where it does not.

    `tests/parse_contract_test.py` holds every other parser to "no prefix
    of an encoding is an object" and names this one an exclusion. The
    exclusion is exactly one octet wide, and this is what is true
    instead: every shorter prefix is refused, and the one that is not is
    the message a pre-BIP37 peer sends.
    """
    with_relay = _VERSION_PAYLOAD + b"\x01"

    for size in range(len(_VERSION_PAYLOAD)):
        for check_validity in (True, False):
            with pytest.raises((BTClibValueError, BTClibRuntimeError, BTClibTypeError)):
                Version.parse(with_relay[:size], check_validity=check_validity)

    # the one prefix that is an object, and it is a different object
    assert Version.parse(with_relay[: len(_VERSION_PAYLOAD)]).relay is None
    assert Version.parse(with_relay).relay is True


def test_the_octets_after_a_version_are_refused() -> None:
    """The other half of the contract, which the relay flag does not touch.

    Whatever follows the flag is refused, so the octets are one whole
    object once the last field is read -- the difference from a parser
    that ignores what is left over, which would read two payloads back as
    the one message.
    """
    with_relay = _VERSION_PAYLOAD + b"\x01"
    for trailing in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the version payload"):
            Version.parse(with_relay + trailing)

    # a hex string is the same buffer, which is the spelling that would
    # slip past a check written against `bytes` alone
    with pytest.raises(BTClibValueError, match="bytes after the version payload"):
        Version.parse((with_relay + b"junk").hex())


def test_a_version_payload_is_read_from_octets_and_not_from_a_stream() -> None:
    """The second thing an optional last field costs, and the answer to it.

    "Is the next octet the relay flag" is a question about the whole
    payload: in a stream holding the message after this one, the answer
    is the first octet of that message, and the reading is silently
    wrong rather than refused. So `Version.parse` takes `Octets` -- what
    `message.payload` already is -- and there is no stream to be wrong
    about. `BIP32KeyOrigin.parse` is the other parser in this library
    that takes `Octets` for a reason of the same shape.
    """
    stream = BytesIO(_VERSION_PAYLOAD + _VERACK)
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Version.parse(stream)  # type: ignore[arg-type]

    # what a caller does instead: the envelope says where the payload
    # ends, and the payload is what this reads
    message = Message.parse(_VERSION)
    assert Version.parse(message.payload).relay is None


def test_the_captured_verack_is_the_empty_payload() -> None:
    """`verack` carries nothing, and the class is the command it is."""
    assert Verack().serialize() == b""
    assert Verack.parse(b"") == Verack()
    assert Verack().to_message(_MAINNET).serialize() == _VERACK
    assert Verack.parse(Message.parse(_VERACK).payload) == Verack()


def test_a_verack_with_a_payload_is_refused() -> None:
    """Where this departs from Core, and the rule it departs towards.

    `ProcessMessage` never reads `vRecv` for a `verack`, so Core ignores
    whatever one carries. This library refuses what follows an object
    everywhere, and a `verack` with a payload is a message that
    serializes back without it.
    """
    for payload in (b"\x00", b"junk"):
        with pytest.raises(BTClibValueError, match="bytes after the verack payload"):
            Verack.parse(payload)


def test_a_verack_consumes_nothing_from_a_stream() -> None:
    """A caller's stream is the caller's, and this message is no octets.

    Which is what makes reading a `verack` out of the middle of one
    harmless: the position does not move, so the next message starts
    where it started.
    """
    stream = BytesIO(b"junk")
    assert Verack.parse(stream) == Verack()
    assert stream.tell() == 0
    assert stream.read() == b"junk"


def test_the_round_trip_of_a_version_a_modern_node_sends() -> None:
    """Every field set, the relay flag among them.

    btclib's own round trip and not a capture: the wiki publishes no
    `version` carrying the flag, and this module's docstring says so.
    """
    version = Version(
        70016,
        ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
        1755000000,
        NetworkAddress(0, "10.0.0.1", 8333),
        NetworkAddress(ServiceFlags.NODE_NETWORK, "2001:db8::1", 8333),
        0x0123456789ABCDEF,
        b"/btclib:2026.8.20/",
        912345,
        relay=True,
    )
    assert Version.parse(version.serialize()) == version
    assert Version.parse(version.to_message(_MAINNET).payload) == version
    assert version.to_message(_MAINNET).command == Version.command == "version"


def test_the_addresses_of_a_version_carry_no_timestamp() -> None:
    """Twenty-six octets each, where an `addr` entry is thirty.

    The same structure in Core's prose and not the same octets, which is
    why `Version.addr_recv` is a `NetworkAddress` and `Addr.addresses` is
    not: putting one where the other belongs is a call mypy refuses.
    """
    version = Version.parse(_VERSION_PAYLOAD)
    address = version.addr_recv

    # 4 + 8 + 8 = 20 octets in front of the first address, and 26 each
    assert _VERSION_PAYLOAD[20:46] == address.serialize()
    assert _VERSION_PAYLOAD[46:72] == version.addr_from.serialize()
    assert len(address.serialize()) == 26

    entry = TimestampedNetworkAddress(0, address)
    assert len(entry.serialize()) == 30
    assert not issubclass(TimestampedNetworkAddress, NetworkAddress)


def test_the_widths_and_signs_are_the_ones_core_declares() -> None:
    """`int nVersion`, `int64_t nTime`, `int starting_height`, and two uint64.

    A negative timestamp is what Core clamps to zero on receipt rather
    than refusing -- `if (nTime < 0) nTime = 0;` -- so it is a value this
    parses, and a `start_height` of -1 is Core's own initializer.
    """
    version = Version(
        -1, 0, -1, NetworkAddress(), NetworkAddress(), 0, b"", -1, relay=None
    )
    assert Version.parse(version.serialize()) == version
    assert version.serialize()[:4] == b"\xff\xff\xff\xff"

    extremes = Version(
        2**31 - 1,
        2**64 - 1,
        2**63 - 1,
        NetworkAddress(),
        NetworkAddress(),
        2**64 - 1,
        b"",
        2**31 - 1,
        relay=False,
    )
    assert Version.parse(extremes.serialize()) == extremes

    minima = replace(
        extremes, version=-(2**31), timestamp=-(2**63), start_height=-(2**31)
    )
    assert Version.parse(minima.serialize()) == minima


def test_what_no_field_of_this_width_holds_is_refused() -> None:
    """`assert_valid` over every field, at the object boundary."""
    for field, value in (
        ("version", 2**31),
        ("version", -(2**31) - 1),
        ("services", -1),
        ("services", 2**64),
        ("timestamp", 2**63),
        ("timestamp", -(2**63) - 1),
        ("nonce", -1),
        ("nonce", 2**64),
        ("start_height", 2**31),
        ("start_height", -(2**31) - 1),
    ):
        with pytest.raises(BTClibValueError, match="invalid"):
            Version(**{field: value})  # type: ignore[arg-type]


def test_a_user_agent_is_octets_and_is_bounded() -> None:
    """Core's `LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH)`.

    Octets and not text: Core reads it into a `std::string` and
    `SanitizeString`s it for the log alone, so a peer may put anything at
    all in it and decoding here would refuse a message Core accepts.
    """
    ugly = bytes(range(256))[:MAX_SUBVERSION_LENGTH]
    assert Version.parse(Version(user_agent=ugly).serialize()).user_agent == ugly

    with pytest.raises(BTClibValueError, match="invalid user agent length"):
        Version(user_agent=bytes(MAX_SUBVERSION_LENGTH + 1))

    # the length written is the length of the octets, which is where a
    # `str` field would go wrong: `len` of text is codepoints, and the
    # var_int in front would then disagree with what follows it
    version = Version(user_agent=b"/\xc3\xa9/")
    assert var_bytes.parse(version.serialize()[80:]) == b"/\xc3\xa9/"

    # and the bound is checked in `parse` too, which is where the octets
    # are a peer's rather than a caller's
    long = Version(user_agent=bytes(MAX_SUBVERSION_LENGTH + 1), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid user agent length"):
        Version.parse(long.serialize(check_validity=False))


def test_a_wrong_type_is_a_type_error() -> None:
    """A value of a type the signature does not declare, at every field."""
    with pytest.raises(BTClibTypeError, match="invalid version type"):
        Version(1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid timestamp type"):
        Version(0, 0, 1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid nonce type"):
        Version(0, 0, 0, None, None, 1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid start height type"):
        Version(0, 0, 0, None, None, 0, b"", 1.5)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid addr_recv type"):
        Version(0, 0, 0, "10.0.0.1")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid addr_from type"):
        Version(0, 0, 0, NetworkAddress(), "10.0.0.1")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Version(user_agent=1)  # type: ignore[arg-type]

    # the relay flag is a kind and not a truth: its value decides what is
    # written, one octet or none, so "no" would be written as True
    with pytest.raises(BTClibTypeError, match="invalid relay type"):
        Version(relay="no")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid relay type"):
        Version(relay=1)  # type: ignore[arg-type]


def test_a_truncated_version_names_the_field_it_stopped_in() -> None:
    """The diagnosis is the truncation, whatever field it fell in."""
    with pytest.raises(BTClibValueError, match="version protocol version"):
        Version.parse(_VERSION_PAYLOAD[:3])
    with pytest.raises(BTClibValueError, match="version services"):
        Version.parse(_VERSION_PAYLOAD[:8])
    with pytest.raises(BTClibValueError, match="version timestamp"):
        Version.parse(_VERSION_PAYLOAD[:16])
    with pytest.raises(BTClibValueError, match="address services"):
        Version.parse(_VERSION_PAYLOAD[:24])
    with pytest.raises(BTClibValueError, match="version nonce"):
        Version.parse(_VERSION_PAYLOAD[:76])
    with pytest.raises(BTClibValueError, match="version start height"):
        Version.parse(_VERSION_PAYLOAD[:98])


def test_frozen() -> None:
    """Refuse assignment to any field: a message is a value."""
    version = Version.parse(_VERSION_PAYLOAD)

    with pytest.raises(FrozenInstanceError):
        version.relay = True  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        version.nonce = 0  # type: ignore[misc]

    assert replace(version, relay=True).relay is True
    assert replace(version, relay=True).serialize() == _VERSION_PAYLOAD + b"\x01"

    # a Verack has no field to assign to, and two of them are one value
    assert Verack() == Verack()
    assert len({Verack(), Verack()}) == 1
