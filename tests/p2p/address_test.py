# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.address` module.

**The authority here is what `tests/p2p/message_test.py` says it is for
the envelope, and no stronger.** Bitcoin Core publishes no vector file
for these structures either -- there is no `address.json` to pin the way
`tests/_data/README.md` pins `siphash.json` -- so what is below is
btclib's own round trips plus one captured message, and the captured one
is what the round trips cannot replace.

That message is the `addr` the Bitcoin Wiki's Protocol documentation
publishes with its octets, cited by revision:
https://en.bitcoin.it/w/index.php?title=Protocol_documentation&oldid=68832

The citation is weaker than a vendored file in the two ways the envelope's
tests state: it names a wiki revision rather than a commit in a repository
anybody can clone, and the page could not be re-read from the environment
these tests were written in. What makes it evidence all the same is that
it authenticates itself -- the checksum in its own header recomputes from
the payload beside it, which `test_the_captured_addr_authenticates_itself`
is -- and that what it decides cannot be decided any other way:

- **the port is big-endian.** Those two octets are `208d`, and a peer
  listening on 8333 is what they mean; read little-endian they are 36128,
  a port nothing serves. A round trip against btclib's own serializer
  agrees with itself whichever way it reads them.
- **an IPv4 address is mapped into sixteen octets.** They are
  `00000000000000000000ffff0a000001`, which is `10.0.0.1`.

Everything else is a round trip, a refusal, or a reading of Core's
src/protocol.h and src/netaddress.cpp.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address

import pytest

from btclib import var_int
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.p2p import (
    Addr,
    Message,
    NetworkAddress,
    ServiceFlags,
    TimestampedNetworkAddress,
)
from btclib.p2p.limits import MAX_ADDR_TO_SEND

# The Bitcoin Wiki's Protocol documentation, "addr" section: one address,
# split at the field boundaries the page annotates.
_ADDR_PAYLOAD = bytes.fromhex(
    "01"  # one address
    "e215104d"  # timestamp
    "0100000000000000"  # services: NODE_NETWORK
    "00000000000000000000ffff0a000001"  # 10.0.0.1, mapped into IPv6
    "208d"  # port 8333, big-endian
)
_ADDR = (
    bytes.fromhex(
        "f9beb4d9"  # mainnet
        "61646472000000000000000"  # "addr", NUL padded to twelve
        "0"
        "1f000000"  # payload length, 31 little-endian
        "ed52399b"  # checksum
    )
    + _ADDR_PAYLOAD
)

_MAINNET = bytes.fromhex("f9beb4d9")


def test_the_captured_addr_authenticates_itself() -> None:
    """What makes a wiki revision evidence: the header checks the payload.

    A mistranscription of either half fails here, which is the property
    that stands in for a vendored file nobody has published. The envelope
    is what checks it, this being one message and not two things that
    happen to sit beside each other.
    """
    message = Message.parse(_ADDR)
    assert message.command == "addr"
    assert message.payload == _ADDR_PAYLOAD
    assert message.checksum == hash256(_ADDR_PAYLOAD)[:4]
    assert message.serialize() == _ADDR


def test_the_captured_addr_reads_the_port_big_endian() -> None:
    """The trap a self-consistent round trip cannot see.

    Two octets, `208d`. Big-endian they are 8333, which is the port
    Bitcoin listens on; little-endian they are 36128, which is nothing.
    Core writes them with `Using<BigEndianFormatter<2>>(obj.port)`, in
    `CService`'s `SERIALIZE_METHODS` of src/netaddress.h, and they are
    the only big-endian field of this protocol.
    """
    addr = Addr.parse(_ADDR_PAYLOAD)
    assert addr.addresses[0].address.port == 8333
    assert addr.addresses[0].address.port != 0x8D20

    # and the other direction, which is the half a parser alone leaves
    # untested: the octets this writes are the octets that arrived
    assert addr.serialize() == _ADDR_PAYLOAD
    assert addr.serialize()[-2:] == bytes.fromhex("208d")


def test_the_captured_addr_maps_its_ipv4_address_in() -> None:
    """Sixteen octets, always, with an IPv4 address inside them.

    `::ffff:10.0.0.1` is what `10.0.0.1` is on the wire, Core's
    `CNetAddr::SerializeV1Array`. `ipv4_mapped` is what answers the
    question a separate tag for the family would have been kept for.
    """
    entry = Addr.parse(_ADDR_PAYLOAD).addresses[0]
    assert entry.address.ip == IPv6Address("::ffff:10.0.0.1")
    assert entry.address.ip.ipv4_mapped == IPv4Address("10.0.0.1")
    assert entry.address.ip.packed == bytes.fromhex("00000000000000000000ffff0a000001")

    # the timestamp is the one an `addr` entry has and a `version`
    # message's addresses have not: four octets, little-endian, unsigned
    assert entry.timestamp == 0x4D1015E2


def test_an_ipv4_address_has_one_object_however_it_is_spelled() -> None:
    """Every spelling of one peer builds the one address.

    The alternative -- holding four octets and a tag for a v4 address and
    sixteen for a v6 one -- is what btclib_node does, and it makes
    `::ffff:10.0.0.1` and `10.0.0.1` two objects with one serialization,
    so a set of peers holds the same peer twice and a round trip is not
    the identity. Sixteen octets throughout is the answer.
    """
    mapped = NetworkAddress(0, "10.0.0.1", 8333)
    spellings = (
        NetworkAddress(0, "::ffff:10.0.0.1", 8333),
        NetworkAddress(0, IPv4Address("10.0.0.1"), 8333),
        NetworkAddress(0, IPv6Address("::ffff:10.0.0.1"), 8333),
        NetworkAddress(0, bytes.fromhex("00000000000000000000ffff0a000001"), 8333),
        NetworkAddress(0, "  10.0.0.1  ", 8333),
    )
    for spelling in spellings:
        assert spelling == mapped
        assert spelling.serialize() == mapped.serialize()

    # one object, so one member of a set: the property a database of
    # peers rests on
    assert len({mapped, *spellings}) == 1


def test_a_real_ipv6_address_is_not_an_ipv4_one() -> None:
    """The sixteen octets are kept, so nothing is mistaken for a mapping."""
    address = NetworkAddress(0, "2001:db8::1", 8333)
    assert address.ip.ipv4_mapped is None
    assert NetworkAddress.parse(address.serialize()) == address

    # the sharp case: an address whose first twelve octets *are* the
    # mapping prefix is the mapped address, and there is no other
    # sixteen-octet value it could be
    assert NetworkAddress(0, "::ffff:255.255.255.255", 0).ip.ipv4_mapped is not None


def test_the_ip_text_is_an_address_and_never_hex() -> None:
    """The one field of this library whose `str` is not a hex string.

    `bytes_from_octets` would read "10.0.0.1" as hex and refuse it, and
    there is no dotted quad it would accept, so a converter of its own is
    what this field takes. Sixteen octets are the bytes-shaped input.
    """
    assert NetworkAddress(0, "::1", 0).ip == IPv6Address("::1")

    with pytest.raises(BTClibValueError, match="invalid ip"):
        NetworkAddress(0, "00000000000000000000ffff0a000001", 0)
    with pytest.raises(BTClibValueError, match="invalid ip"):
        NetworkAddress(0, "not an address", 0)
    with pytest.raises(BTClibValueError, match="invalid ip"):
        NetworkAddress(0, bytes(15), 0)
    with pytest.raises(BTClibValueError, match="invalid ip"):
        NetworkAddress(0, bytes(17), 0)
    with pytest.raises(BTClibTypeError, match="invalid ip type"):
        NetworkAddress(0, 1, 0)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "flags",
    [
        ServiceFlags.NODE_NONE,
        ServiceFlags.NODE_NETWORK,
        ServiceFlags.NODE_NETWORK | ServiceFlags.NODE_WITNESS,
        ServiceFlags.NODE_COMPACT_FILTERS,
        ServiceFlags.NODE_NETWORK_LIMITED,
        ServiceFlags.NODE_P2P_V2,
    ],
)
def test_the_named_service_bits_are_the_ones_core_declares(
    flags: ServiceFlags,
) -> None:
    """src/protocol.h's `enum ServiceFlags`, bit for bit."""
    address = NetworkAddress(flags, "::1", 0)
    assert NetworkAddress.parse(address.serialize()).services == flags


def test_the_named_bits_are_at_the_offsets_core_puts_them() -> None:
    """The numbers, so that a renamed member cannot pass the test above.

    `int()` around each, so that mypy is comparing two integers: an enum
    member and a literal are two `Literal` types to it, and it calls the
    comparison of two that differ a non-overlapping check rather than the
    assertion it is.
    """
    assert int(ServiceFlags.NODE_NONE) == 0
    assert int(ServiceFlags.NODE_NETWORK) == 1 << 0
    assert int(ServiceFlags.NODE_BLOOM) == 1 << 2
    assert int(ServiceFlags.NODE_WITNESS) == 1 << 3
    assert int(ServiceFlags.NODE_COMPACT_FILTERS) == 1 << 6
    assert int(ServiceFlags.NODE_NETWORK_LIMITED) == 1 << 10
    assert int(ServiceFlags.NODE_P2P_V2) == 1 << 11


@pytest.mark.parametrize(
    "bit, what",
    [
        (1 << 1, "BIP64's NODE_GETUTXO, which Core has removed"),
        (1 << 24, "the first of the bits Core reserves for experiments"),
        (1 << 31, "the last of them"),
        (1 << 63, "the highest bit eight octets hold"),
    ],
)
def test_a_service_bit_this_library_cannot_name_round_trips(
    bit: int, what: str
) -> None:
    """An unknown bit is a service, not an error.

    Core reserves bits 24-31 "for temporary experiments" and sends the
    rest through the BIP process, so a bitfield carrying one this library
    has no member for is a peer offering something newer than this
    library -- and `serviceFlagsToStr` answers "UNKNOWN[...]" rather than
    refusing. What that requires of the representation is that the bit
    survive a round trip, which an `IntFlag` gives and a table of known
    names would not.
    """
    services = ServiceFlags.NODE_NETWORK | bit
    address = NetworkAddress(services, "::1", 8333)
    assert int(address.services) == 1 | bit, what
    assert NetworkAddress.parse(address.serialize()) == address, what
    assert ServiceFlags.NODE_NETWORK in address.services, what


def test_the_flags_are_an_int_wherever_one_is_wanted() -> None:
    """`IntFlag`, so nothing else in the library has to know about it."""
    address = NetworkAddress(1, "::1", 0)
    assert address.services == 1
    assert NetworkAddress(ServiceFlags.NODE_NETWORK, "::1", 0) == address
    # and a plain int is coerced on the way in, so the two spellings are
    # one object rather than two that compare equal
    assert isinstance(address.services, ServiceFlags)


def test_a_version_address_and_an_addr_entry_are_not_one_class() -> None:
    """Twenty-six octets and thirty, for what Core's prose calls one thing.

    The mistake this shape makes unsayable is putting an `addr` entry in
    a `version`, which under a single class with a `with_time` flag is a
    runtime question about a field rather than a type error at the call.
    """
    address = NetworkAddress(1, "10.0.0.1", 8333)
    entry = TimestampedNetworkAddress(0x4D1015E2, address)

    assert len(address.serialize()) == 26
    assert len(entry.serialize()) == 30
    assert entry.serialize()[4:] == address.serialize()
    # and the mistake is refused by mypy rather than at runtime, which is
    # the whole point of two classes: `issubclass` is what can be written
    # here at all, `isinstance` on the value being a check mypy answers
    # statically and then reports as unreachable
    assert not issubclass(TimestampedNetworkAddress, NetworkAddress)


def test_the_round_trip_of_every_structure_here() -> None:
    """Each parses back to the object it was written from."""
    address = NetworkAddress(ServiceFlags.NODE_WITNESS, "2001:db8::1", 18333)
    assert NetworkAddress.parse(address.serialize()) == address

    entry = TimestampedNetworkAddress(1, address)
    assert TimestampedNetworkAddress.parse(entry.serialize()) == entry

    addr = Addr([entry, TimestampedNetworkAddress(2, NetworkAddress())])
    assert Addr.parse(addr.serialize()) == addr

    # the empty one, which is a message Core sends: a `getaddr` answered
    # by a node that knows nobody
    assert Addr.parse(Addr().serialize()) == Addr()
    assert Addr().serialize() == b"\x00"


def test_the_defaults_are_the_address_that_says_nothing() -> None:
    """What `version` carries where a node does not know its own address.

    Which is what the captured `version` of `tests/p2p/message_test.py`
    carries: `::ffff:0.0.0.0` and port 0, twice.
    """
    assert NetworkAddress() == NetworkAddress(0, "::", 0)
    assert NetworkAddress().serialize() == bytes(26)
    assert TimestampedNetworkAddress() == TimestampedNetworkAddress(0, NetworkAddress())
    assert TimestampedNetworkAddress().serialize() == bytes(30)


def test_more_addresses_than_a_peer_accepts_are_refused() -> None:
    """Core's `MAX_ADDR_TO_SEND`, at the object boundary and in `parse`.

    The same bound and not the same check: this one answers to
    `check_validity`, and the one in `parse` -- read off the count before
    a single address is built -- does not.
    """
    entry = TimestampedNetworkAddress(0, NetworkAddress())
    assert len(Addr([entry] * MAX_ADDR_TO_SEND).addresses) == MAX_ADDR_TO_SEND

    with pytest.raises(BTClibValueError, match="invalid addresses count"):
        Addr([entry] * (MAX_ADDR_TO_SEND + 1))

    too_many = Addr([entry] * (MAX_ADDR_TO_SEND + 1), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid addresses count"):
        too_many.serialize()


def test_the_count_is_bounded_before_anything_is_built() -> None:
    """The check that is the whole point of having one.

    The count is the peer's to choose and btclib's own `var_int.parse`
    allows 33,554,432 of them, so a parser that builds first turns nine
    octets into as many thirty-octet objects -- which is what
    btclib_node's `Addr.deserialize` does. The refusal here reads the
    count and stops, with no payload behind it at all, and it does not
    answer to `check_validity`.
    """
    for check_validity in (True, False):
        for count in (MAX_ADDR_TO_SEND + 1, var_int.MAX_SIZE):
            header = var_int.serialize(count)
            with pytest.raises(BTClibValueError, match="invalid addresses count"):
                Addr.parse(BytesIO(header), check_validity=check_validity)

    # and the bound itself is a count this reads: what is refused is the
    # number and not the buffer, so the refusal below is the truncation
    header = var_int.serialize(MAX_ADDR_TO_SEND)
    with pytest.raises(BTClibValueError, match="not enough data"):
        Addr.parse(BytesIO(header))


def test_what_no_field_of_this_width_holds_is_refused() -> None:
    """`assert_valid` over every field, at the object boundary."""
    with pytest.raises(BTClibValueError, match="invalid services"):
        NetworkAddress(-1, "::1", 0)
    with pytest.raises(BTClibValueError, match="invalid services"):
        NetworkAddress(1 << 64, "::1", 0)
    with pytest.raises(BTClibValueError, match="invalid port"):
        NetworkAddress(0, "::1", -1)
    with pytest.raises(BTClibValueError, match="invalid port"):
        NetworkAddress(0, "::1", 0x10000)

    with pytest.raises(BTClibValueError, match="invalid timestamp"):
        TimestampedNetworkAddress(-1, NetworkAddress())
    with pytest.raises(BTClibValueError, match="invalid timestamp"):
        TimestampedNetworkAddress(1 << 32, NetworkAddress())

    # the highest value each of them holds is a value, which is what says
    # the bound and not the field is what was refused
    assert NetworkAddress((1 << 64) - 1, "::1", 0xFFFF).serialize()
    assert TimestampedNetworkAddress(0xFFFFFFFF, NetworkAddress()).serialize()


def test_a_wrong_type_is_a_type_error() -> None:
    """A value of a type the signature does not declare, at every field."""
    with pytest.raises(BTClibTypeError, match="invalid services type"):
        NetworkAddress(1.5, "::1", 0)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid port type"):
        NetworkAddress(0, "::1", 1.5)  # type: ignore[arg-type]
    # a bool is an int and would read as port 1 or 0, which the range
    # check cannot tell from a port
    with pytest.raises(BTClibTypeError, match="invalid port type"):
        NetworkAddress(0, "::1", True)
    with pytest.raises(BTClibTypeError, match="invalid services type"):
        NetworkAddress(True, "::1", 0)

    with pytest.raises(BTClibTypeError, match="invalid timestamp type"):
        TimestampedNetworkAddress(1.5, NetworkAddress())  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid address type"):
        TimestampedNetworkAddress(0, "10.0.0.1")  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        Addr(1)  # type: ignore[arg-type]
    # a str and a bytes are Sequences, so the argument is asked whole:
    # what fails must be the argument, not its first character
    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        Addr("10.0.0.1")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        Addr(b"\x00" * 30)  # type: ignore[arg-type]
    # every Octets spelling, not only str and bytes (issue #1434)
    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        Addr(bytearray(b"\x00" * 30))  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        Addr(memoryview(b"\x00" * 30))
    with pytest.raises(BTClibTypeError, match="invalid address type"):
        Addr([NetworkAddress()])  # type: ignore[list-item]


def test_the_octets_of_a_field_are_read_where_they_end() -> None:
    """Every truncation is refused, and the field names itself."""
    address = NetworkAddress(1, "10.0.0.1", 8333)
    with pytest.raises(BTClibValueError, match="address services"):
        NetworkAddress.parse(address.serialize()[:4])
    with pytest.raises(BTClibValueError, match="address ip"):
        NetworkAddress.parse(address.serialize()[:16])
    with pytest.raises(BTClibValueError, match="address port"):
        NetworkAddress.parse(address.serialize()[:25])

    entry = TimestampedNetworkAddress(1, address)
    with pytest.raises(BTClibValueError, match="address timestamp"):
        TimestampedNetworkAddress.parse(entry.serialize()[:3])


def test_a_stream_is_read_one_address_at_a_time() -> None:
    """What `Addr.parse` rests on: each structure leaves the rest alone."""
    first = NetworkAddress(1, "10.0.0.1", 8333)
    second = NetworkAddress(0, "::1", 18333)
    stream = BytesIO(first.serialize() + second.serialize() + b"junk")

    assert NetworkAddress.parse(stream) == first
    assert NetworkAddress.parse(stream) == second
    assert stream.read() == b"junk"


def test_frozen() -> None:
    """Refuse assignment to any field: an address is a value."""
    address = NetworkAddress(1, "10.0.0.1", 8333)

    with pytest.raises(FrozenInstanceError):
        address.port = 0  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        TimestampedNetworkAddress(0, address).timestamp = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        Addr().addresses = ()  # type: ignore[misc]

    assert replace(address, port=18333) == NetworkAddress(1, "10.0.0.1", 18333)


def test_the_addresses_of_an_addr_are_a_tuple() -> None:
    """So that a frozen Addr is what its fields say it is."""
    entry = TimestampedNetworkAddress(0, NetworkAddress())
    assert Addr([entry]).addresses == (entry,)
    assert Addr((entry,)) == Addr([entry])


def test_the_command_and_the_envelope_it_travels_in() -> None:
    """`to_message` writes the command the class holds, once."""
    addr = Addr(
        [TimestampedNetworkAddress(0x4D1015E2, NetworkAddress(1, "10.0.0.1", 8333))]
    )
    message = addr.to_message(_MAINNET)

    assert message.command == Addr.command == "addr"
    assert message.payload == _ADDR_PAYLOAD
    assert message.serialize() == _ADDR
    # and the way back, which is the caller's `if` and not a table here
    assert Addr.parse(Message.parse(_ADDR).payload) == addr


def test_the_flag_still_switches_the_check_off() -> None:
    """Verify check_validity=False writes a timestamp of the wrong type.

    Every entry above is built checked, so `serialize`'s
    `if check_validity:` ran one way only. A `bool` timestamp is the
    invalidity to carry: a bool is an int, so it passes every range check
    and `to_bytes` writes it as the one it is, where a timestamp out of
    range would overflow the four octets before the flag could be read.
    """
    invalid = TimestampedNetworkAddress(True, NetworkAddress(), check_validity=False)

    assert invalid.serialize(check_validity=False)[:4] == b"\x01\x00\x00\x00"
    with pytest.raises(BTClibTypeError, match="invalid timestamp type: bool"):
        invalid.serialize()
