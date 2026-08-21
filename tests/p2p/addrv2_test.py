# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.addrv2` module.

**BIP155 publishes no vectors, and this is where that is said.** The
specification is precise about the fields and about what to do with each
of them, and it carries no worked example, no hex and no file: there is
nothing to pin in `tests/_data/README.md` the way `siphash.json` is
pinned. So what is below is btclib's own round trips plus the octets
Bitcoin Core's unit tests carry, and nothing here is claimed to be more.

Those octets are transcribed from two files of Core, cited by the commit
they were read at rather than by `master`, which moves:

- `src/test/netbase_tests.cpp` at
  [`dbbb780`](https://github.com/bitcoin/bitcoin/blob/dbbb780af02d850a1f9257f18610cfb9de9cb828/src/test/netbase_tests.cpp),
  whose `stream_addrv2_hex` is a whole `addrv2` payload -- a count and
  three entries -- and its `fixture_addresses` the objects Core asserts
  it equals;
- `src/test/net_tests.cpp` at
  [`aa0e0f7`](https://github.com/bitcoin/bitcoin/blob/aa0e0f793fede33326491f14c79c848527632556/src/test/net_tests.cpp),
  whose `cnetaddr_serialize_v2` and `cnetaddr_unserialize_v2` carry a
  network id and an address for each network Core knows, and the
  refusals for a wrong length and an unknown id beside them.

A transcription is weaker than a vendored file in the way
`tests/_data/README.md` states: nothing compares these octets with
upstream byte for byte, so a slip in copying them is a slip this suite
cannot see. What makes them evidence all the same is that Core annotates
every line of both -- "time, Fri Jan 9 02:54:25 UTC 2009", "service
flags, `COMPACTSIZE(NODE_NETWORK)`", "network type (IPv4)" -- and each
annotation is asserted below against the field it names, so a
mistranscription shows up as an octet that disagrees with the comment it
was copied with.

What they decide that a round trip cannot:

- **the port is big-endian.** The last entry's two octets are `f1f2`,
  which Core's fixture built from port 0xf1f2 -- 61938. Read
  little-endian they are 62193, and a round trip against btclib's own
  serializer agrees with itself either way.
- **the services are a `CompactSize`.** One octet where an `addr` entry
  writes eight, and `fd4804` for the third address, which is
  `NODE_WITNESS | NODE_COMPACT_FILTERS | NODE_NETWORK_LIMITED`.
- **each network's address length**, and that the address is the octets
  themselves rather than anything derived from them.

Everything else is a round trip, a refusal, or a reading of BIP155 and of
Core's `SetNetFromBIP155Network`.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
from ipaddress import IPv4Address, IPv6Address

import pytest

from btclib import var_int
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import (
    AddrV2,
    BIP155Network,
    Message,
    NetworkAddress,
    NetworkAddressV2,
    SendAddrV2,
    ServiceFlags,
    TimestampedNetworkAddress,
)
from btclib.p2p.limits import MAX_ADDR_TO_SEND, MAX_ADDRV2_SIZE

_MAINNET = bytes.fromhex("f9beb4d9")

# Core's `stream_addrv2_hex`, of src/test/netbase_tests.cpp, split at the
# field boundaries its own comments annotate
_ADDRV2_PAYLOAD = bytes.fromhex(
    "03"  # number of entries
    "61bc6649"  # time, Fri Jan  9 02:54:25 UTC 2009
    "00"  # service flags, COMPACTSIZE(NODE_NONE)
    "02"  # network id, IPv6
    "10"  # address length, COMPACTSIZE(16)
    "00000000000000000000000000000001"  # address, ::1
    "0000"  # port
    "79627683"  # time, Tue Nov 22 11:22:33 UTC 2039
    "01"  # service flags, COMPACTSIZE(NODE_NETWORK)
    "02"
    "10"
    "00000000000000000000000000000001"
    "00f1"  # port 241
    "ffffffff"  # time, Sun Feb  7 06:28:15 UTC 2106
    "fd4804"  # NODE_WITNESS | NODE_COMPACT_FILTERS | NODE_NETWORK_LIMITED
    "02"
    "10"
    "00000000000000000000000000000001"
    "f1f2"  # port 61938
)

# the loopback address all three of Core's fixtures are on,
# COMPAT_IN6ADDR_LOOPBACK_INIT
_LOOPBACK = bytes.fromhex("00000000000000000000000000000001")

# and the objects Core asserts that payload equals, its `fixture_addresses`
_ADDRV2 = AddrV2(
    [
        NetworkAddressV2(
            0x4966BC61, ServiceFlags.NODE_NONE, BIP155Network.IPV6, _LOOPBACK, 0
        ),
        NetworkAddressV2(
            0x83766279, ServiceFlags.NODE_NETWORK, BIP155Network.IPV6, _LOOPBACK, 0x00F1
        ),
        NetworkAddressV2(
            0xFFFFFFFF,
            ServiceFlags.NODE_WITNESS
            | ServiceFlags.NODE_COMPACT_FILTERS
            | ServiceFlags.NODE_NETWORK_LIMITED,
            BIP155Network.IPV6,
            _LOOPBACK,
            0xF1F2,
        ),
    ]
)

# Core's `cnetaddr_serialize_v2` and `cnetaddr_unserialize_v2`, of
# src/test/net_tests.cpp: the network id and the length-prefixed address
# of one peer on each network Core knows, with the address that peer is
# reached at. A `CNetAddr` carries no time, services or port, so these
# are the middle of an entry rather than a whole one
_CNETADDR_V2 = (
    ("ipv4", BIP155Network.IPV4, "010401020304", "1.2.3.4"),
    (
        "ipv6",
        BIP155Network.IPV6,
        "02101a1b2a2b3a3b4a4b5a5b6a6b7a7b8a8b",
        "1a1b:2a2b:3a3b:4a4b:5a5b:6a6b:7a7b:8a8b",
    ),
    (
        "torv3",
        BIP155Network.TORV3,
        "042079bcc625184b05194975c28b66b66b0469f7f6556fb1ac3189a79b40dda32f1f",
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    ),
    (
        "i2p",
        BIP155Network.I2P,
        "0520a2894dabaec08c0051a481a6dac88b64f98232ae42d4b6fd2fa81952dfe36a87",
        "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p",
    ),
    (
        "cjdns",
        BIP155Network.CJDNS,
        "0610fc000001000200030004000500060007",
        "fc00:1:2:3:4:5:6:7",
    ),
)

_CNETADDR_IDS = tuple(case[0] for case in _CNETADDR_V2)


def _entry(hex_middle: str) -> bytes:
    """Return a whole entry around a `CNetAddr`'s network id and address.

    Core's vectors for the two middle fields are a `CNetAddr`, which
    carries neither the time and services in front of them nor the port
    behind. Zero for all three is what puts them in an entry without
    saying anything else about it: the timestamp is four NUL octets, the
    services one, and the port two.
    """
    return bytes.fromhex("00000000" + "00" + hex_middle + "0000")


def test_the_core_addrv2_payload_round_trips() -> None:
    """Core's own `addrv2` octets, and the objects it says they are.

    `caddress_serialize_v2` asserts the payload of `fixture_addresses`
    equals this hex and `caddress_unserialize_v2` the other direction, so
    both halves are Core's assertion rather than btclib's.
    """
    assert AddrV2.parse(_ADDRV2_PAYLOAD) == _ADDRV2
    assert _ADDRV2.serialize() == _ADDRV2_PAYLOAD


def test_the_core_addrv2_payload_reads_the_port_big_endian() -> None:
    """The trap a self-consistent round trip cannot see.

    Core's third fixture is built at port 0xf1f2 and the two octets are
    `f1f2`; read little-endian they are 62193, which is a different peer.
    The second fixture is the same statement at the other end of the
    field: 0x00f1 is 241 big-endian and 61696 little-endian.
    """
    addr = AddrV2.parse(_ADDRV2_PAYLOAD)
    assert addr.addresses[2].port == 0xF1F2
    assert addr.addresses[2].port != 0xF2F1
    assert addr.addresses[1].port == 0x00F1
    assert addr.addresses[1].port != 0xF100

    # and the other direction, which is the half a parser alone leaves
    # untested: the octets this writes are the octets that arrived
    assert addr.serialize() == _ADDRV2_PAYLOAD
    assert addr.serialize()[-2:] == bytes.fromhex("f1f2")


def test_the_core_addrv2_payload_writes_the_services_as_a_compact_size() -> None:
    """One octet where an `addr` entry writes eight, and three for 1096.

    Which is the encoding change BIP155 made beside the address, and
    Jonas Schnelli's suggestion the BIP credits: `NODE_NONE` is `00` and
    `NODE_NETWORK` is `01` where the older message writes eight octets
    for each.
    """
    addr = AddrV2.parse(_ADDRV2_PAYLOAD)
    assert addr.addresses[0].services == ServiceFlags.NODE_NONE
    assert addr.addresses[1].services == ServiceFlags.NODE_NETWORK
    assert addr.addresses[2].services == (
        ServiceFlags.NODE_WITNESS
        | ServiceFlags.NODE_COMPACT_FILTERS
        | ServiceFlags.NODE_NETWORK_LIMITED
    )

    # Core annotates the third as `fd4804`, which is 1096 in three octets
    assert int(addr.addresses[2].services) == 0x0448
    assert var_int.serialize(int(addr.addresses[2].services)) == bytes.fromhex("fd4804")
    assert _ADDRV2_PAYLOAD.count(bytes.fromhex("fd4804")) == 1


def test_the_core_addrv2_payload_carries_the_timestamps_core_annotates() -> None:
    """Four octets little-endian, which is the field's other end.

    Core's comments name the three by date, and the last of them is the
    largest four octets hold: a timestamp is unsigned here, where a
    `version` message's is signed and eight octets wide.
    """
    addr = AddrV2.parse(_ADDRV2_PAYLOAD)
    assert [entry.timestamp for entry in addr.addresses] == [
        0x4966BC61,
        0x83766279,
        0xFFFFFFFF,
    ]


@pytest.mark.parametrize(
    "network_id, hex_middle, rendering",
    [case[1:] for case in _CNETADDR_V2],
    ids=_CNETADDR_IDS,
)
def test_a_core_network_id_and_address(
    network_id: BIP155Network, hex_middle: str, rendering: str
) -> None:
    """Each network Core knows, with the octets Core writes for it.

    The address is those octets and nothing derived from them, which is
    what makes the third and fourth cases the ones worth having: a
    `.onion` name is a base32 of the address plus a SHA3-256 checksum and
    a version octet, and a `.b32.i2p` name a base32 of the address alone,
    so neither is recoverable from the wire without a hash function this
    codec does not call.
    """
    octets = _entry(hex_middle)
    entry = NetworkAddressV2.parse(octets)

    assert entry.network_id == network_id
    assert entry.serialize() == octets
    assert bytes.fromhex(hex_middle).startswith(bytes([network_id]))
    assert entry.address == bytes.fromhex(hex_middle)[2:]

    # what BIP155's "Address length (bytes)" column fixes for the id, read
    # off the vector rather than off the table the module holds
    assert len(entry.address) == len(bytes.fromhex(hex_middle)) - 2

    # and the two ids whose octets are an address `ipaddress` reads, which
    # is the one line the module leaves to the caller
    if network_id == BIP155Network.IPV4:
        assert IPv4Address(entry.address) == IPv4Address(rendering)
    elif network_id in (BIP155Network.IPV6, BIP155Network.CJDNS):
        assert IPv6Address(entry.address) == IPv6Address(rendering)


@pytest.mark.parametrize(
    "network_id, size",
    [
        (BIP155Network.IPV4, 4),
        (BIP155Network.IPV6, 16),
        (BIP155Network.TORV2, 10),
        (BIP155Network.TORV3, 32),
        (BIP155Network.I2P, 32),
        (BIP155Network.CJDNS, 16),
        (BIP155Network.YGGDRASIL, 16),
    ],
    ids=lambda value: getattr(value, "name", value),
)
def test_the_length_bip155_fixes_for_each_id(
    network_id: BIP155Network, size: int
) -> None:
    """BIP155's table, transcribed here and enforced by `assert_valid`.

    `TORV2` and `YGGDRASIL` are held to it as well, and their lengths
    come from the BIP and from nothing else: Core drops a `TORV2`
    address through its unknown-id path and has no `YGGDRASIL` at all,
    so it enforces a length for neither.
    """
    entry = NetworkAddressV2(0, 0, network_id, bytes(size), 8333)
    assert entry.serialize() == NetworkAddressV2.parse(entry.serialize()).serialize()

    for wrong in (size - 1, size + 1):
        with pytest.raises(BTClibValueError, match="invalid address length"):
            NetworkAddressV2(0, 0, network_id, bytes(wrong), 8333)


def test_an_unknown_network_id_round_trips() -> None:
    """The property BIP155 exists for, and Core's own two vectors for it.

    `cnetaddr_unserialize_v2` reads a network type `aa` with a four-octet
    address and one with none, and asserts of each that the stream is
    consumed -- Core drops the address and goes on reading the ones after
    it. btclib keeps the octets instead, the plain `int` standing where
    no member names the id, which is what `InventoryType` does for a type
    code no member names.
    """
    for hex_middle in ("aa0401020304", "aa00"):
        octets = _entry(hex_middle)
        entry = NetworkAddressV2.parse(octets)

        assert entry.network_id == 0xAA
        assert not isinstance(entry.network_id, BIP155Network)
        assert entry.serialize() == octets

    # and inside a message, which is where Core reads them: an id nobody
    # has heard of does not stop the entries after it
    payload = b"\x02" + _entry("aa0401020304") + _entry("010401020304")
    addr = AddrV2.parse(payload)
    assert addr.addresses[0].network_id == 0xAA
    assert addr.addresses[1].network_id == BIP155Network.IPV4
    assert addr.serialize() == payload


def test_an_unknown_network_id_is_held_to_no_length_but_the_bound() -> None:
    """No table entry, so nothing to disagree with: only `MAX_ADDRV2_SIZE`.

    Which is BIP155's "irrespective of the network ID" read the other
    way round -- the bound applies to every id, and the table applies to
    the ones it names.
    """
    for size in (0, 1, MAX_ADDRV2_SIZE):
        entry = NetworkAddressV2(0, 0, 0xAA, bytes(size), 0)
        assert NetworkAddressV2.parse(entry.serialize()) == entry

    with pytest.raises(BTClibValueError, match="invalid address length"):
        NetworkAddressV2(0, 0, 0xAA, bytes(MAX_ADDRV2_SIZE + 1), 0)


def test_the_address_bound_is_checked_off_the_length_field() -> None:
    """Before the read it would size, which is the whole point of a bound.

    Core refuses the same two: `cnetaddr_unserialize_v2` reads an IPv4 id
    with a length of 513 and an unknown id with a length of
    `CompactSize`'s `MAX_SIZE`, and answers both "Address too long".
    btclib's `var_int.parse` refuses anything above that `MAX_SIZE`
    already, so the check here is what stands between it and 512.
    """
    # BIP155's bound, one octet over, with none of those octets present:
    # the refusal is off the length and cannot be off the address
    too_long = bytes.fromhex("00000000" + "00" + "01" + "fd0102")
    with pytest.raises(BTClibValueError, match="invalid address length"):
        NetworkAddressV2.parse(too_long)

    # and Core's other one, a length no message could carry
    extreme = bytes.fromhex("00000000" + "00" + "aa" + "fe00000002")
    with pytest.raises(BTClibValueError, match="invalid address length"):
        NetworkAddressV2.parse(extreme)

    # the bound does not answer to `check_validity`: a defence a caller
    # can turn off is not one
    with pytest.raises(BTClibValueError, match="invalid address length"):
        NetworkAddressV2.parse(too_long, check_validity=False)


@pytest.mark.parametrize(
    "network_id, wrong, expected",
    [
        (BIP155Network.IPV4, 5, 4),  # Core: "IPv4 address with length 5"
        (BIP155Network.IPV6, 4, 16),  # Core: "IPv6 address with length 4"
        (BIP155Network.TORV2, 9, 10),
        (BIP155Network.TORV3, 0, 32),  # Core: "TORv3 address with length 0"
        (BIP155Network.I2P, 3, 32),  # Core: "I2P address with length 3"
        (BIP155Network.CJDNS, 1, 16),  # Core: "CJDNS address with length 1"
        (BIP155Network.YGGDRASIL, 4, 16),
    ],
    ids=lambda value: getattr(value, "name", value),
)
def test_a_known_id_with_the_wrong_length_is_refused(
    network_id: BIP155Network, wrong: int, expected: int
) -> None:
    """BIP155 says reject the message, and Core throws rather than skips.

    "Clients SHOULD reject messages that contain addresses that have a
    different length than specified in this table for a specific network
    ID, as these are meaningless" -- and `SetNetFromBIP155Network` raises
    `std::ios_base::failure` for each id it knows, where an *unknown* id
    a few lines below it returns false and is dropped. Ignoring the entry
    is what this codec cannot do: a message one address shorter than it
    arrived does not serialize back.

    The lengths are Core's own cases where it has one. `TORV2` and
    `YGGDRASIL` are the two it refuses nothing for, so those two are
    held to BIP155's table and to nothing else.
    """
    octets = _entry(f"{network_id:02x}{wrong:02x}" + "00" * wrong)

    with pytest.raises(BTClibValueError, match=f"instead of {expected} for network id"):
        NetworkAddressV2.parse(octets)

    # and the message with it, an entry nobody can represent not being
    # something a payload can hold either
    with pytest.raises(BTClibValueError, match="invalid address length"):
        AddrV2.parse(b"\x01" + octets)


def test_a_wrong_length_is_a_validity_check_and_answers_to_the_flag() -> None:
    """Which is what tells it from the bound above, and from Core.

    Core refuses off the length field, before the address is read, so its
    own vector for this claims five octets and carries four. Here the
    entry is built first and refused after, which is what lets
    `check_validity=False` read octets nothing accepts -- and the entry
    then serializes back to exactly what it came from, so the round trip
    is the one thing the flag does not cost. Both reject the message;
    what differs is whether a caller can look at it.
    """
    octets = _entry("01050102030405")
    entry = NetworkAddressV2.parse(octets, check_validity=False)

    assert entry.network_id == BIP155Network.IPV4
    assert entry.address == bytes.fromhex("0102030405")
    assert entry.serialize(check_validity=False) == octets

    with pytest.raises(BTClibValueError, match="invalid address length"):
        entry.assert_valid()
    with pytest.raises(BTClibValueError, match="invalid address length"):
        entry.serialize()

    # and Core's own vector, whose address is shorter than its length
    # field says: refused here as the truncation it is, which is the
    # check one layer under the table
    with pytest.raises(BTClibValueError, match="not enough data"):
        NetworkAddressV2.parse(bytes.fromhex("00000000" + "00" + "010501020304"))


def test_a_torv2_address_parses_where_core_ignores_it() -> None:
    """Ignoring is receive policy, and this package holds none.

    BIP155 names `TORV2` in its table and says clients "MUST ignore them
    on receive"; Core carries that out by naming the id in its
    `BIP155Network` and giving `SetNetFromBIP155Network` no case for it,
    so it falls through to the unknown-id path --
    `cnetaddr_unserialize_v2` reads its `03`/`0a` vector and asserts the
    result is `!IsValid()`, parsed and then thrown away. Refusing the
    octets would refuse a message Core accepts.
    """
    octets = _entry("030af1f2f3f4f5f6f7f8f9fa")
    entry = NetworkAddressV2.parse(octets)

    assert entry.network_id == BIP155Network.TORV2
    assert entry.address == bytes.fromhex("f1f2f3f4f5f6f7f8f9fa")
    assert entry.serialize() == octets


def test_an_ipv6_address_in_a_reserved_range_parses() -> None:
    """The other thing BIP155 says to ignore, and the same answer.

    BIP155 version 2.1.0 states it: an IPv4-in-IPv6 or an OnionCat
    address "MUST NOT be sent with the `IPV6` network ID" and clients
    "SHOULD ignore" one on receive, so that one peer is not two. Core
    reads both -- `cnetaddr_unserialize_v2` has a vector for each -- and
    marks the result invalid, which is the same shape as `TORV2` above.
    """
    for hex_middle in (
        "021000000000000000000000ffff01020304",  # ::ffff:1.2.3.4
        "0210fd87d87eeb430102030405060708090a",  # OnionCat
    ):
        octets = _entry(hex_middle)
        entry = NetworkAddressV2.parse(octets)

        assert entry.network_id == BIP155Network.IPV6
        assert entry.serialize() == octets


def test_the_services_have_no_range_check_on_their_compact_size() -> None:
    """The one place btclib's `var_int` default is wrong for this format.

    `var_int.parse` caps at `MAX_SIZE`, 33,554,432, because everything
    else it reads in this library is a length or a count. These octets are
    a bitfield: Core reads them through
    `Using<CompactSizeFormatter<false>>`, the template argument being
    `RangeCheck`, and BIP155 calls the field "64 bits wide". Bit 25 is
    exactly `MAX_SIZE`, so the default cap starts refusing one bit above
    it -- inside the range Core reserves "for temporary experiments".
    """
    assert var_int.MAX_SIZE == 1 << 25

    for services in (1 << 25, 1 << 26, 1 << 63, (1 << 64) - 1):
        entry = NetworkAddressV2(0, services, BIP155Network.IPV4, bytes(4), 8333)
        assert NetworkAddressV2.parse(entry.serialize()) == entry
        assert int(NetworkAddressV2.parse(entry.serialize()).services) == services

    # and the field's own width, which is what refuses one bit above that
    with pytest.raises(BTClibValueError, match="invalid services"):
        NetworkAddressV2(0, 1 << 64, BIP155Network.IPV4, bytes(4), 8333)


def test_a_non_canonical_compact_size_is_refused() -> None:
    """One entry has one serialization, which the encoding is what buys.

    btclib's `var_int.parse` is canonical-only and both `CompactSize`
    fields of an entry inherit it; Core answers the same octets
    "non-canonical ReadCompactSize()".
    """
    canonical = _entry("010401020304")
    assert NetworkAddressV2.parse(canonical).serialize() == canonical

    # the services, written `fd0100` where `01` says the same thing
    non_canonical = bytes.fromhex("00000000" + "fd0100" + "010401020304" + "0000")
    with pytest.raises(BTClibValueError, match="non-canonical var_int"):
        NetworkAddressV2.parse(non_canonical)


def test_an_entry_defaults_to_what_core_default_constructs() -> None:
    """`CAddress()` is `NET_IPV4` at "0.0.0.0", and so is this.

    A default that is valid is what every wire class of this library
    answers with, and here the network id is what decides how long the
    address has to be for it to be one.
    """
    entry = NetworkAddressV2()

    assert entry.timestamp == 0
    assert entry.services == ServiceFlags.NODE_NONE
    assert entry.network_id == BIP155Network.IPV4
    assert entry.address == bytes(4)
    assert entry.port == 0
    assert NetworkAddressV2.parse(entry.serialize()) == entry


def test_an_address_is_accepted_as_hex_text() -> None:
    """`Octets`, which is what every opaque byte field of this library takes.

    The address is not an `IPAddress` the way `NetworkAddress.ip` is, and
    the reason is the reason the field exists: its meaning is the network
    id's, so hex is the one text form that reads the same for every id.
    """
    assert NetworkAddressV2(
        0, 0, BIP155Network.IPV4, "01020304", 8333
    ).address == bytes([1, 2, 3, 4])


def test_an_entry_is_a_frozen_value() -> None:
    """Hashable, and `replace` is what moves one to another port."""
    entry = NetworkAddressV2(1, 1, BIP155Network.IPV4, bytes(4), 8333)

    assert entry == NetworkAddressV2(1, 1, BIP155Network.IPV4, bytes(4), 8333)
    assert len({entry, NetworkAddressV2(1, 1, BIP155Network.IPV4, bytes(4), 8333)}) == 1
    assert replace(entry, port=18333).port == 18333
    assert entry.port == 8333

    with pytest.raises(FrozenInstanceError):
        entry.port = 18333  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs, exception, match",
    [
        ({"timestamp": 1.5}, BTClibTypeError, "invalid timestamp type"),
        ({"timestamp": True}, BTClibTypeError, "invalid timestamp type"),
        ({"timestamp": -1}, BTClibValueError, "invalid timestamp"),
        ({"timestamp": 1 << 32}, BTClibValueError, "invalid timestamp"),
        ({"services": 1.5}, BTClibTypeError, "invalid services type"),
        ({"services": True}, BTClibTypeError, "invalid services type"),
        ({"services": -1}, BTClibValueError, "invalid services"),
        ({"network_id": 1.5}, BTClibTypeError, "invalid network_id type"),
        ({"network_id": True}, BTClibTypeError, "invalid network_id type"),
        ({"network_id": -1}, BTClibValueError, "invalid network_id"),
        ({"network_id": 1 << 8}, BTClibValueError, "invalid network_id"),
        ({"port": 1.5}, BTClibTypeError, "invalid port type"),
        ({"port": True}, BTClibTypeError, "invalid port type"),
        ({"port": -1}, BTClibValueError, "invalid port"),
        ({"port": 1 << 16}, BTClibValueError, "invalid port"),
    ],
    ids=str,
)
def test_an_entry_refuses_a_field_no_width_holds(
    kwargs: dict[str, object], exception: type[Exception], match: str
) -> None:
    """Every field, its type and its range, through btclib's own exceptions.

    A bool is in the list for each of the four integer fields, and it is
    not pedantry: `True` is the number one, so a `port=True` would read
    as a peer on port 1 and a `network_id=True` as `IPV4`, which is
    exactly the value the range check cannot tell from a real one.
    """
    fields: dict[str, object] = {
        "timestamp": 0,
        "services": 0,
        "network_id": BIP155Network.IPV4,
        "address": bytes(4),
        "port": 0,
    }
    fields.update(kwargs)
    with pytest.raises(exception, match=match):
        NetworkAddressV2(**fields)  # type: ignore[arg-type]


def test_an_addrv2_bounds_its_count_before_it_builds_anything() -> None:
    """`MAX_ADDR_TO_SEND`, which is BIP155's thousand and Core's constant.

    "One message can contain up to 1,000 addresses. Clients SHOULD reject
    messages with more addresses", and Core reads `addr` and `addrv2`
    through the one `ProcessAddrs`, whose `vAddr.size() >
    MAX_ADDR_TO_SEND` is a `Misbehaving`. The check is off the count and
    before the loop, so nine octets do not ask for 33,554,432 objects.
    """
    entry = NetworkAddressV2(0, 0, BIP155Network.IPV4, bytes(4), 8333)
    assert len(AddrV2([entry] * MAX_ADDR_TO_SEND).addresses) == MAX_ADDR_TO_SEND

    with pytest.raises(BTClibValueError, match="invalid addresses count"):
        AddrV2([entry] * (MAX_ADDR_TO_SEND + 1))

    # off the count field, with nothing behind it: what a payload of a
    # few octets would otherwise allocate
    claimed = var_int.serialize(MAX_ADDR_TO_SEND + 1)
    with pytest.raises(BTClibValueError, match="invalid addresses count"):
        AddrV2.parse(claimed)

    # and it does not answer to `check_validity` either
    with pytest.raises(BTClibValueError, match="invalid addresses count"):
        AddrV2.parse(claimed, check_validity=False)


def test_an_addrv2_refuses_what_is_not_a_sequence_of_entries() -> None:
    """Asked whole, so that a str is a bad argument and not bad elements."""
    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        AddrV2("not a sequence")  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid addresses type"):
        AddrV2(1)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid address type"):
        AddrV2([1])  # type: ignore[list-item]

    # and an `addr` entry is not one either, which is the whole of what
    # two classes buy over one with a mode flag: the octets differ, so
    # putting one where the other belongs is a call mypy refuses and
    # `assert_valid` refuses again for the caller who has not run it
    entry = TimestampedNetworkAddress(0, NetworkAddress(1, "10.0.0.1", 8333))
    with pytest.raises(BTClibTypeError, match="invalid address type"):
        AddrV2([entry])  # type: ignore[list-item]


def test_an_empty_addrv2_is_a_message() -> None:
    """A count of zero, which is one octet and a complete payload."""
    assert AddrV2().serialize() == b"\x00"
    assert AddrV2.parse(b"\x00") == AddrV2()
    assert AddrV2().addresses == ()


def test_the_payloads_read_from_a_stream_and_refuse_a_trailing_octet() -> None:
    """Both halves of `assert_no_trailing`, for each class here.

    A caller's stream is left on the octet after the object -- an entry
    inside an `addrv2` is read from the very stream the payload is read
    from -- while a buffer is one whole object, so what follows in it is
    malleability.
    """
    stream = BytesIO(_ADDRV2_PAYLOAD + b"\xff")
    assert AddrV2.parse(stream) == _ADDRV2
    assert stream.read() == b"\xff"

    with pytest.raises(BTClibValueError, match="bytes after the addrv2 payload"):
        AddrV2.parse(_ADDRV2_PAYLOAD + b"\xff")
    with pytest.raises(BTClibValueError, match="bytes after the addrv2 entry"):
        NetworkAddressV2.parse(_entry("010401020304") + b"\xff")
    with pytest.raises(BTClibValueError, match="bytes after the sendaddrv2 payload"):
        SendAddrV2.parse(b"\x00")


def test_a_truncated_entry_is_refused_field_by_field() -> None:
    """Every prefix of an encoding, which is what `read_exactly` is for.

    A short read answers with what is left rather than raising, so each
    field boundary is a check of its own: the timestamp, the network id,
    the address and the port each name themselves in the refusal.
    """
    octets = _entry("010401020304")
    for i in range(len(octets)):
        with pytest.raises((BTClibValueError, BTClibTypeError)):
            NetworkAddressV2.parse(octets[:i])


def test_sendaddrv2_is_the_whole_of_that_command() -> None:
    """No fields, an empty payload, and the command is all there is.

    Core's `msg_sendaddrv2` serializes to nothing and deserializes
    nothing, and BIP155 gives the message no body at all: sending one is
    the statement.
    """
    assert SendAddrV2().serialize() == b""
    assert SendAddrV2().serialize(check_validity=False) == b""
    assert SendAddrV2.parse(b"") == SendAddrV2()
    assert SendAddrV2.parse(b"", check_validity=False) == SendAddrV2()
    assert SendAddrV2.command == "sendaddrv2"

    # the envelope's `payload=b""` default is what carries it
    message = SendAddrV2().to_message(_MAINNET)
    assert message.command == "sendaddrv2"
    assert message.payload == b""
    assert Message.parse(message.serialize()) == message


def test_sendaddrv2_leaves_a_callers_stream_where_it_was() -> None:
    """It consumes nothing, so a stream after one is a stream untouched."""
    stream = BytesIO(b"\x01\x02")
    assert SendAddrV2.parse(stream) == SendAddrV2()
    assert stream.read() == b"\x01\x02"


def test_the_payloads_travel_under_the_commands_bip155_names() -> None:
    """The round trip through an envelope, which is what a payload adds."""
    for payload in (_ADDRV2, SendAddrV2()):
        octets = payload.to_message(_MAINNET).serialize()
        message = Message.parse(octets)

        assert message.command == type(payload).command
        assert message.payload == payload.serialize()
        assert message.serialize() == octets

    assert AddrV2.command == "addrv2"
    assert AddrV2.parse(_ADDRV2.to_message(_MAINNET).payload) == _ADDRV2
