# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP155's `addrv2`, the `sendaddrv2` that asks for it, and the id table.

The message that gossips an address of any network, and the one a peer
sends to say it understands the first. BIP155 is the specification and
is unusually precise; Core's `CAddress` under `V2_NETWORK` -- src/
protocol.h and src/netaddress.h -- is the implementation, and where the
two read differently this module says so and follows the BIP.

An entry is `addr`'s idea in a different encoding, not a variant of it:
four octets of timestamp, then the service flags as a `CompactSize`, a
one-octet network id, the address as `var_bytes`, and the big-endian
port. Nothing about it is an `addr` entry's octets, and the address field
is not an IP address at all -- a `TORV3` one is an ed25519 public key.

**A class of its own, and one rather than two.** `NetworkAddress` holds
an `ipaddress.IPv6Address`, which is what half of these addresses are
not, so reuse is refused by the field before it is refused by anything
else: giving that field a union type would put "which of these is it" on
every existing caller of `.ip`, which is the cost issue #1098 declined
when it made `TimestampedNetworkAddress` a second class rather than a
flag on the first. A caller therefore has three types where the protocol
has three encodings -- a `version`'s address, an `addr`'s, and this one --
and the type is what says which message an address came off.

One and not two because BIP155 defines one record: `time` is in its
table unconditionally, no message carries the untimestamped form, and
the split that gave `addr` two classes has nothing here to divide.
`NetworkAddressV2` is therefore the counterpart of
`TimestampedNetworkAddress` rather than of `NetworkAddress`, and "V2" is
Core's word for the encoding -- `CAddress::V2_NETWORK`,
`SerializeV2Stream` -- rather than a second version of the class above
it.

**An unknown network id round-trips.** It is the property the format
exists for: a new network is meant to need no new message, so a parser
that refused an id it had not heard of could not read the message the
next BIP makes ordinary. `_bip155_network_from_int` hands back the plain
`int` where no member names the id, which is what `InventoryType` does
for a type code and the envelope does for a command. Core drops such an
address instead -- `SetNetFromBIP155Network` returns false and
`UnserializeV2Stream` consumes the octets into a default `CNetAddr` --
and it is right to, being a node: BIP155 says clients SHOULD NOT gossip
addresses of networks they cannot validate. That is a rule about what to
relay, and this package relays nothing; keeping the octets is what lets
the caller apply it.

**A known id whose address is the wrong length is refused, and the
message with it.** BIP155: "Clients SHOULD reject messages that contain
addresses that have a different length than specified in this table for a
specific network ID, as these are meaningless." Core implements exactly
that, `SetNetFromBIP155Network` throwing `std::ios_base::failure` on each
of the five it knows, which fails the whole message rather than the
entry. So does `assert_valid` here, and refusing is what a codec can
mean by it: dropping the entry would leave a message that serializes back
one address shorter than it arrived, and there is no value of a field
that means "this one was ignored".

What BIP155 does say to *ignore* is a different thing, and neither half
of it is refused here: a `TORV2` address, and an `IPV6` address inside a
range reserved for embedding another network -- `::ffff:0:0/96` and
OnionCat's `fd87:d87e:eb43::/48`. Both are receive policy, about whether
an address is worth keeping rather than whether the octets decode, and
Core carries them out by parsing the entry and marking the result
invalid. A parser that refused them would refuse a message Core accepts.

**`TORV2` and `YGGDRASIL` are in the table, where Core acts on
neither.** BIP155 reserves both, and says "Further network ID numbers
MUST be reserved in a new BIP document", so 3 and 7 mean what they mean
for good. Core names `TORV2` in its own `BIP155Network` and nowhere else
-- `SetNetFromBIP155Network` has no case for it, so an address under it
falls through to the unknown-id path and is dropped, and the test
framework's `ADDRV2_NET_NAME` has no entry for it. `YGGDRASIL` Core has
not got at all, Yggdrasil being carried there as ordinary IPv6, so an id
7 from a real Yggdrasil peer is an unknown network to a Core node today.

Naming them is not offering them: an id round-trips whether or not a
member names it, so what the member changes is only whether a caller
reading a captured message sees `BIP155Network.TORV2` or `3` -- and a
table with a hole in it is one somebody eventually reuses. The rule the
tree already follows is `InventoryType`'s: name what the specification
names, and not what it merely reserves for the future.

**The port is big-endian**, as it is in `addr`, and the evidence is not a
round trip: `tests/p2p/addrv2_test.py` is driven by the `addrv2` payload
of Core's own `netbase_tests.cpp`, whose last entry reads port `f1f2` --
61938 one way and 62193 the other.

**The service flags are a `CompactSize` with no range check on it**,
which is the one place btclib's `var_int` default is wrong for this
format. `var_int.parse` caps at Core's `MAX_SIZE`, 33,554,432, because
every var_int btclib otherwise reads is a length or a count; these octets
are a 64-bit bitfield, and Core reads them through
`Using<CompactSizeFormatter<false>>`, the `false` being `RangeCheck`. Bit
25 is 33,554,432 exactly -- inside Core's "reserved for temporary
experiments" range, bits 24 to 31 -- so the default cap starts refusing
peers one bit above it.

**The address itself is opaque octets, and no rendering is offered.**
That is what BIP155 bought: the field's meaning is the network id's, so a
type that decoded it would have to hold every network's format and would
be wrong about the next one. `IPv4Address(entry.address)` is a caller's
one line for the two ids where it applies; a `.onion` name is SHA3-256
and a checksum over the same octets, and a `.b32.i2p` name is base32 of
them, neither of which is a codec's work.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.address import ServiceFlags, _service_flags_from_int
from btclib.p2p.limits import MAX_ADDR_TO_SEND, MAX_ADDRV2_SIZE
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "AddrV2",
    "BIP155Network",
    "NetworkAddressV2",
    "SendAddrV2",
]

# the fixed-width fields of a BIP155 entry: the services and the address
# are a CompactSize and a var_bytes, so neither has one
_TIMESTAMP_SIZE = 4
_NETWORK_ID_SIZE = 1
_PORT_SIZE = 2

_MAX_TIMESTAMP = (1 << (8 * _TIMESTAMP_SIZE)) - 1
_MAX_NETWORK_ID = (1 << (8 * _NETWORK_ID_SIZE)) - 1
_MAX_PORT = (1 << (8 * _PORT_SIZE)) - 1

# the width of the bitfield the CompactSize carries, which is the cap
# `var_int.parse` is given in place of its own: BIP155 calls `services`
# "a bit field that is 64 bits wide", and Core turns the range check off
# for it rather than raising it
_MAX_SERVICES = (1 << 64) - 1


class BIP155Network(IntEnum):
    """The network an `addrv2` address belongs to, BIP155's id table.

    Every id of that table, spelled as its "Enumeration" column spells
    them. Core's own name for the enum, of src/netaddress.h, taken
    rather than a `NetworkId`: "network" in btclib already means the
    chain -- `btclib.network.Network`, and `btclib.p2p.magic_from_network`
    beside it -- and these are IPv4, Tor and I2P.

    `TORV2` and `YGGDRASIL` are members where Core acts on neither, and
    the module docstring is why. An id no member names is not an error
    either, which is `_bip155_network_from_int`.

    An `IntEnum` and not an `IntFlag`, for the reason `InventoryType` is
    one: these are exclusive kinds and not bits, so composing two of them
    would answer for a network that does not exist.
    """

    IPV4 = 1
    IPV6 = 2
    TORV2 = 3
    TORV3 = 4
    I2P = 5
    CJDNS = 6
    YGGDRASIL = 7


# what BIP155's "Address length (bytes)" column fixes for each id. A
# private table and not a property of the enum: it is the length of the
# `addr` field rather than anything about the network, and it is what
# `assert_valid` refuses a mismatch against.
#
# Keyed `int` rather than `BIP155Network`, the members being their own
# values: what is looked up here is a `network_id`, which is the plain
# integer wherever no member names it
_ADDRESS_SIZE: dict[int, int] = {
    BIP155Network.IPV4: 4,
    BIP155Network.IPV6: 16,
    BIP155Network.TORV2: 10,
    BIP155Network.TORV3: 32,
    BIP155Network.I2P: 32,
    BIP155Network.CJDNS: 16,
    BIP155Network.YGGDRASIL: 16,
}


def _assert_int_range(value: int, high: int, what: str) -> None:
    """Refuse a value that is no integer, or one outside a field's width.

    No low end, where `handshake._assert_int_range` takes one: every
    integer field of a BIP155 entry is unsigned, and a `version`
    message's protocol version and timestamp are not.

    Private and unvalidated of its own arguments, as a private twin is:
    the width and the name are literals of this module at every call.
    That twin is written there rather than shared because a validity
    check is one line per field, and sharing it would put a name in
    `btclib.utils` that no caller outside these two modules has.
    """
    # a bool is an int and would read as the number one or zero, which
    # the range check cannot tell from a field whose value that is
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if not 0 <= value <= high:
        raise BTClibValueError(f"invalid {what}: {value}")


def _bip155_network_from_int(network_id: int) -> BIP155Network | int:
    """Return the member an id names, leaving an unnamed id alone.

    `IntEnum` refuses a value no member has, and an id no member has is
    the whole point of this format: the answer is
    `inventory._inventory_type_from_int`'s, which is to hand the value
    back for `assert_valid` one line later to refuse through this
    library's own exception classes if one octet cannot hold it.

    A bool is handed back rather than converted, `BIP155Network(True)`
    being `IPV4`: `is_integer` is the predicate every integer field of
    this library is held to, and a `network_id=True` that arrived as
    `IPV4` would pass the refusal `assert_valid` exists to make.
    """
    if not is_integer(network_id):
        return network_id
    try:
        return BIP155Network(network_id)
    except ValueError:
        return network_id


@dataclass(frozen=True)
class NetworkAddressV2:
    """One entry of an `addrv2`: a peer, and the network it is on.

    Bitcoin Core's `CAddress` written with `CAddress::V2_NETWORK`, which
    is BIP155's table of five fields in its order: `timestamp` in four
    octets little-endian, `services` as a `CompactSize`, `network_id` in
    one octet, `address` as `var_bytes`, and `port` in two octets
    big-endian.

    `address` is the octets and nothing more -- the network id says how
    to read them, and the module docstring is why nothing here does.
    `network_id` is a `BIP155Network` where a member names the id and the
    plain `int` where none does, which is how an address of a network this
    library has not heard of comes back as it arrived. `services` is a
    `ServiceFlags`, which is an `int` carrying the bits it cannot name.

    A `port` of zero is what BIP155 requires where a port means nothing
    for the network, and is a value like any other here.

    Frozen and hashable, every field being immutable: an address is a
    value, it is what an address database keys on, and
    `dataclasses.replace` is what moves one to another port.
    """

    timestamp: int
    services: ServiceFlags
    network_id: BIP155Network | int
    address: bytes
    port: int

    def __init__(
        self,
        timestamp: int = 0,
        services: int = ServiceFlags.NODE_NONE,
        network_id: int = BIP155Network.IPV4,
        address: Octets = b"\x00\x00\x00\x00",
        port: int = 0,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "services", _service_flags_from_int(services))
        object.__setattr__(self, "network_id", _bip155_network_from_int(network_id))
        object.__setattr__(self, "address", bytes_from_octets(address))
        object.__setattr__(self, "port", port)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a field no width holds, and an address of the wrong length.

        The length is BIP155's table read against `network_id`: an id a
        member names fixes it, and a mismatch is what the BIP calls
        meaningless and what Core's `SetNetFromBIP155Network` throws on.
        An id no member names fixes nothing, so `MAX_ADDRV2_SIZE` is the
        whole of what such an address is held to.
        """
        _assert_int_range(self.timestamp, _MAX_TIMESTAMP, "timestamp")
        _assert_int_range(self.services, _MAX_SERVICES, "services")
        _assert_int_range(self.network_id, _MAX_NETWORK_ID, "network_id")
        _assert_int_range(self.port, _MAX_PORT, "port")

        if len(self.address) > MAX_ADDRV2_SIZE:
            err_msg = f"invalid address length: {len(self.address)} bytes"
            err_msg += f" instead of at most {MAX_ADDRV2_SIZE}"
            raise BTClibValueError(err_msg)

        size = _ADDRESS_SIZE.get(self.network_id)
        if size is not None and len(self.address) != size:
            err_msg = f"invalid address length: {len(self.address)} bytes"
            err_msg += f" instead of {size} for network id {int(self.network_id)}"
            raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the entry's octets, the port last and big-endian."""
        if check_validity:
            self.assert_valid()

        out = self.timestamp.to_bytes(_TIMESTAMP_SIZE, byteorder="little", signed=False)
        out += var_int.serialize(int(self.services))
        out += int(self.network_id).to_bytes(
            _NETWORK_ID_SIZE, byteorder="little", signed=False
        )
        out += var_bytes.serialize(self.address)
        # the one big-endian field of this protocol, as it is in `addr`:
        # network byte order, as every port is
        out += self.port.to_bytes(_PORT_SIZE, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[NetworkAddressV2], data: BinaryData, *, check_validity: bool = True
    ) -> NetworkAddressV2:
        """Return the entry the octets describe, the address bounded first.

        `MAX_ADDRV2_SIZE` is checked off the length field and before the
        read it would size, which is where a bound is worth having: the
        length is the peer's to choose. It does not answer to
        `check_validity`, on `Message.parse`'s reasoning -- a defence a
        caller can turn off is not one -- where the table check in
        `assert_valid` does, being a statement about the address rather
        than about what reading it costs.
        """
        stream = bytesio_from_binarydata(data)

        timestamp = int.from_bytes(
            read_exactly(stream, _TIMESTAMP_SIZE, "address timestamp"),
            byteorder="little",
            signed=False,
        )
        # the cap is the bitfield's width and not `var_int`'s default:
        # these octets are not a length or a count, and Core turns its
        # own range check off for them
        services = var_int.parse(stream, _MAX_SERVICES)
        network_id = int.from_bytes(
            read_exactly(stream, _NETWORK_ID_SIZE, "address network id"),
            byteorder="little",
            signed=False,
        )
        # read by hand where `serialize` above uses `var_bytes`:
        # `var_bytes.parse` reads the length and the octets in one call,
        # and the bound has to stand between the two
        size = var_int.parse(stream)
        if size > MAX_ADDRV2_SIZE:
            err_msg = f"invalid address length: {size} bytes"
            err_msg += f" instead of at most {MAX_ADDRV2_SIZE}"
            raise BTClibValueError(err_msg)
        address = read_exactly(stream, size, "address")
        port = int.from_bytes(
            read_exactly(stream, _PORT_SIZE, "address port"),
            byteorder="big",
            signed=False,
        )
        assert_no_trailing(data, stream, "addrv2 entry")

        return cls(
            timestamp,
            services,
            network_id,
            address,
            port,
            check_validity=check_validity,
        )


@dataclass(frozen=True)
class AddrV2(Payload):
    """The `addrv2` message: peers of any network, with when they were seen.

    A count and that many `NetworkAddressV2`, which is Core's
    `msg_addrv2` and what `ProcessMessage` reads through the same branch
    it reads an `addr` with, `CAddress::V2_NETWORK` in place of
    `V1_NETWORK` being the whole of the difference there.

    No base shared with `Addr`, where `Inv` and `GetData` have one: those
    two are one body under two commands, and these two are two bodies --
    a `TimestampedNetworkAddress` and a `NetworkAddressV2` are different
    octets, so what a base could hold is the word "count".

    **The count is bounded before anything is built**, at
    `MAX_ADDR_TO_SEND`, which is BIP155's thousand and Core's constant
    for both commands. As in `Addr.parse` the check is off the count and
    before the loop, and it does not answer to `check_validity`.

    A tuple and not a list, so that a frozen `AddrV2` is what its field
    says it is; `dataclasses.replace` is what changes the addresses in one.
    """

    command = "addrv2"

    addresses: tuple[NetworkAddressV2, ...]

    def __init__(
        self,
        addresses: Sequence[NetworkAddressV2] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        # a str and a bytes are Sequences, and each of their elements is
        # what a `NetworkAddressV2` is not: asked whole here, so that a
        # caller who passed one gets a complaint about the argument
        # rather than about its first character
        if isinstance(addresses, (str, bytes, bytearray, memoryview)) or not isinstance(
            addresses, Sequence
        ):
            err_msg = f"invalid addresses type: {type(addresses).__name__}"
            raise BTClibTypeError(err_msg)
        object.__setattr__(self, "addresses", tuple(addresses))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse more addresses than a peer accepts, and ask each of them."""
        if len(self.addresses) > MAX_ADDR_TO_SEND:
            err_msg = f"invalid addresses count: {len(self.addresses)}"
            err_msg += f" instead of at most {MAX_ADDR_TO_SEND}"
            raise BTClibValueError(err_msg)

        for address in self.addresses:
            if not isinstance(address, NetworkAddressV2):
                err_msg = f"invalid address type: {type(address).__name__}"  # type: ignore[unreachable]
                raise BTClibTypeError(err_msg)
            address.assert_valid()

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the count, then that many BIP155 entries."""
        if check_validity:
            self.assert_valid()

        out = var_int.serialize(len(self.addresses))
        for address in self.addresses:
            out += address.serialize(check_validity=check_validity)
        return out

    @classmethod
    def parse(
        cls: type[AddrV2], data: BinaryData, *, check_validity: bool = True
    ) -> AddrV2:
        """Return the addresses the payload carries, the count bounded first."""
        stream = bytesio_from_binarydata(data)

        count = var_int.parse(stream)
        if count > MAX_ADDR_TO_SEND:
            err_msg = f"invalid addresses count: {count}"
            err_msg += f" instead of at most {MAX_ADDR_TO_SEND}"
            raise BTClibValueError(err_msg)

        addresses = [
            NetworkAddressV2.parse(stream, check_validity=check_validity)
            for _ in range(count)
        ]
        assert_no_trailing(data, stream, "addrv2 payload")

        return cls(addresses, check_validity=check_validity)


@dataclass(frozen=True)
class SendAddrV2(Payload):
    """The `sendaddrv2` message: no fields, and an empty payload.

    Core's `msg_sendaddrv2`, and the whole of that command: a peer that
    sends one is saying it understands `addrv2` and would rather have it
    than `addr`.

    BIP155 puts it in the handshake -- it "MUST only be sent in response
    to the `version` message from a peer and prior to sending the
    `verack` message", and Core disconnects a peer that sends one after
    the `verack`. That is a rule about *when*, which needs a connection to
    hold; this package has none, so the rule is documented here and
    nothing enforces it. The message lives beside `addrv2` rather than in
    `btclib.p2p.handshake` because it is about nothing else.

    `parse` refuses an octet, as `Verack.parse` does and for that class's
    reason: this library refuses what follows an object everywhere else,
    and a `sendaddrv2` with a payload is a message that serializes back
    without it. The two classes repeat three lines rather than share a
    base -- `keepalive._NoncePayload` is a base because two commands have
    one *body*, and the absence of a body is not one to share.
    """

    command = "sendaddrv2"

    def __init__(self, *, check_validity: bool = True) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Accept: a message with no fields has none to refuse."""

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the empty payload a `sendaddrv2` is."""
        if check_validity:
            self.assert_valid()

        return b""

    @classmethod
    def parse(
        cls: type[SendAddrV2], data: BinaryData, *, check_validity: bool = True
    ) -> SendAddrV2:
        """Return a `SendAddrV2`, refusing any octet at all.

        Octets are refused by `assert_no_trailing`, which is where the
        rule already is; a caller's stream is left exactly where it was,
        a `sendaddrv2` consuming nothing from one.
        """
        stream = bytesio_from_binarydata(data)
        assert_no_trailing(data, stream, "sendaddrv2 payload")

        return cls(check_validity=check_validity)
