# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Where a peer is, what it offers, and the `addr` message that gossips it.

Bitcoin Core's `CAddress`, of src/protocol.h, in the version-1 encoding
its `SERIALIZE_METHODS` writes with `Encoding::V1`: eight octets of
service flags, then the sixteen of address and two of port that
`CService` writes under it. BIP155's `addrv2` is a different
encoding of the same idea and is `btclib.p2p.addrv2`, not this module.

**Two classes for what Core's prose calls one structure**, because the
octets are not the same: a `version` message's two addresses carry no
timestamp and an `addr` message's carry four octets of one in front. Core
writes that as a serialization parameter -- `CAddress::SerParams` with
`Format::Disk`, `Format::Network` -- and its test framework as
`CAddress.deserialize(f, with_time=True)`. A parameter is what btclib_node
has too, and it is where that implementation loses a round trip: a
`NetworkAddress` parsed with `version_msg=True` is *forced* to `time=0`
rather than left without one, so the field says zero where it means
absent, and an `addr` entry cannot be told from a `version` one by looking
at it. Here `Version.addr_recv` is annotated `NetworkAddress` and
`Addr.addresses` holds `TimestampedNetworkAddress`, so putting one where
the other belongs is a call mypy refuses rather than octets a peer
refuses.

**The port is big-endian and it is the only field of this protocol that
is.** Core writes it through `Using<BigEndianFormatter<2>>(obj.port)`,
in `CService`'s `SERIALIZE_METHODS` of src/netaddress.h, network byte
order being what a port has been since sockets: everything
else in a p2p message, this structure's service flags and timestamp
included, is little-endian. A self-consistent round trip cannot see this
being wrong, which is why the test module for this one is driven by a
captured `addr` message whose port reads 8333 one way and 36128 the
other.

**The address is sixteen octets, always, with IPv4 mapped into them.**
`::ffff:a.b.c.d` -- ten NUL octets, two 0xff, then the four of the v4
address -- is what a v4 peer is on the wire, and the sixteen octets are
what is held here rather than a narrower form plus a tag for which it is.
That is the second thing btclib_node departs from and the second round
trip it loses: it stores four octets for a v4 address and sixteen for a
v6 one, so an IPv6 address that happens to begin with the mapping prefix
parses back as the IPv4 address it is not, and its own test works around
the collision with an unexplained `49`. `ipaddress.IPv6Address` is
`.packed` in one direction and the constructor in the other, exactly and
for every value, and `.ipv4_mapped` is what answers the question the tag
was for.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntFlag
from ipaddress import IPv4Address, IPv6Address, ip_address

from btclib import var_int
from btclib.alias import BinaryData
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.limits import MAX_ADDR_TO_SEND
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "Addr",
    "IPAddress",
    "NetworkAddress",
    "ServiceFlags",
    "TimestampedNetworkAddress",
]

# CAddress's version-1 fields, in the order it serializes them
_SERVICES_SIZE = 8
_IP_SIZE = 16
_PORT_SIZE = 2
_TIMESTAMP_SIZE = 4

_MAX_SERVICES = (1 << (8 * _SERVICES_SIZE)) - 1
_MAX_PORT = (1 << (8 * _PORT_SIZE)) - 1
_MAX_TIMESTAMP = (1 << (8 * _TIMESTAMP_SIZE)) - 1

# what a caller may hand where an address is wanted: the two objects
# `ipaddress` builds, the text either of them prints, and the sixteen
# octets of the wire. Not `Octets`, which would read "10.0.0.1" as a hex
# string and refuse it: this field is an address, so its text form is an
# address and not hex
IPAddress = IPv4Address | IPv6Address | str | bytes


class ServiceFlags(IntFlag):
    """The services a node advertises, Bitcoin Core's `ServiceFlags`.

    src/protocol.h, spelled as Core spells it, and a bit set rather than
    a table: the eight octets are a bitfield, an unknown bit is a service
    this library has not heard of rather than an error, and Core says so
    where it reserves bits 24-31 "for temporary experiments" and sends
    everything else through the BIP process.

    An `IntFlag` is what round-trips such a bit: a value with bits no
    member names keeps them and compares equal to the integer it was
    built from, so `ServiceFlags(1 << 40)` serializes back to the octets
    it was parsed from. The members are what a caller reads the named
    bits with -- `ServiceFlags.NODE_WITNESS in flags` -- and neither
    `parse` nor `assert_valid` consults them.

    Bit 1 is absent because Core removed it: it was BIP64's
    `NODE_GETUTXO`, and a `version` still carrying it is exactly the
    unnamed bit above. `serviceFlagsToStr` is Core's own answer to the
    same question, and it answers "UNKNOWN[...]" rather than refusing.
    """

    NODE_NONE = 0
    NODE_NETWORK = 1 << 0
    NODE_BLOOM = 1 << 2
    NODE_WITNESS = 1 << 3
    NODE_COMPACT_FILTERS = 1 << 6
    NODE_NETWORK_LIMITED = 1 << 10
    NODE_P2P_V2 = 1 << 11


def _ipv6_from_ip_address(ip: IPAddress) -> IPv6Address:
    """Return the sixteen-octet address, mapping an IPv4 one into them.

    What the wire carries, from any of the spellings a caller holds one
    in: an `IPv4Address` or `IPv6Address`, the text either prints, or the
    sixteen octets themselves. An IPv4 address in any of those forms
    comes back as `::ffff:a.b.c.d`, which is what Core's
    `CNetAddr::SerializeV1Array` writes for one.

    Text is read as an address and never as hex, which is where this
    departs from every other `bytes | str` field of this library:
    `bytes_from_octets` would take "10.0.0.1" for a hex string and refuse
    it, and would take a sixteen-character dotted quad -- there is none --
    for octets. Sixteen octets are the one bytes-shaped input, being what
    `IPv6Address` accepts and what the wire holds.
    """
    if isinstance(ip, IPv6Address):
        return ip
    if isinstance(ip, IPv4Address):
        return IPv6Address(f"::ffff:{ip}")
    if isinstance(ip, (bytes, bytearray, memoryview)):
        octets = bytes(ip)
        if len(octets) != _IP_SIZE:
            err_msg = f"invalid ip: {len(octets)}"
            err_msg += f" instead of {_IP_SIZE} bytes"
            raise BTClibValueError(err_msg)
        return IPv6Address(octets)
    if not isinstance(ip, str):
        err_msg = f"invalid ip type: {type(ip).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)

    # `ip_address` and not `IPv6Address`: the latter refuses "10.0.0.1"
    # outright, where the whole point of the mapping is that a v4 address
    # is a value this structure carries
    try:
        parsed = ip_address(ip.strip())
    except ValueError as e:
        raise BTClibValueError(f"invalid ip: {e}") from e
    return _ipv6_from_ip_address(parsed)


def _service_flags_from_int(services: int) -> ServiceFlags | int:
    """Return the flags of a bitfield, leaving what is no bitfield alone.

    `ServiceFlags(services)` refuses a negative value with a bare
    `ValueError` -- `enum`'s, naming the class -- and refuses nothing
    else, an unnamed bit being a service this library does not know. So
    what cannot be a bitfield at all is handed back as it came, for the
    `assert_valid` one line later to refuse through this library's own
    exception classes.

    Private, and imported by `handshake` all the same: two modules coerce
    the one field -- an address carries the flags and the `version`
    message quotes them -- and a converter shared inside a package is what
    `magic.py` reaching `network._validated_network_name` already is.
    """
    if is_integer(services) and 0 <= services <= _MAX_SERVICES:
        return ServiceFlags(services)
    return services


def _assert_valid_body(services: int, port: int) -> None:
    """Refuse a service bitfield or a port no eight or two octets hold.

    The address is not asked about: an `IPv6Address` is sixteen octets by
    construction, so there is no invalid one to refuse -- the refusal is
    the converter's, one call earlier, where a value that is no address
    at all is still reachable.
    """
    # a bool is an int and would read as the flag NODE_NETWORK or as
    # NODE_NONE, which the range check below cannot tell from a bitfield
    if not is_integer(services):
        err_msg = f"invalid services type: {type(services).__name__}"
        raise BTClibTypeError(err_msg)
    if not 0 <= services <= _MAX_SERVICES:
        raise BTClibValueError(f"invalid services: {services}")

    if not is_integer(port):
        err_msg = f"invalid port type: {type(port).__name__}"
        raise BTClibTypeError(err_msg)
    if not 0 <= port <= _MAX_PORT:
        raise BTClibValueError(f"invalid port: {port}")


@dataclass(frozen=True)
class NetworkAddress:
    """Where a peer is and what it offers: (services, ip, port).

    Bitcoin Core's `CService` with the service flags in front of it, in
    the twenty-six octets a `CAddress` writes under `Encoding::V1` with
    no timestamp in front -- which is what a `version` message's
    `addr_recv` and
    `addr_from` are. `TimestampedNetworkAddress` is the thirty-octet form
    an `addr` message carries, and the module docstring is why they are
    two classes.

    `ip` is an `ipaddress.IPv6Address` and is always sixteen octets, an
    IPv4 peer being `::ffff:a.b.c.d`: `ip.ipv4_mapped` is the v4 address
    where there is one and `None` where there is not, which is the
    question a caller would otherwise keep a tag for. The constructor
    takes any of the spellings `IPAddress` names, so "10.0.0.1" and
    "::ffff:10.0.0.1" build the one object -- as they must, being the one
    peer.

    `services` is a `ServiceFlags`, which is an `int` carrying the bits
    it cannot name; `port` is the one big-endian field in this protocol.

    Frozen and hashable, all three fields being immutable: an address is
    a value, it is what an address database keys on, and
    `dataclasses.replace` is what moves one to another port.

    No `to_dict` and no `from_dict`, for the reason `Message` has none:
    those agree with a json shape somebody else writes, and the shape
    Core's rpc renders a peer as -- `getpeerinfo`'s "addr" -- is a
    formatted string and this structure's fields spread across a dozen
    other keys, so the pair would be inventing one rather than reading
    one.
    """

    services: ServiceFlags
    ip: IPv6Address
    port: int

    def __init__(
        self,
        services: int = ServiceFlags.NODE_NONE,
        ip: IPAddress = "::",
        port: int = 0,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "services", _service_flags_from_int(services))
        object.__setattr__(self, "ip", _ipv6_from_ip_address(ip))
        object.__setattr__(self, "port", port)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a services or a port no eight or two octets hold."""
        _assert_valid_body(self.services, self.port)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the twenty-six octets, the port last and big-endian."""
        if check_validity:
            self.assert_valid()

        out = int(self.services).to_bytes(
            _SERVICES_SIZE, byteorder="little", signed=False
        )
        out += self.ip.packed
        # the one big-endian field of this protocol: Core's
        # BigEndianFormatter<2>, network byte order as every port is
        out += self.port.to_bytes(_PORT_SIZE, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[NetworkAddress], data: BinaryData, *, check_validity: bool = True
    ) -> NetworkAddress:
        """Return the address the twenty-six octets describe."""
        stream = bytesio_from_binarydata(data)

        services = int.from_bytes(
            read_exactly(stream, _SERVICES_SIZE, "address services"),
            byteorder="little",
            signed=False,
        )
        ip = read_exactly(stream, _IP_SIZE, "address ip")
        port = int.from_bytes(
            read_exactly(stream, _PORT_SIZE, "address port"),
            byteorder="big",
            signed=False,
        )
        assert_no_trailing(data, stream, "network address")

        return cls(services, ip, port, check_validity=check_validity)


@dataclass(frozen=True)
class TimestampedNetworkAddress:
    """One entry of an `addr` message: when a peer was last seen, and where.

    The thirty octets Bitcoin Core writes for a `CAddress` on the network
    -- four of `nTime`, then the twenty-six a `NetworkAddress` is. The
    timestamp is unsigned and four octets wide where a `version`
    message's is signed and eight, which is the second reason these are
    two structures rather than one with a flag: the same name in Core's
    prose is not the same field.

    Composed rather than inherited, so that a `Version` cannot be handed
    one: a subclass of `NetworkAddress` would satisfy that annotation and
    serialize four octets nobody asked for, which is the trap this
    module's docstring names in the implementation that has it.
    """

    timestamp: int
    address: NetworkAddress

    def __init__(
        self,
        timestamp: int = 0,
        address: NetworkAddress | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(
            self,
            "address",
            NetworkAddress(check_validity=check_validity)
            if address is None
            else address,
        )

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a timestamp no four octets hold, and ask the address."""
        if not is_integer(self.timestamp):
            err_msg = f"invalid timestamp type: {type(self.timestamp).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.timestamp <= _MAX_TIMESTAMP:
            raise BTClibValueError(f"invalid timestamp: {self.timestamp}")

        # the annotation says this cannot happen and `check_validity=False`
        # is why it can, as it is everywhere this library asks a built
        # object what type its fields are
        if not isinstance(self.address, NetworkAddress):
            err_msg = f"invalid address type: {type(self.address).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)
        self.address.assert_valid()

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the thirty octets: the timestamp, then the address."""
        if check_validity:
            self.assert_valid()

        out = self.timestamp.to_bytes(_TIMESTAMP_SIZE, byteorder="little", signed=False)
        out += self.address.serialize(check_validity=check_validity)
        return out

    @classmethod
    def parse(
        cls: type[TimestampedNetworkAddress],
        data: BinaryData,
        *,
        check_validity: bool = True,
    ) -> TimestampedNetworkAddress:
        """Return the entry the thirty octets describe."""
        stream = bytesio_from_binarydata(data)

        timestamp = int.from_bytes(
            read_exactly(stream, _TIMESTAMP_SIZE, "address timestamp"),
            byteorder="little",
            signed=False,
        )
        address = NetworkAddress.parse(stream, check_validity=check_validity)
        assert_no_trailing(data, stream, "timestamped network address")

        return cls(timestamp, address, check_validity=check_validity)


@dataclass(frozen=True)
class Addr(Payload):
    """The `addr` message: peers this node knows of, with when it saw them.

    A count and that many `TimestampedNetworkAddress`, which is what
    Core's `msg_addr` writes and what its `ProcessMessage` reads back.

    **The count is bounded before anything is built**, at Core's
    `MAX_ADDR_TO_SEND`: `vAddr.size() > MAX_ADDR_TO_SEND` is a
    `Misbehaving` there, so a message above it is one no peer accepts.
    The bound is checked in `parse` off the count and before the loop,
    where it is the whole point of having one -- the count is the peer's
    to choose, and btclib's own `var_int.parse` allows 33,554,432 of
    them, which is the number of thirty-octet objects an implementation
    without this check builds out of nine octets. That check does not
    answer to `check_validity`, on `Message.parse`'s reasoning: a defence
    a caller can turn off is not one.

    A tuple and not a list, so that a frozen `Addr` is what its fields
    say it is: `dataclasses.replace` is what changes the addresses in
    one, as it is for every other frozen class here.
    """

    command = "addr"

    addresses: tuple[TimestampedNetworkAddress, ...]

    def __init__(
        self,
        addresses: Sequence[TimestampedNetworkAddress] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        # a str and a bytes are Sequences, and each of their elements is
        # what a `TimestampedNetworkAddress` is not: asked whole here, so
        # that a caller who passed one gets a complaint about the
        # argument rather than about its first character
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
            if not isinstance(address, TimestampedNetworkAddress):
                err_msg = f"invalid address type: {type(address).__name__}"  # type: ignore[unreachable]
                raise BTClibTypeError(err_msg)
            address.assert_valid()

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the count, then that many timestamped addresses."""
        if check_validity:
            self.assert_valid()

        out = var_int.serialize(len(self.addresses))
        for address in self.addresses:
            out += address.serialize(check_validity=check_validity)
        return out

    @classmethod
    def parse(
        cls: type[Addr], data: BinaryData, *, check_validity: bool = True
    ) -> Addr:
        """Return the addresses the payload carries, the count bounded first."""
        stream = bytesio_from_binarydata(data)

        count = var_int.parse(stream)
        if count > MAX_ADDR_TO_SEND:
            err_msg = f"invalid addresses count: {count}"
            err_msg += f" instead of at most {MAX_ADDR_TO_SEND}"
            raise BTClibValueError(err_msg)

        addresses = [
            TimestampedNetworkAddress.parse(stream, check_validity=check_validity)
            for _ in range(count)
        ]
        assert_no_trailing(data, stream, "addr payload")

        return cls(addresses, check_validity=check_validity)
