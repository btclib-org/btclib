# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The two messages a connection opens with: `version` and `verack`.

Bitcoin Core's `msg_version` and `msg_verack`, of
test/functional/test_framework/messages.py, read against what
`net_processing.cpp` actually does with the octets -- which is not the
same thing, and the difference is this module's one hard decision.

**`version`'s trailing fields are conditional, and the conditional is not
the protocol version.** Core's test framework reads the relay flag `if
self.nVersion >= 70001`, which is BIP37's rule as BIP37 states it. Core
itself reads it `if (!vRecv.empty())`, and the same for the user agent
and the start height above it. The two disagree about a peer that
announces 70016 and stops after the start height, and Core is the one
that decides whether such a peer is accepted: it is.

So the flag's presence is a *field* here -- `relay` is `None` where the
octets ended before it -- and the protocol version is not consulted. The
alternative that reads the version number makes the encoding a function
of another field, so that a `Version(version=60002, relay=True)` is an
object with no serialization and a real 70016 peer that omitted the flag
is a message with no object; the alternative that ignores what is left
over breaks this library's rule that octets are one whole object, and
would read two distinct payloads back as the one `Version`. A field
keeps both: every octet is accounted for, whatever follows the flag is
refused, and the two payloads are two objects each serializing back to
the buffer it came from.

**What it costs, and this is the one place it is worth saying.** Two
things, both of them consequences of a last field that may not be there.

A prefix of one `Version` encoding *is* another `Version`, so the generic
"no prefix of an encoding is an object" property that
`tests/parse_contract_test.py` holds every parser to is false of this one
by construction. What that property is *for* -- two buffers decoding to
one object that serializes back to only one of them -- is not: the two
buffers are two objects, each writing back the octets it came from.
`tests/p2p/handshake_test.py` drives that, and the exclusion in
`parse_contract_test.py` names it.

And `Version.parse` takes `Octets` where every other parser in this
package takes `BinaryData`, because a `version` payload does not say how
long it is: whether the last octet is the relay flag or the first octet
of whatever comes next is a question the buffer cannot answer, and the
envelope's length field is what answers it. A caller has that already --
`Version.parse(message.payload)` -- so what a stream would add is the
one reading that is silently wrong. `btclib.bip32.key_origin` is the
other parser in this library that takes `Octets` for this reason, and
`parse_contract_test.py` states it there too.

Core's conditionals reach further up than the relay flag, and this
module's requirements stop where they stop being about a message anybody
sends. `addr_from` through `start_height` are required here, where
net_processing.cpp would accept a `version` truncated after `addr_recv`:
those `if (!vRecv.empty())` are a defence against a short read rather than
a statement that five fields are optional, no BIP made any of them so,
and no peer above Core's own `MIN_PEER_PROTO_VERSION` omits them. The
relay flag is the one of them a BIP did make optional, and it is the one
modelled as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

from typing_extensions import override

from btclib import var_bytes
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.address import (
    NetworkAddress,
    ServiceFlags,
    _service_flags_from_int,
)
from btclib.p2p.limits import MAX_SUBVERSION_LENGTH
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "Verack",
    "Version",
]

_VERSION_SIZE = 4
_SERVICES_SIZE = 8
_TIMESTAMP_SIZE = 8
_NONCE_SIZE = 8
_START_HEIGHT_SIZE = 4
_RELAY_SIZE = 1

_MAX_SERVICES = (1 << (8 * _SERVICES_SIZE)) - 1
_MAX_NONCE = (1 << (8 * _NONCE_SIZE)) - 1

# Core declares nVersion and starting_height `int` and nTime `int64_t`,
# and its test framework reads all three signed; the service flags and
# the nonce are `uint64_t`. So two of the widths below are two-sided
_MIN_INT32 = -(1 << (8 * _VERSION_SIZE - 1))
_MAX_INT32 = (1 << (8 * _VERSION_SIZE - 1)) - 1
_MIN_INT64 = -(1 << (8 * _TIMESTAMP_SIZE - 1))
_MAX_INT64 = (1 << (8 * _TIMESTAMP_SIZE - 1)) - 1


def _assert_int_range(value: int, low: int, high: int, what: str) -> None:
    """Refuse a value that is no integer, or one outside a field's width.

    Private and unvalidated of its own arguments, as a private twin is:
    the three that follow the value are literals of this module.
    """
    # a bool is an int and would read as the number one or zero, which
    # the range check cannot tell from a field whose value that is
    if not is_integer(value):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if not low <= value <= high:
        raise BTClibValueError(f"invalid {what}: {value}")


@dataclass(frozen=True)
class Version(Payload):
    """The `version` message: who is calling, and what it can do.

    Nine fields, of which the last may not be on the wire at all. In the
    order Core serializes them: the protocol version, the service flags,
    the sender's clock, the address it is writing to, the address it is
    writing from, a nonce it recognizes its own connection by, the user
    agent, the height of its best chain, and BIP37's relay flag.

    `relay` is `True`, `False` or `None`, and `None` is not `False`: it
    says the octets ended before the flag, which is what a peer older
    than BIP37 sends and what Core still accepts from any peer. What such
    a peer *means* is `True` -- `net_processing.cpp` initializes `bool
    fRelay = true` and overwrites it only where the field is there -- and
    `is_relay_requested` is that reading, so that a caller does not write
    `if version.relay` and answer the opposite of the protocol's default
    for every peer that omitted it. The module docstring is why the
    presence is a field rather than a function of `version`.

    `user_agent` is octets and not text. Core reads it into a
    `std::string` and sanitizes it only for the log -- `SanitizeString`
    on `cleanSubVer` -- so a peer may put anything at all in it, and
    decoding here would refuse a message Core accepts. A caller that
    wants to show one decodes it, with the error handling it wants.
    `MAX_SUBVERSION_LENGTH` is the bound on it, Core's `LIMITED_STRING`.

    `timestamp` and `start_height` are signed, `version` is signed, and
    `services` and `nonce` are not, each following the type Core declares
    -- a negative `nTime` is what Core clamps to zero on receipt rather
    than refusing, so it is a value this parses.

    `addr_recv` and `addr_from` carry no timestamp, which is
    `btclib.p2p.address`'s reason for two classes.
    """

    command = "version"

    version: int
    services: ServiceFlags
    timestamp: int
    addr_recv: NetworkAddress
    addr_from: NetworkAddress
    nonce: int
    user_agent: bytes
    start_height: int
    relay: bool | None

    def __init__(
        self,
        version: int = 0,
        services: int = ServiceFlags.NODE_NONE,
        timestamp: int = 0,
        addr_recv: NetworkAddress | None = None,
        addr_from: NetworkAddress | None = None,
        nonce: int = 0,
        user_agent: Octets = b"",
        start_height: int = 0,
        relay: bool | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "services", _service_flags_from_int(services))
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(
            self,
            "addr_recv",
            NetworkAddress(check_validity=check_validity)
            if addr_recv is None
            else addr_recv,
        )
        object.__setattr__(
            self,
            "addr_from",
            NetworkAddress(check_validity=check_validity)
            if addr_from is None
            else addr_from,
        )
        object.__setattr__(self, "nonce", nonce)
        object.__setattr__(self, "user_agent", bytes_from_octets(user_agent))
        object.__setattr__(self, "start_height", start_height)
        object.__setattr__(self, "relay", relay)

        if check_validity:
            self.assert_valid()

    @property
    def is_relay_requested(self) -> bool:
        """Answer whether this peer wants transactions announced to it.

        BIP37's flag, with BIP37's default where the flag is absent:
        Bitcoin Core's `net_processing.cpp` declares `bool fRelay = true`
        before it reads the message and assigns to it only inside `if
        (!vRecv.empty())`, so a `version` that stops before the flag asks
        for relay rather than refusing it.

        The reading and not the field, which is what `relay` is: a caller
        that needs to know whether the peer said so reads `relay is
        None`. Reading `relay` itself for the answer is what makes an
        absent flag mean the opposite of what the protocol says it means.
        """
        return self.relay is not False

    def assert_valid(self) -> None:
        """Refuse a field no wire value of its own width holds."""
        _assert_int_range(self.version, _MIN_INT32, _MAX_INT32, "version")
        _assert_int_range(self.services, 0, _MAX_SERVICES, "services")
        _assert_int_range(self.timestamp, _MIN_INT64, _MAX_INT64, "timestamp")
        _assert_int_range(self.nonce, 0, _MAX_NONCE, "nonce")
        _assert_int_range(self.start_height, _MIN_INT32, _MAX_INT32, "start height")

        for what, address in (
            ("addr_recv", self.addr_recv),
            ("addr_from", self.addr_from),
        ):
            if not isinstance(address, NetworkAddress):
                err_msg = f"invalid {what} type: {type(address).__name__}"  # type: ignore[unreachable]
                raise BTClibTypeError(err_msg)
            address.assert_valid()

        if len(self.user_agent) > MAX_SUBVERSION_LENGTH:
            err_msg = f"invalid user agent length: {len(self.user_agent)}"
            err_msg += f" instead of at most {MAX_SUBVERSION_LENGTH} bytes"
            raise BTClibValueError(err_msg)

        # a kind and not a truth: the value decides what is written, one
        # octet or none, so `relay="no"` would serialize as True rather
        # than as the False a configuration file meant by it
        if self.relay is not None and not isinstance(self.relay, bool):
            err_msg = f"invalid relay type: {type(self.relay).__name__}"  # type: ignore[unreachable]
            raise BTClibTypeError(err_msg)

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the payload, the relay octet written only if there is one."""
        if check_validity:
            self.assert_valid()

        out = self.version.to_bytes(_VERSION_SIZE, byteorder="little", signed=True)
        out += int(self.services).to_bytes(
            _SERVICES_SIZE, byteorder="little", signed=False
        )
        out += self.timestamp.to_bytes(_TIMESTAMP_SIZE, byteorder="little", signed=True)
        out += self.addr_recv.serialize(check_validity=check_validity)
        out += self.addr_from.serialize(check_validity=check_validity)
        out += self.nonce.to_bytes(_NONCE_SIZE, byteorder="little", signed=False)
        out += var_bytes.serialize(self.user_agent)
        out += self.start_height.to_bytes(
            _START_HEIGHT_SIZE, byteorder="little", signed=True
        )
        if self.relay is not None:
            out += bytes([int(self.relay)])
        return out

    @classmethod
    def parse(
        cls: type[Version], data: Octets, *, check_validity: bool = True
    ) -> Version:
        """Return the `version` the payload describes, relay flag or not.

        The flag is read where an octet is left and left `None` where
        none is, which is the one conditional here; everything before it
        is required, and the module docstring is why.

        `Octets` and not `BinaryData`, which is the other half of that
        decision: "where an octet is left" is a question about the whole
        payload, and in a stream holding the next message the answer
        would be the first octet of that one. The envelope is what says
        where a payload ends, so `message.payload` is what this takes.

        Only `0x00` and `0x01` are a flag. Core's `Unserialize` for a
        bool takes any octet and answers `!= 0`, so `0x02` reads as true
        there and is written back as `0x01` -- two payloads, one object,
        and only one of them serialized back. That is the malleability
        `Message`'s command padding is refused for one layer down, and
        the same answer is given here.
        """
        # `BytesIO(bytes_from_octets(...))` and not
        # `bytesio_from_binarydata`, which hands a caller's stream back as
        # it came: a stream is the whole of what this must not accept, so
        # the refusal is the coercion's rather than a check of its own
        stream = BytesIO(bytes_from_octets(data))

        version = int.from_bytes(
            read_exactly(stream, _VERSION_SIZE, "version protocol version"),
            byteorder="little",
            signed=True,
        )
        services = int.from_bytes(
            read_exactly(stream, _SERVICES_SIZE, "version services"),
            byteorder="little",
            signed=False,
        )
        timestamp = int.from_bytes(
            read_exactly(stream, _TIMESTAMP_SIZE, "version timestamp"),
            byteorder="little",
            signed=True,
        )
        addr_recv = NetworkAddress.parse(stream, check_validity=check_validity)
        addr_from = NetworkAddress.parse(stream, check_validity=check_validity)
        nonce = int.from_bytes(
            read_exactly(stream, _NONCE_SIZE, "version nonce"),
            byteorder="little",
            signed=False,
        )
        user_agent = var_bytes.parse(stream)
        start_height = int.from_bytes(
            read_exactly(stream, _START_HEIGHT_SIZE, "version start height"),
            byteorder="little",
            signed=True,
        )

        relay: bool | None = None
        octet = stream.read(_RELAY_SIZE)
        if octet:
            if octet[0] > 1:
                raise BTClibValueError(f"invalid relay flag: {octet.hex()}")
            relay = bool(octet[0])
        assert_no_trailing(data, stream, "version payload")

        return cls(
            version,
            services,
            timestamp,
            addr_recv,
            addr_from,
            nonce,
            user_agent,
            start_height,
            relay,
            check_validity=check_validity,
        )


@dataclass(frozen=True)
class Verack(Payload):
    """The `verack` message: no fields, and an empty payload.

    Bitcoin Core's `msg_verack`, which serializes to nothing and whose
    `deserialize` reads nothing.

    A class all the same, and the empty payload is why rather than
    despite: it is the one payload type whose whole content is its
    command, so the constant on it is the entire benefit of having a
    class at all, and it is what proves the shape
    `btclib.p2p.payload.Payload` states is uniform. `Verack().to_message(
    magic)` is a complete `verack`, resting on the envelope's
    `payload=b""` default.

    `parse` refuses an octet, where Core ignores whatever a `verack`
    carries -- `ProcessMessage` never reads `vRecv` for one. This library
    refuses what follows an object everywhere else, and a `verack` with a
    payload is a message that serializes back without it.
    """

    command = "verack"

    def __init__(self, *, check_validity: bool = True) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Accept: a message with no fields has none to refuse."""

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the empty payload a `verack` is."""
        if check_validity:
            self.assert_valid()

        return b""

    @classmethod
    def parse(
        cls: type[Verack], data: BinaryData, *, check_validity: bool = True
    ) -> Verack:
        """Return a `Verack`, refusing any octet at all.

        Octets are refused by `assert_no_trailing`, which is where the
        rule already is; a caller's stream is left exactly where it was,
        a `verack` consuming nothing from one.
        """
        stream = bytesio_from_binarydata(data)
        assert_no_trailing(data, stream, "verack payload")

        return cls(check_validity=check_validity)
