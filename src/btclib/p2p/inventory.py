# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What a peer has, what it wants, and what it could not find.

The messages by which peers tell each other what they have and ask for
what they do not, and the type code under them. `inv`, `getdata` and
`notfound` are a vector of Bitcoin Core's `CInv`, of src/protocol.h;
`getblocks` and `getheaders` are a protocol version, a locator and a stop
hash; `headers` is block headers. The layout is Core's
test/functional/test_framework/messages.py -- `msg_inv`, `msg_getdata`,
`msg_notfound`, `msg_getblocks`, `msg_getheaders`, `msg_headers` and the
`CInv` and `CBlockLocator` under them, at the revision `TF2.md` pins --
and the type codes are src/protocol.h's `GetDataMsg`.

**Three commands share one body, and so one class each over one private
base**, which is `btclib.p2p.keepalive`'s shape for `ping` and `pong`:
`Inv`, `GetData` and `NotFound` are one vector of `Inventory`, `GetBlocks`
and `GetHeaders` one (version, locator, stop hash). A field naming the
command instead would let a caller build an `inv` that serializes under
"getdata"; a subclass setting `command` cannot, and the generated
`__eq__` keeps an `inv` and a `getdata` of the same octets two objects.

**`InventoryType` is an `IntEnum`, and the `ServiceFlags` reasoning does
not transfer.** Eight octets of service flags are a bitfield throughout,
so `IntFlag` is what the field *is* and an unnamed bit is a service not
yet heard of. A type code is not a bitfield: `MSG_TX`, `MSG_BLOCK`,
`MSG_FILTERED_BLOCK`, `MSG_CMPCT_BLOCK` and `MSG_WTX` are one through
five, exclusive kinds and not bits, and only `MSG_WITNESS_FLAG` is a bit.
An `IntFlag` over them would compose nonsense and answer for it: 1 | 4
would be `MSG_WTX`, so `MSG_TX in InventoryType(5)` would be true and a
`wtx` announcement would test as a `tx` one. `IntEnum` is what says these
are kinds -- and the composites are members because Core makes them
members, `MSG_WITNESS_TX` and `MSG_WITNESS_BLOCK` being named in
`GetDataMsg` itself. `MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG` is not:
BIP144 reserved it and Core carries it commented out, so naming it here
would be btclib publishing a code Core does not.

What the flag being a bit still buys is `Inventory.is_witness`, which is
the reading rather than the field, as `Version.is_relay_requested` is:
a caller asking whether a peer wants the witness reads that instead of
comparing against two members and forgetting the third the next BIP adds.

**An unrecognized type code round-trips**, which is the envelope's rule
about an unrecognized command one layer down. `IntEnum` refuses a value
no member names, so the coercion is `_inventory_type_from_int` and it
hands back the plain `int` where there is no member -- exactly what
`_inventory_type_from_int`'s neighbour `_service_flags_from_int` does for
what is no bitfield at all. `Inventory.type_code` is therefore
`InventoryType | int`, four octets wide either way, and the octets a
peer sent come back as they arrived.

**`headers` carries a transaction count that is always zero, and it is
dropped rather than stored.** Core writes a header followed by an empty
transaction vector -- `msg_headers.serialize` builds a `CBlock` per
header for exactly that -- and reads it as `ReadCompactSize(vRecv); //
ignore tx count; assume it is 0`. Storing it would be a second object
for one meaning: a `headers` message says nothing about how many
transactions a block has, so a field holding what a peer wrote there
would be a field with no reading. What dropping it costs is an encoding
this cannot reproduce, so a non-zero count is *refused* rather than
ignored, and the property kept is the one this library keeps everywhere:
every payload it accepts serializes back to the octets it came from.
`Verack.parse` refuses an octet Core ignores for the same reason, and
`Version.parse` refuses a relay flag of `0x02` that Core reads as true.
A non-minimal encoding of the zero needs no refusal of its own, btclib's
`var_int.parse` being canonical-only already.

**`getblocks` and `getheaders` carry an ignored field too, and that one
is stored**, which is the contrast worth having in one place. Core
writes the stream's protocol version in front of the locator and
discards what it reads -- `CBlockLocator`'s `SERIALIZE_METHODS` on one
side, `msg_getblocks` on the other, whose comment reads "Bitcoin Core
ignores the version field. Set it to 0." Ignored is not constant: a Core
node sends the version it negotiated, its test framework sends zero, and
a message carrying either is one both accept. So the field varies over
messages anybody sends and is a field; the `headers` count does not vary
at all.

**Every hash is held the way a block explorer prints it** and reversed on
the wire, as `OutPoint.tx_id` and `BlockHeader.previous_block_hash` are:
these are the same hashes those fields hold, so a caller comparing an
announcement with a transaction it has must not have to reverse one of
them. `tests/p2p/inventory_test.py` is driven by the vendored mainnet
blocks for that reason -- the hash of a real block is what tells the two
orders apart, and nothing a round trip does can.

**Every count is bounded before the loop that allocates on it**, each
under Core's own name in `btclib.p2p.limits`: `MAX_INV_SZ`,
`MAX_HEADERS_RESULTS`, `MAX_LOCATOR_SZ`. A count is the peer's to choose
and btclib's `var_int.parse` allows 33,554,432 of anything, so the check
before the loop is the whole of what a bound is for -- and, as in
`Addr.parse`, it does not answer to `check_validity`, a defence a caller
can turn off not being one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import TypeVar

from typing_extensions import Self, override

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.limits import MAX_HEADERS_RESULTS, MAX_INV_SZ, MAX_LOCATOR_SZ
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    is_octets,
    read_exactly,
)

__all__ = [
    "MSG_WITNESS_FLAG",
    "GetBlocks",
    "GetData",
    "GetHeaders",
    "Headers",
    "Inv",
    "Inventory",
    "InventoryType",
    "NotFound",
]

# what a sequence field holds, so that checking the sequence itself does
# not forget what its elements are: one helper, three fields
_Element = TypeVar("_Element")

# CInv's two fields, and the protocol version a locator is written behind
_TYPE_SIZE = 4
_HASH_SIZE = 32
_VERSION_SIZE = 4

_MAX_TYPE = (1 << (8 * _TYPE_SIZE)) - 1

# Core declares the version a locator carries `int`, and its test
# framework reads it signed: two-sided, as `Version.version` is
_MIN_INT32 = -(1 << (8 * _VERSION_SIZE - 1))
_MAX_INT32 = (1 << (8 * _VERSION_SIZE - 1)) - 1

# the transaction count Core writes after each header in a `headers`
# message and ignores on the way back: always zero, never stored, and
# the module docstring is why
_NO_TRANSACTIONS = var_int.serialize(0)

# Bitcoin Core's src/protocol.h, `inline constexpr uint32_t
# MSG_WITNESS_FLAG = 1 << 30`: the bit a peer that can serve witnesses
# ORs into a `getdata` type code, BIP144's. Not a type code itself, which
# is why it is a constant beside the enum rather than a member of it --
# Core keeps it outside `GetDataMsg` for the same reason.
#
# Named in this module and not republished by `btclib.p2p`, as
# `address.IPAddress` is not: a caller testing the bit by hand names the
# module the protocol constant comes from, and `Inventory.is_witness` is
# what spares most of them from needing it at all
MSG_WITNESS_FLAG = 1 << 30


class InventoryType(IntEnum):
    """What an inventory entry's hash identifies, Core's `GetDataMsg`.

    src/protocol.h, spelled as Core spells it, composites included:
    `MSG_WITNESS_TX` and `MSG_WITNESS_BLOCK` are members there rather
    than something a caller assembles, so they are members here. The
    third BIP144 reserved, `MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG`, is
    not: Core's own line for it is commented out as "reserved for future
    use and remains unused", and a library naming it would be publishing
    a code the protocol has not got.

    `UNDEFINED` is Core's name for zero, which is the code an entry
    carries when it identifies nothing -- `CInv`'s default, and what its
    test framework's type map calls "Error".

    An `IntEnum` and not an `IntFlag`: the module docstring has why the
    `ServiceFlags` reasoning stops here, and `_inventory_type_from_int`
    is what keeps a code no member names from being an error.

    `GetDataMsg` is Core's name and is not taken here, being the name of
    one of the three messages that carry the code: an `inv` announces
    with it and a `notfound` refuses with it.
    """

    UNDEFINED = 0
    MSG_TX = 1
    MSG_BLOCK = 2
    MSG_FILTERED_BLOCK = 3  # BIP37
    MSG_CMPCT_BLOCK = 4  # BIP152
    MSG_WTX = 5  # BIP339
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG  # BIP144
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG  # BIP144


def _inventory_type_from_int(type_: int) -> InventoryType | int:
    """Return the member a code names, leaving an unnamed code alone.

    `IntEnum` refuses a value no member has, where `IntFlag` keeps an
    unnamed bit: that difference is the whole of the work here, and the
    answer is the one `_service_flags_from_int` gives for what is no
    bitfield -- hand the value back, for `assert_valid` one line later to
    refuse through this library's own exception classes if the four
    octets cannot hold it.

    A bool is handed back rather than converted, `InventoryType(True)`
    being `MSG_TX`: `is_integer` is the predicate every integer field of
    this library is held to, and a `type=True` that arrived as `MSG_TX`
    would pass the refusal `assert_valid` exists to make.
    """
    if not is_integer(type_):
        return type_
    try:
        return InventoryType(type_)
    except ValueError:
        return type_


def _assert_valid_hash(hash_: bytes, what: str) -> None:
    """Refuse what is not the thirty-two octets of a hash256.

    Private and unvalidated of `what`, as a private twin is: every caller
    hands it a literal of this module.
    """
    # bytes() is the type check and never assigned back: validating must
    # not rewrite the object it is asked to inspect
    value = bytes(hash_)
    if len(value) != _HASH_SIZE:
        err_msg = f"invalid {what}: {len(value)} bytes"
        err_msg += f" instead of {_HASH_SIZE}"
        raise BTClibValueError(err_msg)


def _sequence_of(values: Sequence[_Element], what: str) -> tuple[_Element, ...]:
    """Return the tuple of a sequence that is not text or octets.

    An Octets -- str, bytes, bytearray or memoryview -- is a Sequence
    whose elements are a character or an integer, which is what none of
    the fields below holds: asked whole here, so that a caller who passed
    one is told about the argument rather than about its first element.
    `is_octets` is the four spellings named once, so a spelling `Octets`
    gains later is refused here too (issue #1405, as issue #1261 for
    `utils.is_octets` itself).
    """
    if is_octets(values) or not isinstance(values, Sequence):
        raise BTClibTypeError(f"invalid {what} type: {type(values).__name__}")
    return tuple(values)


@dataclass(frozen=True)
class Inventory:
    """One entry of an `inv`, a `getdata` or a `notfound`: (type, hash).

    Bitcoin Core's `CInv`, of src/protocol.h, whose `SERIALIZE_METHODS`
    is `READWRITE(obj.type, obj.hash)`: four octets of type code,
    little-endian, and the thirty-two of a hash256.

    `type_code` is an `InventoryType` where a member names the code and
    the plain `int` where none does, which is how a code this library has
    not heard of round-trips. Core spells the field `type` and this
    library cannot: a class attribute of that name shadows the builtin
    inside its own body, and `type[Inventory]` is what every `parse` here
    annotates its `cls` with -- "type code" being what the protocol
    documentation calls it in prose anyway.

    `hash` is a transaction id, a witness transaction id or a block hash
    depending on that code, and is held in the order a block explorer
    prints: the order `OutPoint.tx_id` and
    `BlockHeader.previous_block_hash` are held in, these being those very
    hashes.

    Frozen and hashable, both fields being immutable: an entry is a
    value, and it is what a set of announcements from a peer holds.
    """

    type_code: InventoryType | int
    hash: bytes

    def __init__(
        self,
        type_code: int = InventoryType.UNDEFINED,
        hash: Octets = b"\x00" * _HASH_SIZE,  # noqa: A002
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "type_code", _inventory_type_from_int(type_code))
        object.__setattr__(self, "hash", bytes_from_octets(hash))

        if check_validity:
            self.assert_valid()

    @property
    def is_witness(self) -> bool:
        """Answer whether the code asks for the witness beside the data.

        BIP144's bit, `MSG_WITNESS_FLAG`, which Core ORs into a type code
        rather than listing beside it -- `GetFetchFlags` is the one line
        that sets it, on a peer that may be served witnesses.

        The reading and not the field, as `Version.is_relay_requested`
        is: comparing `type_code` against `MSG_WITNESS_TX` and
        `MSG_WITNESS_BLOCK` is the same question asked in a way that goes
        wrong the day a BIP names a third composite.
        """
        return bool(int(self.type_code) & MSG_WITNESS_FLAG)

    def assert_valid(self) -> None:
        """Refuse a code no four octets hold, or a hash of another size."""
        # a bool is an int and would read as MSG_TX or UNDEFINED, which
        # the range check below cannot tell from a code whose value that is
        if not is_integer(self.type_code):
            err_msg = f"invalid type_code type: {type(self.type_code).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.type_code <= _MAX_TYPE:
            raise BTClibValueError(f"invalid type_code: {self.type_code}")

        _assert_valid_hash(self.hash, "hash length")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the thirty-six octets: the code, then the hash."""
        if check_validity:
            self.assert_valid()

        out = int(self.type_code).to_bytes(_TYPE_SIZE, byteorder="little", signed=False)
        out += self.hash[::-1]
        return out

    @classmethod
    def parse(
        cls: type[Inventory], data: BinaryData, *, check_validity: bool = True
    ) -> Inventory:
        """Return the entry the thirty-six octets describe."""
        stream = bytesio_from_binarydata(data)

        type_code = int.from_bytes(
            read_exactly(stream, _TYPE_SIZE, "inventory type code"),
            byteorder="little",
            signed=False,
        )
        hash_ = read_exactly(stream, _HASH_SIZE, "inventory hash")[::-1]
        assert_no_trailing(data, stream, "inventory entry")

        return cls(type_code, hash_, check_validity=check_validity)


@dataclass(frozen=True)
class _InventoryPayload(Payload):
    """A count and that many `Inventory`, with the command left open.

    Private, and a base rather than one class with the command as a
    field, which is `btclib.p2p.keepalive._NoncePayload`'s argument: an
    `inv`, a `getdata` and a `notfound` are three message types with one
    body, and the command is what tells them apart, so it is what the
    subclass sets and nothing else is.

    A tuple and not a list, so that a frozen entry vector is what its
    field says it is; `dataclasses.replace` is what changes it.
    """

    items: tuple[Inventory, ...]

    def __init__(
        self, items: Sequence[Inventory] = (), *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "items", _sequence_of(items, "items"))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse more entries than a peer accepts, and ask each of them."""
        if len(self.items) > MAX_INV_SZ:
            err_msg = f"invalid items count: {len(self.items)}"
            err_msg += f" instead of at most {MAX_INV_SZ}"
            raise BTClibValueError(err_msg)

        for item in self.items:
            if not isinstance(item, Inventory):
                err_msg = f"invalid item type: {type(item).__name__}"  # type: ignore[unreachable]
                raise BTClibTypeError(err_msg)
            item.assert_valid()

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the count, then that many inventory entries."""
        if check_validity:
            self.assert_valid()

        out = var_int.serialize(len(self.items))
        for item in self.items:
            out += item.serialize(check_validity=check_validity)
        return out

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> Self:
        """Return the entries the payload carries, the count bounded first."""
        stream = bytesio_from_binarydata(data)

        count = var_int.parse(stream)
        if count > MAX_INV_SZ:
            err_msg = f"invalid items count: {count}"
            err_msg += f" instead of at most {MAX_INV_SZ}"
            raise BTClibValueError(err_msg)

        items = [
            Inventory.parse(stream, check_validity=check_validity) for _ in range(count)
        ]
        assert_no_trailing(data, stream, f"{cls.command} payload")

        return cls(items, check_validity=check_validity)


class Inv(_InventoryPayload):
    """The `inv` message: what this node has, offered unasked.

    Bitcoin Core's `msg_inv`. An announcement and not a delivery: what a
    peer does with one is send back a `getdata` for the entries it wants,
    which is the next class down.

    Core announces transactions as `MSG_TX` or `MSG_WTX` and blocks as
    `MSG_BLOCK` -- "Invs always use TX/WTX or BLOCK", says the comment in
    `GetDataMsg` -- and the witness bit belongs to a `getdata`. That is a
    rule about what a node sends, not about what these octets can carry,
    so nothing here refuses the other codes: a peer that sends one is
    answered by the caller's own policy, this package holding none.
    """

    command = "inv"


class GetData(_InventoryPayload):
    """The `getdata` message: send me these, by identifier.

    Bitcoin Core's `msg_getdata`, and the one of the three whose codes
    use the full vocabulary: `MSG_FILTERED_BLOCK`, `MSG_CMPCT_BLOCK` and
    the witness composites "can only occur in getdata", which is where
    `Inventory.is_witness` earns its place.
    """

    command = "getdata"


class NotFound(_InventoryPayload):
    """The `notfound` message: I have none of these.

    Bitcoin Core's `msg_notfound`, the answer to a `getdata` naming
    something this node cannot serve -- a transaction that has left its
    mempool, most often.

    **`MAX_INV_SZ` bounds this one too, where Core does not bound it**,
    and the difference is worth stating rather than glossing: Core
    refuses an over-long `inv` or `getdata` with a `Misbehaving` and
    answers an over-long `notfound` by ignoring its contents instead. A
    parser has to bound it all the same -- a count is the peer's to
    choose, and this is the same loop the other two run -- and
    `MAX_INV_SZ` is the right number for it because a `notfound` answers
    a `getdata`, which cannot have held more.
    """

    command = "notfound"


@dataclass(frozen=True)
class _LocatorPayload(Payload):
    """Where I am on the chain, and where to stop, with the command open.

    Private, and the base of `GetBlocks` and `GetHeaders` for the reason
    `_InventoryPayload` is the base of three: one body, two commands.

    The three fields are Core's `msg_getblocks` and `msg_getheaders`: the
    protocol version the `CBlockLocator` is written behind, the locator
    itself, and the hash to stop at. `locator` is the vector Core calls
    `vHave` -- block hashes from the sender's tip backwards, sparsening
    as they go, so that the receiver can find the last block the two have
    in common in one message; `hash_stop` is all zeros for "as much as
    you will give me", which is Core's own default.
    """

    version: int
    locator: tuple[bytes, ...]
    hash_stop: bytes

    def __init__(
        self,
        version: int = 0,
        locator: Sequence[Octets] = (),
        hash_stop: Octets = b"\x00" * _HASH_SIZE,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "version", version)
        object.__setattr__(
            self,
            "locator",
            tuple(
                bytes_from_octets(hash_) for hash_ in _sequence_of(locator, "locator")
            ),
        )
        object.__setattr__(self, "hash_stop", bytes_from_octets(hash_stop))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a version, a locator or a stop hash no message carries."""
        # a bool is an int and would read as the protocol version one or
        # zero, which the range check cannot tell from one
        if not is_integer(self.version):
            err_msg = f"invalid version type: {type(self.version).__name__}"
            raise BTClibTypeError(err_msg)
        if not _MIN_INT32 <= self.version <= _MAX_INT32:
            raise BTClibValueError(f"invalid version: {self.version}")

        if len(self.locator) > MAX_LOCATOR_SZ:
            err_msg = f"invalid locator count: {len(self.locator)}"
            err_msg += f" instead of at most {MAX_LOCATOR_SZ}"
            raise BTClibValueError(err_msg)
        for hash_ in self.locator:
            _assert_valid_hash(hash_, "locator hash length")

        _assert_valid_hash(self.hash_stop, "hash_stop length")

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the version, the locator, then the stop hash."""
        if check_validity:
            self.assert_valid()

        out = self.version.to_bytes(_VERSION_SIZE, byteorder="little", signed=True)
        out += var_int.serialize(len(self.locator))
        for hash_ in self.locator:
            out += hash_[::-1]
        out += self.hash_stop[::-1]
        return out

    @classmethod
    def parse(cls, data: BinaryData, *, check_validity: bool = True) -> Self:
        """Return the locator the payload carries, the count bounded first."""
        stream = bytesio_from_binarydata(data)

        version = int.from_bytes(
            read_exactly(stream, _VERSION_SIZE, "locator protocol version"),
            byteorder="little",
            signed=True,
        )

        count = var_int.parse(stream)
        if count > MAX_LOCATOR_SZ:
            err_msg = f"invalid locator count: {count}"
            err_msg += f" instead of at most {MAX_LOCATOR_SZ}"
            raise BTClibValueError(err_msg)
        locator = [
            read_exactly(stream, _HASH_SIZE, "locator hash")[::-1] for _ in range(count)
        ]

        hash_stop = read_exactly(stream, _HASH_SIZE, "hash_stop")[::-1]
        assert_no_trailing(data, stream, f"{cls.command} payload")

        return cls(version, locator, hash_stop, check_validity=check_validity)


class GetBlocks(_LocatorPayload):
    """The `getblocks` message: announce the blocks after this point.

    Bitcoin Core's `msg_getblocks`. The answer is an `inv` of up to five
    hundred block hashes, which the asker then fetches with a `getdata`
    -- one round trip more than `getheaders`, and what a node without the
    headers-first sync uses.
    """

    command = "getblocks"


class GetHeaders(_LocatorPayload):
    """The `getheaders` message: send the headers after this point.

    Bitcoin Core's `msg_getheaders`. The answer is a `headers` message of
    up to `MAX_HEADERS_RESULTS` headers, and a shorter one is how the
    asker learns it has reached the peer's tip -- Core's comment on that
    constant says so, and calls changing it a protocol upgrade.
    """

    command = "getheaders"


@dataclass(frozen=True)
class Headers(Payload):
    """The `headers` message: block headers, and no transactions.

    Bitcoin Core's `msg_headers`: a count, and that many eighty-octet
    headers each followed by a transaction count of zero. The count is
    not a field of this class and the module docstring is why; `serialize`
    writes the zero after every header and `parse` refuses anything else.

    `BlockHeader` is the type, `btclib.block` already parsing and
    serializing one: a header vector is that class in a loop rather than
    a second reader of the same eighty octets. Which is also what makes
    the elements answerable to `assert_valid_pow` -- this class does not
    call it, a `headers` message being how a node *learns* of work it has
    not checked, and the caller is who decides when to.

    **`MAX_HEADERS_RESULTS` bounds the count before the loop**, Core's
    own bound on this message and the reason its handler reads the
    headers by hand: "we don't want to risk deserializing 2000 full
    blocks".

    Frozen, and the one class here that is not hashable: `BlockHeader` is
    a mutable dataclass, so a tuple of them cannot be hashed.
    `dataclasses.replace` is what changes the headers in one.
    """

    command = "headers"

    headers: tuple[BlockHeader, ...]

    def __init__(
        self, headers: Sequence[BlockHeader] = (), *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "headers", _sequence_of(headers, "headers"))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse more headers than a peer sends, and ask each of them."""
        if len(self.headers) > MAX_HEADERS_RESULTS:
            err_msg = f"invalid headers count: {len(self.headers)}"
            err_msg += f" instead of at most {MAX_HEADERS_RESULTS}"
            raise BTClibValueError(err_msg)

        for header in self.headers:
            if not isinstance(header, BlockHeader):
                err_msg = f"invalid header type: {type(header).__name__}"  # type: ignore[unreachable]
                raise BTClibTypeError(err_msg)
            header.assert_valid()

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the count, then each header and the zero after it."""
        if check_validity:
            self.assert_valid()

        out = var_int.serialize(len(self.headers))
        for header in self.headers:
            out += header.serialize(check_validity=check_validity)
            out += _NO_TRANSACTIONS
        return out

    @classmethod
    def parse(
        cls: type[Headers], data: BinaryData, *, check_validity: bool = True
    ) -> Headers:
        """Return the headers the payload carries, the count bounded first.

        The transaction count after each header is read and refused
        unless it is zero, where Core reads it and throws it away: a
        `headers` carrying any other number is a message this library
        could not write back, and refusing what it cannot reproduce is
        what it does everywhere else -- `Verack.parse` on a payload Core
        ignores, `Version.parse` on a relay flag Core accepts.
        """
        stream = bytesio_from_binarydata(data)

        count = var_int.parse(stream)
        if count > MAX_HEADERS_RESULTS:
            err_msg = f"invalid headers count: {count}"
            err_msg += f" instead of at most {MAX_HEADERS_RESULTS}"
            raise BTClibValueError(err_msg)

        headers = []
        for _ in range(count):
            headers.append(BlockHeader.parse(stream, check_validity=check_validity))
            transactions = var_int.parse(stream)
            if transactions:
                err_msg = f"invalid transaction count: {transactions}"
                err_msg += " instead of 0"
                raise BTClibValueError(err_msg)
        assert_no_trailing(data, stream, "headers payload")

        return cls(headers, check_validity=check_validity)
