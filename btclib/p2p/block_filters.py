# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP157's six messages: the compact filters, and the chain over them.

The client's three requests and the server's three answers.
`getcfilters` asks for the filters of a height range and is answered by
one `cfilter` per block; `getcfheaders` asks for the filter *hashes* of a
range and is answered by one `cfheaders` holding them all; `getcfcheckpt`
asks for every thousandth filter header and is answered by a `cfcheckpt`.
BIP157 is the specification, and its field tables are the wire form; the
layout Core writes is test/functional/test_framework/messages.py's
`msg_getcfilters`, `msg_cfilter`, `msg_getcfheaders`, `msg_cfheaders`,
`msg_getcfcheckpt` and `msg_cfcheckpt`, and the handlers reading them are
`ProcessGetCFilters`, `ProcessGetCFHeaders` and `ProcessGetCFCheckPt` of
src/net_processing.cpp.

**A `cfilter` holds the filter as octets, not as a `BasicBlockFilter`.**
The type code decides the format -- BIP157: "Each type is identified by a
one byte code, and specifies the contents and serialization format of the
filter" -- and only `BASIC` is defined, so octets under any other code are
not a BIP158 filter and reading them as one would be inventing an answer.
`basic_filter` is where a caller says the code is `BASIC` and gets the
typed object, refused there if the Golomb stream does not decode.

That property costs nothing here because of the field order: BIP157 puts
BlockHash *before* FilterBytes, and `BasicBlockFilter.parse` needs
exactly that hash -- it is the SipHash key the filter is built under, and
the reason the hash is `parse`'s argument rather than something read back
out of the octets. So the message carries everything the typed object
needs, `basic_filter` takes no argument, and nothing about the seam is
left to a caller to supply.

**What a `cfilter` cannot be checked for is that its filter is its
block's**, and saying so is the point rather than an omission. A block
hash is a key and not a commitment: every thirty-two octets key some
filter, so a filter and a hash that do not belong together decode exactly
as a pair that does. What settles it is the block -- `from_block`
recomputes the filter -- or the header chain a `cfheaders` carries, and
both are the caller's, this package holding no chain and no blocks it did
not receive.

**An unrecognized filter type round-trips as a plain integer**, which is
what `InventoryType` and BIP155's network id do here, and BIP157's own
text is what decides it rather than that precedent: "Nodes receiving
`getcfilters` with an unsupported filter type SHOULD NOT respond" is a
rule about answering, and a rule about answering can only be applied by
something that has read the message. Core reads it the same way, casting
the octet to `BlockFilterType` and leaving `PrepareBlockFilterRequest` to
refuse the request afterwards.

`BlockFilterType` therefore names `BASIC` and nothing else. Core's own
enum has a second member, `INVALID = 255`, and it is not here: it is the
sentinel a `BlockFilterType` variable holds when there is no filter type,
where BIP158 defines the one code the protocol has -- the same reason
`InventoryType` does not name the composite BIP144 reserved and Core
carries commented out.

**`cfheaders` stores the filter hashes it carries, and derives the
headers.** The message holds a previous filter header and a vector of
hashes; the headers are what a client computes from the two, and BIP157
sends the hashes precisely so that it has to. Storing the derived headers
instead would be the question issue #1101 answered for `headers`' always-
zero transaction count, and the answer is the same: keep what the wire
holds, so that every payload serializes back to the octets it came from.
`filter_headers` is the derivation, as `Inventory.is_witness` is the
reading of a bit rather than a second field -- and it is the same
`block_filter.filter_header` that `BasicBlockFilter.header` is, the
general form being over a hash and the method the case where the filter
is at hand.

`cfcheckpt` needs no such derivation: what it carries *is* filter
headers, one per thousand blocks, and `heights` is the arithmetic BIP157
states over them.

**Every hash is held in the order a block explorer prints it** and
reversed on the wire, as everywhere else in this package: `BlockHeader.hash`
is what a `stop_hash` is compared against, `BasicBlockFilter.hash` is what
a `cfheaders` entry is, and `BasicBlockFilter.header` is what a
`cfcheckpt` entry is. A caller must not have to reverse one of them.

**Two of BIP157's three bounds are on a range this package cannot
resolve, and the third is a count, which is the one a parser can hold.**
`MAX_GETCFILTERS_SIZE` and `MAX_GETCFHEADERS_SIZE` bound the distance
from StartHeight to the height of StopHash, and a hash is a height only
to something holding the chain, so `getcfilters` and `getcfheaders` carry
the constants in their docstrings for the caller that has one and check
neither. `cfheaders`' FilterHashesLength is BIP157's "MUST NOT be greater
than 2,000" and is checked before the loop that allocates on it, as every
count in this package is.

`cfcheckpt`'s vector is bounded by no constant, and none is invented for
it: BIP157 bounds it by the length of the chain, Core sizes it as
`stop_index->nHeight / CFCHECKPT_INTERVAL` when it writes one and reads
none, and what stands in front of the loop here is the octets --
`read_exactly` refuses the first entry past the end, so the vector cannot
outgrow the payload, and the payload is the envelope's
`MAX_PROTOCOL_MESSAGE_LENGTH`. A second constant would be a number to be
wrong about in a third place, which is `btclib.p2p.data`'s argument for
bounding no message length.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from typing import TypeVar

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.block.block_filter import BasicBlockFilter, filter_header
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p.limits import CFCHECKPT_INTERVAL, MAX_GETCFHEADERS_SIZE
from btclib.p2p.payload import Payload
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "BlockFilterType",
    "CFCheckpt",
    "CFHeaders",
    "CFilter",
    "GetCFCheckpt",
    "GetCFHeaders",
    "GetCFilters",
]

# BIP157's fixed-width fields: the one octet of the type code, the
# thirty-two of a hash256, and the four of a height
_TYPE_SIZE = 1
_HASH_SIZE = 32
_HEIGHT_SIZE = 4

_MAX_TYPE = (1 << (8 * _TYPE_SIZE)) - 1
_MAX_HEIGHT = (1 << (8 * _HEIGHT_SIZE)) - 1


class BlockFilterType(IntEnum):
    """What a filter type code names, Core's `BlockFilterType`.

    src/blockfilter.h, and the one code BIP158 defines: "The initial
    filter types are defined separately in BIP 158", which defines
    `BASIC` and nothing after it.

    Core's enum has a second member, `INVALID = 255`, and it is not here.
    That value is what a `BlockFilterType` variable holds when there is
    no filter type -- `BlockFilterTypeByName` sets it on a name it cannot
    match -- rather than a code a peer may send, and a library naming it
    would be publishing a code the protocol has not got. `InventoryType`
    leaves out the composite BIP144 reserved for the same reason.

    An `IntEnum`, and `_block_filter_type_from_int` is what keeps a code
    no member names from being an error: the module docstring has why an
    unsupported type is a rule about answering rather than about reading.
    """

    BASIC = 0  # BIP158


def _block_filter_type_from_int(filter_type: int) -> BlockFilterType | int:
    """Return the member a code names, leaving an unnamed code alone.

    `IntEnum` refuses a value no member has, so the plain `int` is handed
    back where none does -- `_inventory_type_from_int` and
    `_bip155_network_from_int` are the same two lines for the same
    reason, and `assert_valid` refuses one octet cannot hold afterwards.

    A bool is handed back rather than converted, `BlockFilterType(False)`
    being `BASIC`: `is_integer` is the predicate every integer field of
    this library is held to, and a `filter_type=False` that arrived as
    `BASIC` would pass the refusal `assert_valid` exists to make.
    """
    if not is_integer(filter_type):
        return filter_type
    try:
        return BlockFilterType(filter_type)
    except ValueError:
        return filter_type


def _assert_valid_type(filter_type: BlockFilterType | int) -> None:
    """Refuse a filter type no octet holds."""
    # a bool is an int and would read as BASIC, which the range check
    # below cannot tell from the code whose value that is
    if not is_integer(filter_type):
        err_msg = f"invalid filter_type type: {type(filter_type).__name__}"
        raise BTClibTypeError(err_msg)
    if not 0 <= filter_type <= _MAX_TYPE:
        raise BTClibValueError(f"invalid filter_type: {filter_type}")


def _assert_valid_hash(hash_: bytes, what: str) -> None:
    """Refuse what is not the thirty-two octets of a hash256.

    Private and unvalidated of `what`, as `inventory._assert_valid_hash`
    is: every caller hands it a literal of this module.
    """
    # bytes() is the type check and never assigned back: validating must
    # not rewrite the object it is asked to inspect
    value = bytes(hash_)
    if len(value) != _HASH_SIZE:
        err_msg = f"invalid {what}: {len(value)} bytes"
        err_msg += f" instead of {_HASH_SIZE}"
        raise BTClibValueError(err_msg)


def _hashes_of(hashes: Sequence[Octets], what: str) -> tuple[bytes, ...]:
    """Return the tuple of a hash vector that is not text or octets.

    A str and a bytes are Sequences whose elements are a character and an
    integer, which is what no field below holds: asked whole here, so
    that a caller who passed one hash instead of a vector of them is told
    about the argument rather than about its first character.
    """
    if isinstance(hashes, (str, bytes, bytearray, memoryview)) or not isinstance(
        hashes, Sequence
    ):
        raise BTClibTypeError(f"invalid {what} type: {type(hashes).__name__}")
    return tuple(bytes_from_octets(hash_) for hash_ in hashes)


# so that `GetCFilters.parse` answers a `GetCFilters` and not the private
# base: the body is one and the two return types are not
_Request = TypeVar("_Request", bound="_FilterRangeRequest")


@dataclass(frozen=True)
class _FilterRangeRequest(Payload):
    """A filter type, a start height and a stop hash, the command open.

    Private, and a base rather than one class with the command as a
    field, which is `keepalive._NoncePayload`'s argument: `getcfilters`
    and `getcfheaders` are two message types with one body -- BIP157's
    two field tables are the same three rows -- and the command is what
    tells them apart, so it is what the subclass sets and nothing else
    is. The generated `__eq__` compares the class, so a `getcfilters` and
    a `getcfheaders` of one range stay two objects.

    `start_height` is unsigned, Core reading it into a `uint32_t`;
    `stop_hash` is the block the range ends at, held in display order.
    """

    filter_type: BlockFilterType | int
    start_height: int
    stop_hash: bytes

    def __init__(
        self,
        filter_type: int = BlockFilterType.BASIC,
        start_height: int = 0,
        stop_hash: Octets = b"\x00" * _HASH_SIZE,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "filter_type", _block_filter_type_from_int(filter_type)
        )
        object.__setattr__(self, "start_height", start_height)
        object.__setattr__(self, "stop_hash", bytes_from_octets(stop_hash))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a type, a height or a stop hash the fields cannot hold."""
        _assert_valid_type(self.filter_type)

        # a bool is an int and would read as height one or zero, which
        # the range check cannot tell from a height whose value that is
        if not is_integer(self.start_height):
            err_msg = f"invalid start_height type: {type(self.start_height).__name__}"
            raise BTClibTypeError(err_msg)
        if not 0 <= self.start_height <= _MAX_HEIGHT:
            raise BTClibValueError(f"invalid start_height: {self.start_height}")

        _assert_valid_hash(self.stop_hash, "stop_hash length")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the type, the height, then the stop hash."""
        if check_validity:
            self.assert_valid()

        out = int(self.filter_type).to_bytes(_TYPE_SIZE, byteorder="little")
        out += self.start_height.to_bytes(_HEIGHT_SIZE, byteorder="little")
        out += self.stop_hash[::-1]
        return out

    @classmethod
    def parse(
        cls: type[_Request], data: BinaryData, *, check_validity: bool = True
    ) -> _Request:
        """Return the range the payload asks for."""
        stream = bytesio_from_binarydata(data)

        filter_type = read_exactly(stream, _TYPE_SIZE, "filter type")[0]
        start_height = int.from_bytes(
            read_exactly(stream, _HEIGHT_SIZE, "start height"), byteorder="little"
        )
        stop_hash = read_exactly(stream, _HASH_SIZE, "stop hash")[::-1]
        assert_no_trailing(data, stream, f"{cls.command} payload")

        return cls(filter_type, start_height, stop_hash, check_validity=check_validity)


class GetCFilters(_FilterRangeRequest):
    """The `getcfilters` message: the filters of a range of blocks.

    Bitcoin Core's `msg_getcfilters`. The answer is one `cfilter` per
    block, "sequentially in order by block height", which is the one
    request here whose answer is many messages.

    **`limits.MAX_GETCFILTERS_SIZE` is not checked here**: BIP157 bounds
    the *range*, "the difference MUST be strictly less than 1000", and
    the far end of it is a hash. Turning that hash into a height needs
    the chain, which this package does not hold, so the bound belongs to
    the caller that does -- and the constant is in `btclib.p2p.limits`
    under Core's own name for it.
    """

    command = "getcfilters"


class GetCFHeaders(_FilterRangeRequest):
    """The `getcfheaders` message: the filter hashes of a range of blocks.

    Bitcoin Core's `msg_getcfheaders`, and the same three fields as
    `getcfilters` for a range twice as long: BIP157 bounds this one at
    "strictly less than 2,000", `limits.MAX_GETCFHEADERS_SIZE`, and it is
    unchecked here for the reason above. The answer is one `cfheaders`
    however long the range, the hashes being fixed width.
    """

    command = "getcfheaders"


@dataclass(frozen=True)
class CFilter(Payload):
    """The `cfilter` message: one block's filter, and the block it is of.

    Bitcoin Core's `msg_cfilter`: the type code, the block hash, and the
    serialized filter behind a `CompactSize` length. `block_hash` is in
    display order, `BlockHeader.hash`'s.

    `filter_bytes` is BIP157's FilterBytes -- what
    `BasicBlockFilter.serialize` writes, the element count and the
    Golomb-Rice set -- and is held as octets: what they encode is the
    type code's to say, and only `BASIC` says anything. `basic_filter` is
    the typed reading, and the module docstring is where that is argued
    and where what this message cannot be checked for is written down.

    Frozen and hashable, both octet fields being immutable, which is what
    holding the filter as octets rather than as a mutable
    `BasicBlockFilter` buys.
    """

    command = "cfilter"

    filter_type: BlockFilterType | int
    block_hash: bytes
    filter_bytes: bytes

    def __init__(
        self,
        filter_type: int = BlockFilterType.BASIC,
        block_hash: Octets = b"\x00" * _HASH_SIZE,
        filter_bytes: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "filter_type", _block_filter_type_from_int(filter_type)
        )
        object.__setattr__(self, "block_hash", bytes_from_octets(block_hash))
        object.__setattr__(self, "filter_bytes", bytes_from_octets(filter_bytes))

        if check_validity:
            self.assert_valid()

    @property
    def basic_filter(self) -> BasicBlockFilter:
        """Return the filter these octets are, keyed on this block hash.

        The reading and not the field: a `cfilter` of any other type
        carries octets no BIP defines, so this is where a caller says the
        type is `BASIC` and is refused if it is not. What
        `BasicBlockFilter.parse` then refuses is a Golomb stream that
        does not decode -- an element count the bits fall short of, a
        delta past the range, an octet the deltas never reached.

        No argument, which is the seam this message closes: BlockHash
        precedes FilterBytes in BIP157's table, so the hash the filter is
        keyed by arrived with it.
        """
        if self.filter_type != BlockFilterType.BASIC:
            err_msg = f"invalid filter_type for a basic filter: {self.filter_type}"
            raise BTClibValueError(err_msg)
        return BasicBlockFilter.parse(self.filter_bytes, self.block_hash)

    def assert_valid(self) -> None:
        """Refuse a type or a block hash the fields cannot hold.

        The filter octets are not decoded, whatever the type code says:
        `basic_filter` is where they are read as BIP158's, and refusing
        them here would make the same octets parse under a type code
        nobody has defined and fail under the one that is. They
        round-trip either way, which is the property this package keeps.

        Nor are they asked anything else. `bytes_from_octets` is what
        `__init__` coerced them with and there is no width they must
        have, so unlike the two hash fields there is nothing left here to
        refuse -- a `cfilter` of an empty filter is a message BIP158's
        own vector file holds.
        """
        _assert_valid_type(self.filter_type)
        _assert_valid_hash(self.block_hash, "block_hash length")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the type, the block hash, then the filter behind a length."""
        if check_validity:
            self.assert_valid()

        out = int(self.filter_type).to_bytes(_TYPE_SIZE, byteorder="little")
        out += self.block_hash[::-1]
        out += var_bytes.serialize(self.filter_bytes)
        return out

    @classmethod
    def parse(
        cls: type[CFilter], data: BinaryData, *, check_validity: bool = True
    ) -> CFilter:
        """Return the filter octets the payload carries, and their block.

        NumFilterBytes gets no bound of its own: `var_bytes.parse` reads
        the length and then reads *from the stream*, so what it can build
        is what the payload holds, and what the payload holds is the
        envelope's `MAX_PROTOCOL_MESSAGE_LENGTH`. A filter has no other
        limit to be held to -- BIP158 bounds the element count and
        `BasicBlockFilter.parse` checks that, over octets a caller has
        already been handed.
        """
        stream = bytesio_from_binarydata(data)

        filter_type = read_exactly(stream, _TYPE_SIZE, "filter type")[0]
        block_hash = read_exactly(stream, _HASH_SIZE, "block hash")[::-1]
        filter_bytes = var_bytes.parse(stream)
        assert_no_trailing(data, stream, "cfilter payload")

        return cls(filter_type, block_hash, filter_bytes, check_validity=check_validity)


@dataclass(frozen=True)
class CFHeaders(Payload):
    """The `cfheaders` message: the filter hashes a header chain is built of.

    Bitcoin Core's `msg_cfheaders`: the type code, the stop hash, the
    filter header before the first block of the range, and the vector of
    filter hashes. Every hash is in display order, `BasicBlockFilter.hash`'s
    and `BasicBlockFilter.header`'s.

    **The hashes are the field and the headers are derived**, which is
    what BIP157 sends: a client that was handed the headers would have
    nothing left to check, where the hashes plus one previous header
    chain into headers it computed itself. `filter_headers` is that
    derivation; the module docstring is where storing it instead is
    refused.

    `previous_filter_header` is thirty-two zero octets for a range
    starting at the genesis block, which is BIP157's definition of the
    header before the first one.

    Frozen and hashable, every field being immutable;
    `dataclasses.replace` is what changes the vector.
    """

    command = "cfheaders"

    filter_type: BlockFilterType | int
    stop_hash: bytes
    previous_filter_header: bytes
    filter_hashes: tuple[bytes, ...]

    def __init__(
        self,
        filter_type: int = BlockFilterType.BASIC,
        stop_hash: Octets = b"\x00" * _HASH_SIZE,
        previous_filter_header: Octets = b"\x00" * _HASH_SIZE,
        filter_hashes: Sequence[Octets] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "filter_type", _block_filter_type_from_int(filter_type)
        )
        object.__setattr__(self, "stop_hash", bytes_from_octets(stop_hash))
        object.__setattr__(
            self,
            "previous_filter_header",
            bytes_from_octets(previous_filter_header),
        )
        object.__setattr__(
            self, "filter_hashes", _hashes_of(filter_hashes, "filter_hashes")
        )

        if check_validity:
            self.assert_valid()

    @property
    def filter_headers(self) -> tuple[bytes, ...]:
        """Return the filter header of each block of the range, in order.

        BIP157: a filter header is "the double-SHA256 of the
        concatenation of the filter hash with the previous filter
        header", so the vector plus `previous_filter_header` is a chain,
        and the last entry is the header a client compares against what
        another peer told it. `block_filter.filter_header` is the one
        step, the same one `BasicBlockFilter.header` takes where the
        filter itself is at hand.

        Every hash is in display order, so every header answered is too.
        A tuple, as `CFCheckpt.filter_headers` is: one name over the two
        messages, and one type with it.
        """
        headers = []
        previous = self.previous_filter_header
        for filter_hash in self.filter_hashes:
            previous = filter_header(filter_hash, previous)
            headers.append(previous)
        return tuple(headers)

    def assert_valid(self) -> None:
        """Refuse more hashes than BIP157 allows, and any of another width."""
        _assert_valid_type(self.filter_type)
        _assert_valid_hash(self.stop_hash, "stop_hash length")
        _assert_valid_hash(self.previous_filter_header, "previous_filter_header length")

        if len(self.filter_hashes) > MAX_GETCFHEADERS_SIZE:
            err_msg = f"invalid filter_hashes count: {len(self.filter_hashes)}"
            err_msg += f" instead of at most {MAX_GETCFHEADERS_SIZE}"
            raise BTClibValueError(err_msg)
        for filter_hash in self.filter_hashes:
            _assert_valid_hash(filter_hash, "filter hash length")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the type, the two hashes, then the count and the vector."""
        if check_validity:
            self.assert_valid()

        out = int(self.filter_type).to_bytes(_TYPE_SIZE, byteorder="little")
        out += self.stop_hash[::-1]
        out += self.previous_filter_header[::-1]
        out += var_int.serialize(len(self.filter_hashes))
        for filter_hash in self.filter_hashes:
            out += filter_hash[::-1]
        return out

    @classmethod
    def parse(
        cls: type[CFHeaders], data: BinaryData, *, check_validity: bool = True
    ) -> CFHeaders:
        """Return the hashes the payload carries, the count bounded first.

        BIP157's "FilterHashesLength MUST NOT be greater than 2,000",
        checked before the loop that allocates on it: the count is the
        peer's to choose and btclib's `var_int.parse` allows 33,554,432
        of anything.
        """
        stream = bytesio_from_binarydata(data)

        filter_type = read_exactly(stream, _TYPE_SIZE, "filter type")[0]
        stop_hash = read_exactly(stream, _HASH_SIZE, "stop hash")[::-1]
        previous = read_exactly(stream, _HASH_SIZE, "previous filter header")[::-1]

        count = var_int.parse(stream)
        if count > MAX_GETCFHEADERS_SIZE:
            err_msg = f"invalid filter_hashes count: {count}"
            err_msg += f" instead of at most {MAX_GETCFHEADERS_SIZE}"
            raise BTClibValueError(err_msg)
        filter_hashes = [
            read_exactly(stream, _HASH_SIZE, "filter hash")[::-1] for _ in range(count)
        ]
        assert_no_trailing(data, stream, "cfheaders payload")

        return cls(
            filter_type,
            stop_hash,
            previous,
            filter_hashes,
            check_validity=check_validity,
        )


@dataclass(frozen=True)
class GetCFCheckpt(Payload):
    """The `getcfcheckpt` message: the checkpoints up to a block.

    Bitcoin Core's `msg_getcfcheckpt`: a type code and a stop hash, and
    the one request of the three with no start height -- a checkpoint
    chain always begins at the genesis block, so what a client asks for
    is only where it ends.

    A class of its own rather than a third `_FilterRangeRequest`: two
    fields are not three, and a `start_height` here would be a field no
    message carries.

    Frozen and hashable, both fields being immutable.
    """

    command = "getcfcheckpt"

    filter_type: BlockFilterType | int
    stop_hash: bytes

    def __init__(
        self,
        filter_type: int = BlockFilterType.BASIC,
        stop_hash: Octets = b"\x00" * _HASH_SIZE,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "filter_type", _block_filter_type_from_int(filter_type)
        )
        object.__setattr__(self, "stop_hash", bytes_from_octets(stop_hash))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a type or a stop hash the fields cannot hold."""
        _assert_valid_type(self.filter_type)
        _assert_valid_hash(self.stop_hash, "stop_hash length")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the type code, then the stop hash."""
        if check_validity:
            self.assert_valid()

        out = int(self.filter_type).to_bytes(_TYPE_SIZE, byteorder="little")
        out += self.stop_hash[::-1]
        return out

    @classmethod
    def parse(
        cls: type[GetCFCheckpt], data: BinaryData, *, check_validity: bool = True
    ) -> GetCFCheckpt:
        """Return the chain end the payload asks the checkpoints of."""
        stream = bytesio_from_binarydata(data)

        filter_type = read_exactly(stream, _TYPE_SIZE, "filter type")[0]
        stop_hash = read_exactly(stream, _HASH_SIZE, "stop hash")[::-1]
        assert_no_trailing(data, stream, "getcfcheckpt payload")

        return cls(filter_type, stop_hash, check_validity=check_validity)


@dataclass(frozen=True)
class CFCheckpt(Payload):
    """The `cfcheckpt` message: a filter header every thousand blocks.

    Bitcoin Core's `msg_cfcheckpt`: the type code, the stop hash, and the
    vector of filter headers. These are headers and not hashes, so
    nothing is derived from them -- the contrast with `cfheaders` one
    class up, which sends the hashes so that the client does the
    chaining. `filter_headers` is the field here and the derivation
    there, which is the one name a caller wants off either message.

    `heights` is what BIP157 says the entries are of: "one entry for each
    block on the chain terminating in StopHash, where the block height is
    a multiple of 1,000 greater than 0".

    **No count bound**, where every other vector in this package has one:
    BIP157 bounds this one by the length of the chain and Core reads no
    `cfcheckpt` at all, so there is no constant to hold it to and none is
    invented. The module docstring has what stands in front of the loop
    instead.

    Frozen and hashable; `dataclasses.replace` is what changes the
    vector.
    """

    command = "cfcheckpt"

    filter_type: BlockFilterType | int
    stop_hash: bytes
    filter_headers: tuple[bytes, ...]

    def __init__(
        self,
        filter_type: int = BlockFilterType.BASIC,
        stop_hash: Octets = b"\x00" * _HASH_SIZE,
        filter_headers: Sequence[Octets] = (),
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "filter_type", _block_filter_type_from_int(filter_type)
        )
        object.__setattr__(self, "stop_hash", bytes_from_octets(stop_hash))
        object.__setattr__(
            self, "filter_headers", _hashes_of(filter_headers, "filter_headers")
        )

        if check_validity:
            self.assert_valid()

    @property
    def heights(self) -> list[int]:
        """Return the block height each filter header is that of.

        BIP157's rule read off the vector, `CFCHECKPT_INTERVAL` being
        Core's name for the thousand: the entries are in ascending order
        by height, so the first is the header of block 1,000 and the last
        is the highest multiple of a thousand at or below the height of
        the stop hash.
        """
        return [
            CFCHECKPT_INTERVAL * (index + 1)
            for index in range(len(self.filter_headers))
        ]

    def assert_valid(self) -> None:
        """Refuse a type, a stop hash, or a header of another width."""
        _assert_valid_type(self.filter_type)
        _assert_valid_hash(self.stop_hash, "stop_hash length")

        for header in self.filter_headers:
            _assert_valid_hash(header, "filter header length")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the type, the stop hash, then the count and the vector."""
        if check_validity:
            self.assert_valid()

        out = int(self.filter_type).to_bytes(_TYPE_SIZE, byteorder="little")
        out += self.stop_hash[::-1]
        out += var_int.serialize(len(self.filter_headers))
        for header in self.filter_headers:
            out += header[::-1]
        return out

    @classmethod
    def parse(
        cls: type[CFCheckpt], data: BinaryData, *, check_validity: bool = True
    ) -> CFCheckpt:
        """Return the checkpoint headers the payload carries."""
        stream = bytesio_from_binarydata(data)

        filter_type = read_exactly(stream, _TYPE_SIZE, "filter type")[0]
        stop_hash = read_exactly(stream, _HASH_SIZE, "stop hash")[::-1]

        count = var_int.parse(stream)
        filter_headers = [
            read_exactly(stream, _HASH_SIZE, "filter header")[::-1]
            for _ in range(count)
        ]
        assert_no_trailing(data, stream, "cfcheckpt payload")

        return cls(
            filter_type, stop_hash, filter_headers, check_validity=check_validity
        )
