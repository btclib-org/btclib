# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.block_filters` module.

**What stands as authority for the wire form, said plainly.** Nobody
publishes a captured BIP157 message: the Bitcoin Wiki's Protocol page
annotates a `version`, a `verack` and an `addr` and none of these six,
and Bitcoin Core has no vector file for them. The wire form here is
BIP157's own field tables and the writer Core reads them back with,
test/functional/test_framework/messages.py's `msg_cfilter` and its five
neighbours, and the octets below were assembled from those tables rather
than captured from anything.

**What is vendored is the other half of the message, and it is real.**
`tests/block/_data/blockfilters.json` is Core's BIP158 vector file, pinned
by `tests/_data/README.md` and already read whole by
`tests/block/blockfilters_test.py`: ten testnet blocks with, per row,
the serialized basic filter, the previous filter header and the basic
filter header. Those are exactly the fields a `cfilter`, a `cfheaders`
and a `cfcheckpt` carry, so every filter, hash and header below is a
value Core computed. Nothing is vendored a second time.

**The vector file is what decides the seam, not a round trip.** A
`cfilter` carries the block hash beside the filter, and that hash is the
SipHash key the filter was built under: read it the wrong way round and
`basic_filter` still answers with an object, still round-trips, and
matches nothing the block touches. So the match test below queries each
row's filter through the payload for the scripts Core's row holds -- the
check that fails if the thirty-two octets are reversed, and the one no
self-consistent serializer can pass by agreeing with itself.

The filter hashes and filter headers of `cfheaders` and `cfcheckpt` are
written the same way, `ser_uint256`, and nothing outside this library
pins their order: what is cited for them is that Core writes every one of
these vectors with that one function.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
from typing import Any

import pytest

from btclib import var_int
from btclib.block import BasicBlockFilter, Block
from btclib.block.block_filter import filter_header
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import (
    BlockFilterType,
    CFCheckpt,
    CFHeaders,
    CFilter,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
    Message,
)
from btclib.p2p.limits import (
    CFCHECKPT_INTERVAL,
    MAX_GETCFHEADERS_SIZE,
    MAX_GETCFILTERS_SIZE,
)
from tests import load, vector_id

_MAINNET = bytes.fromhex("f9beb4d9")

# an unnamed filter type: BIP158 defines the zero and nothing else, and
# BIP157 leaves what to do with the rest to the node rather than to the
# parser
_UNKNOWN_TYPE = 0x2A

_HEADER_ROW = 1  # the column names, which `blockfilters_test.py` also drops


def _rows() -> list[Any]:
    """Return Core's BIP158 vector rows, the column-name row dropped."""
    rows: list[Any] = load("block", "_data", "blockfilters.json")
    return rows[_HEADER_ROW:]


def filter_params() -> list[Any]:
    """Return one pytest.param per row: height, block, filter, header pair.

    Columns 0, 2, 3, 4, 5 and 6 of the file -- the height, the serialized
    block, the previous output scripts, the previous filter header, the
    serialized basic filter and the basic filter header -- labelled as
    `blockfilters_test.py` labels them, by height and by Core's note.
    """
    return [
        pytest.param(
            row[0], row[2], row[3], row[4], row[5], row[6], id=vector_id(row[0], row[7])
        )
        for row in _rows()
    ]


def _first_row() -> Any:
    """Return the genesis row, whose previous filter header is the zeros."""
    return _rows()[0]


def _genesis_cfilter() -> CFilter:
    """Return the `cfilter` of the genesis block, from Core's own columns."""
    row = _first_row()
    block = Block.parse(row[2])
    return CFilter(BlockFilterType.BASIC, block.header.hash, bytes.fromhex(row[5]))


@pytest.mark.parametrize(
    "height, serialization, prevout_scripts, previous_header, basic_filter, basic_header",
    filter_params(),
)
def test_a_cfilter_carries_the_filter_core_computed(
    height: int,
    serialization: str,
    prevout_scripts: list[str],
    previous_header: str,
    basic_filter: str,
    basic_header: str,
) -> None:
    """Each row's filter, put in a `cfilter` and taken back out.

    `basic_filter` is the typed reading, and it takes no argument: the
    block hash arrived in the message, ahead of the filter octets, which
    is the whole of the seam. What comes back is the filter Core states,
    equal to the one `BasicBlockFilter.parse` gives when handed the same
    two things by hand.
    """
    block = Block.parse(serialization)
    payload = CFilter(BlockFilterType.BASIC, block.header.hash, basic_filter)

    assert payload.filter_bytes.hex() == basic_filter
    assert payload.basic_filter == BasicBlockFilter.parse(
        basic_filter, block.header.hash
    )
    assert payload.basic_filter.serialize().hex() == basic_filter

    octets = payload.serialize()
    assert CFilter.parse(octets) == payload
    assert octets == bytes([BlockFilterType.BASIC]) + block.header.hash[::-1] + (
        var_int.serialize(len(payload.filter_bytes)) + payload.filter_bytes
    )


@pytest.mark.parametrize(
    "height, serialization, prevout_scripts, previous_header, basic_filter, basic_header",
    filter_params(),
)
def test_a_cfilter_matches_what_its_block_touches(
    height: int,
    serialization: str,
    prevout_scripts: list[str],
    previous_header: str,
    basic_filter: str,
    basic_header: str,
) -> None:
    """The check a reversed block hash fails and a round trip does not.

    The hash is the SipHash key, so a `cfilter` whose thirty-two octets
    were read the wrong way round yields a filter that decodes,
    serializes back and answers False to every script its block holds.
    Reading the filter off the parsed message and querying it for the
    scripts Core's row states is what tells the two apart.
    """
    block = Block.parse(serialization)
    payload = CFilter(BlockFilterType.BASIC, block.header.hash, basic_filter)
    parsed = CFilter.parse(payload.serialize())

    scripts = [
        out.script_pub_key.script for tx in block.transactions for out in tx.vout
    ]
    scripts += [bytes.fromhex(script) for script in prevout_scripts]
    included = [s for s in scripts if s and not s.startswith(b"\x6a")]

    block_filter = parsed.basic_filter
    for script in included:
        assert block_filter.match(script)
    assert block_filter.match_any(included) == bool(included)


@pytest.mark.parametrize(
    "height, serialization, prevout_scripts, previous_header, basic_filter, basic_header",
    filter_params(),
)
def test_a_cfheaders_derives_the_header_core_states(
    height: int,
    serialization: str,
    prevout_scripts: list[str],
    previous_header: str,
    basic_filter: str,
    basic_header: str,
) -> None:
    """The hashes are the field and the headers are the derivation.

    Each row gives a previous filter header and the header chained onto
    it, which is a `cfheaders` of one entry: the filter hash goes in, and
    the header Core states comes out of `filter_headers`. Nothing here is
    btclib compared with itself -- the answer is the row's.
    """
    block = Block.parse(serialization)
    block_filter = BasicBlockFilter.parse(basic_filter, block.header.hash)
    payload = CFHeaders(
        BlockFilterType.BASIC,
        block.header.hash,
        previous_header,
        [block_filter.hash],
    )

    assert [header.hex() for header in payload.filter_headers] == [basic_header]
    assert CFHeaders.parse(payload.serialize()) == payload


def test_the_cfheaders_derivation_feeds_each_header_into_the_next() -> None:
    """The fold, which a message of one entry cannot exercise.

    Core's rows are ten blocks of no particular adjacency -- heights 0,
    2, 3, 15007 and on -- so the file is not a chain and cannot be read
    as one: each row pins one step, and what is left to check is that the
    step after it starts from the answer of the first rather than from
    the field again. Only the first header below is Core's; the rest is
    this library composing that step with itself, and saying so is the
    point.
    """
    row = _first_row()
    block_filter = BasicBlockFilter.parse(row[5], Block.parse(row[2]).header.hash)
    hashes = [block_filter.hash, b"\x07" * 32, b"\x09" * 32]

    payload = CFHeaders(BlockFilterType.BASIC, bytes(32), row[4], hashes)
    headers = payload.filter_headers

    assert headers[0].hex() == row[6]
    assert headers[1] == filter_header(hashes[1], headers[0])
    assert headers[2] == filter_header(hashes[2], headers[1])
    assert len(headers) == len(hashes)

    # and an empty vector derives nothing rather than the field itself
    assert CFHeaders(BlockFilterType.BASIC, bytes(32), row[4]).filter_headers == ()


def test_a_cfcheckpt_stores_headers_and_names_their_heights() -> None:
    """What `cfcheckpt` carries is headers, so nothing is derived from them.

    The contrast with `cfheaders` one class up, and the reason `heights`
    is offered instead: BIP157 puts one entry at every block height that
    is a multiple of a thousand, so the position in the vector says which
    block an entry is of and nothing else does. The entries here are the
    filter headers of Core's rows, which are real headers and not a real
    checkpoint chain -- the file's heights are 0, 2, 3 and on, so what
    they stand in for is thirty-two octets each.
    """
    rows = _rows()
    headers = [bytes.fromhex(row[6]) for row in rows]
    payload = CFCheckpt(
        BlockFilterType.BASIC, Block.parse(rows[-1][2]).header.hash, headers
    )

    assert payload.filter_headers == tuple(headers)
    assert payload.heights == [
        CFCHECKPT_INTERVAL * i for i in range(1, len(headers) + 1)
    ]
    assert payload.heights[0] == CFCHECKPT_INTERVAL
    assert CFCheckpt.parse(payload.serialize()) == payload

    assert CFCheckpt().heights == []


def test_the_wire_layout_is_bip157s_field_table() -> None:
    """Each message's octets, field by field, as BIP157 tabulates them.

    Assembled from the tables and not captured, which the module
    docstring says: the type code is one octet, a height is four
    little-endian, a hash is thirty-two written in the internal order,
    and a vector is a `CompactSize` count in front of its entries.
    """
    stop = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000123"
    )
    previous = bytes.fromhex(
        "00000000000000000000000000000000000000000000000000000000000004a1"
    )

    assert GetCFilters(BlockFilterType.BASIC, 1, stop).serialize() == (
        b"\x00" + b"\x01\x00\x00\x00" + stop[::-1]
    )
    assert GetCFHeaders(BlockFilterType.BASIC, 1, stop).serialize() == (
        b"\x00" + b"\x01\x00\x00\x00" + stop[::-1]
    )
    assert GetCFCheckpt(BlockFilterType.BASIC, stop).serialize() == b"\x00" + stop[::-1]
    assert CFilter(BlockFilterType.BASIC, stop, b"\xff").serialize() == (
        b"\x00" + stop[::-1] + b"\x01\xff"
    )
    assert CFHeaders(BlockFilterType.BASIC, stop, previous, [stop]).serialize() == (
        b"\x00" + stop[::-1] + previous[::-1] + b"\x01" + stop[::-1]
    )
    assert CFCheckpt(BlockFilterType.BASIC, stop, [previous]).serialize() == (
        b"\x00" + stop[::-1] + b"\x01" + previous[::-1]
    )


def test_getcfilters_and_getcfheaders_are_one_body_under_two_commands() -> None:
    """The two requests BIP157 tabulates with the same three rows.

    A subclass each rather than a command field, which is
    `keepalive._NoncePayload`'s argument: the generated `__eq__` compares
    the class, so the same range asked two ways stays two messages.
    """
    stop = b"\x11" * 32
    asked = GetCFilters(BlockFilterType.BASIC, 7, stop)
    other = GetCFHeaders(BlockFilterType.BASIC, 7, stop)

    assert asked.serialize() == other.serialize()
    # through `object`, because mypy refuses the direct comparison as
    # non-overlapping -- which is the property being asserted, said
    # statically; what runs here is the runtime half of it
    either: object = asked
    assert either != other
    assert asked.command == "getcfilters"
    assert other.command == "getcfheaders"
    assert type(GetCFilters.parse(asked.serialize())) is GetCFilters
    assert type(GetCFHeaders.parse(other.serialize())) is GetCFHeaders


def test_an_unknown_filter_type_round_trips_as_an_integer() -> None:
    """BIP157's rule is about answering, so the parser reads what it is sent.

    "Nodes receiving `getcfilters` with an unsupported filter type SHOULD
    NOT respond" can only be obeyed by something that has read the
    message, and Core reads the three requests that way: the octet is
    cast to `BlockFilterType` and `PrepareBlockFilterRequest` disconnects
    the peer afterwards. Its `BlockFilter::Unserialize` refuses one
    instead, because it builds the Golomb parameters as it reads -- which
    is what `basic_filter` defers, and what lets a `cfilter` of any type
    be held here.
    """
    for payload in (
        GetCFilters(_UNKNOWN_TYPE),
        GetCFHeaders(_UNKNOWN_TYPE),
        GetCFCheckpt(_UNKNOWN_TYPE),
        CFilter(_UNKNOWN_TYPE),
        CFHeaders(_UNKNOWN_TYPE),
        CFCheckpt(_UNKNOWN_TYPE),
    ):
        assert payload.filter_type == _UNKNOWN_TYPE
        assert not isinstance(payload.filter_type, BlockFilterType)
        octets = payload.serialize()
        assert octets[0] == _UNKNOWN_TYPE
        assert type(payload).parse(octets) == payload

    # and the code BIP158 does define is the member, not the integer
    assert CFilter(0).filter_type is BlockFilterType.BASIC
    assert int(BlockFilterType.BASIC) == 0


def test_the_table_names_the_one_code_bip158_defines() -> None:
    """`INVALID = 255` is Core's sentinel and is not a wire code.

    It is what `BlockFilter::m_filter_type` is initialized to and the one
    case `BuildParams` answers false for: a filter with no type rather
    than a type a peer sends, so naming it here would publish a code the
    protocol has not got.
    """
    assert [member.name for member in BlockFilterType] == ["BASIC"]
    assert 255 not in set(BlockFilterType)
    assert CFilter(255).filter_type == 255


def test_a_bool_is_not_a_filter_type() -> None:
    """`BlockFilterType(False)` is `BASIC`, which is what the refusal is for.

    A bool is an int, so a flag arriving where a code was meant would be
    coerced into the member whose value it has and pass every check after
    it. `is_integer` is the predicate every integer field of this library
    is held to, and the coercion hands a bool back untouched for it.
    """
    with pytest.raises(BTClibTypeError, match="invalid filter_type type: bool"):
        CFilter(True)
    with pytest.raises(BTClibTypeError, match="invalid filter_type type: bool"):
        GetCFCheckpt(False)


def test_a_filter_type_wider_than_an_octet_is_refused() -> None:
    """One octet, BIP157's own width for the field."""
    with pytest.raises(BTClibValueError, match="invalid filter_type: 256"):
        CFHeaders(256)
    with pytest.raises(BTClibValueError, match="invalid filter_type: -1"):
        CFCheckpt(-1)


def test_the_basic_reading_is_refused_for_any_other_type() -> None:
    """`basic_filter` is where a caller says the code is `BASIC`.

    BIP157: "Each type is identified by a one byte code, and specifies
    the contents and serialization format of the filter". Octets under a
    code nobody has defined are not a BIP158 filter, so reading them as
    one would be inventing an answer.
    """
    octets = _genesis_cfilter().filter_bytes
    payload = CFilter(_UNKNOWN_TYPE, b"\x11" * 32, octets)

    with pytest.raises(BTClibValueError, match="invalid filter_type for a basic"):
        _ = payload.basic_filter

    # the same octets under the code BIP158 defines are a filter
    keyed = CFilter(BlockFilterType.BASIC, b"\x11" * 32, octets).basic_filter
    assert keyed.serialize() == octets


def test_a_cfilter_of_any_type_parses_and_serializes_back() -> None:
    """`assert_valid` does not decode the filter, whatever the code says.

    Refusing a malformed Golomb stream here would make the same octets
    parse under a type nobody has defined and fail under the one that is
    defined, and the octets round-trip either way. `basic_filter` is
    where they are read, and where the refusal is.
    """
    # a var_int of two elements with no set behind them: the count says
    # more than the bits can hold
    truncated = b"\x02"
    for filter_type in (BlockFilterType.BASIC, _UNKNOWN_TYPE):
        payload = CFilter(filter_type, b"\x22" * 32, truncated)
        assert CFilter.parse(payload.serialize()) == payload
        assert payload.filter_bytes == truncated

    with pytest.raises(BTClibValueError, match="not enough binary data"):
        _ = CFilter(BlockFilterType.BASIC, b"\x22" * 32, truncated).basic_filter


def test_a_cfilter_cannot_be_told_its_filter_is_not_its_blocks() -> None:
    """A block hash is a key, not a commitment, and this is where that is said.

    The genesis filter under another block's hash decodes, round-trips
    and answers False to every script the genesis block touches. Nothing
    in the message settles it: what does is the block, or the header
    chain a `cfheaders` carries, and both are the caller's.
    """
    row = _first_row()
    genesis = Block.parse(row[2])
    other = Block.parse(_rows()[1][2])

    wrong = CFilter(BlockFilterType.BASIC, other.header.hash, row[5])
    assert CFilter.parse(wrong.serialize()) == wrong

    script = genesis.transactions[0].vout[0].script_pub_key.script
    assert _genesis_cfilter().basic_filter.match(script)
    assert not wrong.basic_filter.match(script)


def test_the_cfheaders_count_is_bounded_before_the_loop() -> None:
    """BIP157's "FilterHashesLength MUST NOT be greater than 2,000".

    Read off the payload before the vector is built, which is what a
    bound is for: the count is the peer's to choose, and btclib's
    `var_int.parse` allows 33,554,432 of anything.
    """
    too_many = var_int.serialize(MAX_GETCFHEADERS_SIZE + 1)
    payload = b"\x00" + bytes(32) + bytes(32) + too_many
    with pytest.raises(BTClibValueError, match="invalid filter_hashes count: 2001"):
        CFHeaders.parse(payload)

    with pytest.raises(BTClibValueError, match="invalid filter_hashes count: 2001"):
        CFHeaders(0, bytes(32), bytes(32), [bytes(32)] * (MAX_GETCFHEADERS_SIZE + 1))

    # and the bound itself is a message this parses
    at_the_bound = CFHeaders(
        0, bytes(32), bytes(32), [bytes(32)] * MAX_GETCFHEADERS_SIZE
    )
    assert len(CFHeaders.parse(at_the_bound.serialize()).filter_hashes) == (
        MAX_GETCFHEADERS_SIZE
    )


def test_the_cfcheckpt_vector_is_bounded_by_the_octets_and_by_nothing_else() -> None:
    """No constant, because BIP157 bounds it by the length of the chain.

    A count larger than the octets is refused by the first entry that
    runs past the end, so the vector cannot outgrow the payload -- and
    the payload is `MAX_PROTOCOL_MESSAGE_LENGTH`, the envelope's.
    """
    payload = b"\x00" + bytes(32) + var_int.serialize(1000) + bytes(32)
    with pytest.raises(BTClibValueError, match="not enough data for the filter header"):
        CFCheckpt.parse(payload)


def test_a_range_bound_needs_a_chain_and_is_therefore_not_checked() -> None:
    """BIP157 bounds a range whose far end is a hash, which is not a height.

    So `MAX_GETCFILTERS_SIZE` and `MAX_GETCFHEADERS_SIZE` are published
    for the caller holding the chain and checked nowhere here: a
    `getcfilters` naming any start height is a message this parses, the
    number of blocks it covers being unknowable from the octets.
    """
    assert (MAX_GETCFILTERS_SIZE, MAX_GETCFHEADERS_SIZE) == (1000, 2000)

    huge = GetCFilters(BlockFilterType.BASIC, 0xFFFFFFFF, b"\x33" * 32)
    assert GetCFilters.parse(huge.serialize()) == huge
    assert GetCFHeaders(BlockFilterType.BASIC, 0xFFFFFFFF, b"\x33" * 32).start_height


def test_a_start_height_is_four_unsigned_octets() -> None:
    """Core reads StartHeight into a `uint32_t`, so neither sign nor a fifth."""
    with pytest.raises(BTClibValueError, match="invalid start_height: 4294967296"):
        GetCFilters(BlockFilterType.BASIC, 1 << 32)
    with pytest.raises(BTClibValueError, match="invalid start_height: -1"):
        GetCFHeaders(BlockFilterType.BASIC, -1)
    with pytest.raises(BTClibTypeError, match="invalid start_height type: bool"):
        GetCFilters(BlockFilterType.BASIC, True)


def test_a_hash_of_another_width_is_refused() -> None:
    """Every hash field is the thirty-two octets of a hash256."""
    with pytest.raises(BTClibValueError, match="invalid stop_hash length: 31 bytes"):
        GetCFilters(BlockFilterType.BASIC, 0, bytes(31))
    with pytest.raises(BTClibValueError, match="invalid block_hash length: 33 bytes"):
        CFilter(BlockFilterType.BASIC, bytes(33))
    with pytest.raises(BTClibValueError, match="invalid stop_hash length: 1 bytes"):
        GetCFCheckpt(BlockFilterType.BASIC, bytes(1))
    with pytest.raises(
        BTClibValueError, match="invalid previous_filter_header length: 2 bytes"
    ):
        CFHeaders(BlockFilterType.BASIC, bytes(32), bytes(2))
    with pytest.raises(BTClibValueError, match="invalid filter hash length: 4 bytes"):
        CFHeaders(BlockFilterType.BASIC, bytes(32), bytes(32), [bytes(4)])
    with pytest.raises(BTClibValueError, match="invalid filter header length: 4 bytes"):
        CFCheckpt(BlockFilterType.BASIC, bytes(32), [bytes(4)])


def test_a_vector_field_is_asked_for_whole() -> None:
    """A str and a bytes are Sequences, and neither is a vector of hashes.

    Passing one hash where the vector was meant would zip through its
    octets and refuse the first of them by width, complaining about
    something the caller never wrote.
    """
    with pytest.raises(BTClibTypeError, match="invalid filter_hashes type: bytes"):
        CFHeaders(BlockFilterType.BASIC, bytes(32), bytes(32), bytes(32))  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid filter_headers type: str"):
        CFCheckpt(BlockFilterType.BASIC, bytes(32), "00" * 32)
    with pytest.raises(BTClibTypeError, match="invalid filter_headers type: int"):
        CFCheckpt(BlockFilterType.BASIC, bytes(32), 1)  # type: ignore[arg-type]


def test_the_filter_octets_are_asked_for_their_type() -> None:
    """`filter_bytes` is octets, and what is no octets is refused by name."""
    with pytest.raises(BTClibTypeError, match="invalid octets type: int"):
        CFilter(BlockFilterType.BASIC, bytes(32), 1)  # type: ignore[arg-type]


def test_a_truncated_payload_is_refused_at_the_field_it_stops_in() -> None:
    """A short read is truncation, named by the field it fell in."""
    with pytest.raises(BTClibValueError, match="not enough data for the filter type"):
        GetCFilters.parse(b"")
    with pytest.raises(BTClibValueError, match="not enough data for the start height"):
        GetCFilters.parse(b"\x00\x01")
    with pytest.raises(BTClibValueError, match="not enough data for the stop hash"):
        GetCFHeaders.parse(b"\x00" + bytes(4) + bytes(31))
    with pytest.raises(BTClibValueError, match="not enough data for the stop hash"):
        GetCFCheckpt.parse(b"\x00" + bytes(31))
    with pytest.raises(BTClibValueError, match="not enough data for the block hash"):
        CFilter.parse(b"\x00" + bytes(31))
    with pytest.raises(
        BTClibValueError, match="not enough data for the previous filter header"
    ):
        CFHeaders.parse(b"\x00" + bytes(32) + bytes(31))
    with pytest.raises(BTClibValueError, match="not enough data for the filter hash"):
        CFHeaders.parse(b"\x00" + bytes(32) + bytes(32) + b"\x01" + bytes(31))


def test_trailing_octets_are_refused_but_a_stream_is_not() -> None:
    """What follows a whole payload in a buffer is malleability.

    A caller's stream is the other case and nothing is checked there,
    which is `utils.assert_no_trailing`'s split and Core's between
    `Unserialize` and "extra data after PSBT".
    """
    for payload in (
        GetCFilters(),
        GetCFHeaders(),
        GetCFCheckpt(),
        CFilter(),
        CFHeaders(),
        CFCheckpt(),
    ):
        octets = payload.serialize()
        cls: Any = type(payload)
        with pytest.raises(BTClibValueError, match="payload"):
            cls.parse(octets + b"\x00")

        stream = BytesIO(octets + b"\xff")
        assert cls.parse(stream) == payload
        assert stream.read() == b"\xff"


def test_every_message_goes_through_the_envelope_under_its_own_command() -> None:
    """The six commands, each written by the class that carries it."""
    commands = []
    for payload in (
        GetCFilters(),
        CFilter(),
        GetCFHeaders(),
        CFHeaders(),
        GetCFCheckpt(),
        CFCheckpt(),
    ):
        message = payload.to_message(_MAINNET)
        commands.append(message.command)
        assert Message.parse(message.serialize()) == message
        cls: Any = type(payload)
        assert cls.parse(message.payload) == payload

    assert commands == [
        "getcfilters",
        "cfilter",
        "getcfheaders",
        "cfheaders",
        "getcfcheckpt",
        "cfcheckpt",
    ]


def test_a_payload_is_frozen_and_a_replacement_is_a_new_one() -> None:
    """Frozen and hashable, which holding the filter as octets is what buys.

    A `BasicBlockFilter` is a mutable dataclass, so a `cfilter` holding
    one could not be hashed; these six hold octets and integers, and a
    set of them is what a caller collecting answers from peers has.
    """
    payload = _genesis_cfilter()
    with pytest.raises(FrozenInstanceError):
        payload.filter_type = 1  # type: ignore[misc]

    assert len({payload, _genesis_cfilter()}) == 1
    assert replace(payload, filter_type=_UNKNOWN_TYPE).filter_bytes == (
        payload.filter_bytes
    )
    assert len({CFHeaders(), CFCheckpt(), GetCFCheckpt()}) == 3


def test_check_validity_is_the_only_thing_the_flag_turns_off() -> None:
    """A field the checks would refuse, built and written without them.

    The flag reaches `serialize` and `parse` the same way it does
    everywhere in this library, and what it does not reach is a field
    boundary: `read_exactly` measures one whatever the flag says.
    """
    payload = CFilter(0, bytes(32), b"", check_validity=False)
    assert payload.serialize(check_validity=False) == b"\x00" + bytes(32) + b"\x00"

    wide = CFHeaders(1 << 20, bytes(32), bytes(32), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid filter_type: 1048576"):
        wide.assert_valid()


def test_the_filter_header_derivation_is_one_function() -> None:
    """`BasicBlockFilter.header` and `CFHeaders.filter_headers` are one step.

    BIP157 defines a filter header over a filter *hash*, which is what a
    `cfheaders` carries and what `block_filter.filter_header` takes; the
    method is that function over a filter that is at hand.
    """
    row = _first_row()
    block_filter = BasicBlockFilter.parse(row[5], Block.parse(row[2]).header.hash)

    assert block_filter.header(row[4]) == filter_header(block_filter.hash, row[4])
    assert filter_header(block_filter.hash, row[4]).hex() == row[6]

    with pytest.raises(BTClibValueError, match="invalid size"):
        filter_header(bytes(31), bytes(32))
