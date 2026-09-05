# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.inventory` module.

**There is no captured message here, and this is where that is said.**
The envelope's tests and the address payload's are driven by messages the
Bitcoin Wiki's Protocol documentation publishes with their octets; that
page annotates a `version`, a `verack` and an `addr`, and none of the six
commands this module holds. Bitcoin Core publishes no vector file for
them either -- there is no `inv.json` to pin the way
`tests/_data/README.md` pins `siphash.json`. So what is below is btclib's
own round trips plus the vendored mainnet blocks, and nothing is claimed
to be more.

**What the vendored blocks decide is the one thing a round trip cannot:
which way round a hash goes on the wire.** A self-consistent serializer
reversing both directions agrees with itself, and would announce every
transaction and every block under a hash no peer recognizes. Two facts
outside this library settle it, and `tests/block/_data/block_1.bin` is
where they meet:

- the genesis block hash is
  `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`,
  which is what a node prints and what every explorer shows;
- block 1's header carries that hash as its parent, and those thirty-two
  octets of the file are `6fe28c0a...` -- the same hash the other way
  round, its leading zeros trailing.

So an `inv` announcing the genesis block must write those very octets,
and `Inventory.hash` must read them back as the string above. The
`getblocks` and `getheaders` locators are the same hashes and get the
same check.

**Those eighty octets authenticate themselves more strongly than a
captured message does.** A capture is pinned by the four-octet checksum
in its own header; a mainnet header is pinned by its proof of work, so
no other eighty octets hash below the target it declares.
`assert_valid_pow` is that check, run here, and `tests/_data/README.md`
records the height and hash of every block file this reads.

Everything else is a round trip, a refusal, or a reading of Core's
src/protocol.h, src/net_processing.h and
test/functional/test_framework/messages.py, whose revision `TF2.md`
pins.
"""

from __future__ import annotations

import enum
from dataclasses import FrozenInstanceError, replace
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from btclib import var_int
from btclib.block import BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import (
    GetBlocks,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    InventoryType,
    Message,
    NetworkAddress,
    NotFound,
)
from btclib.p2p.inventory import MSG_WITNESS_FLAG
from btclib.p2p.limits import MAX_HEADERS_RESULTS, MAX_INV_SZ, MAX_LOCATOR_SZ

# the vendored mainnet blocks, whose heights and hashes tests/_data/
# README.md records and whose first eighty octets are the header.
# tests/block/_data and not a second copy here: a block is a block, and
# the pin that covers it is the one already written
_BLOCK_DATA = Path(__file__).parent.parent / "block" / "_data"
_HEADER_1 = (_BLOCK_DATA / "block_1.bin").read_bytes()[:80]
_HEADER_170 = (_BLOCK_DATA / "block_170.bin").read_bytes()[:80]

# the genesis block hash and block 1's, the way a node prints them
_GENESIS = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
_BLOCK_1 = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"

_MAINNET = bytes.fromhex("f9beb4d9")


def _headers() -> Headers:
    """Return a `headers` message of the two vendored mainnet headers."""
    return Headers([BlockHeader.parse(_HEADER_1), BlockHeader.parse(_HEADER_170)])


def test_the_vendored_headers_authenticate_themselves() -> None:
    """Proof of work, which is a stronger pin than a capture's checksum.

    A captured message is authenticated by four octets of double SHA-256
    over its own payload, which anybody can recompute over anything. A
    mainnet header is authenticated by the work behind it: these eighty
    octets are the only ones anyone has found that hash below the target
    they declare, so a mistranscription of any field fails here.
    """
    header = BlockHeader.parse(_HEADER_1)
    header.assert_valid_pow()

    assert header.hash.hex() == _BLOCK_1
    assert header.previous_block_hash.hex() == _GENESIS
    assert header.serialize() == _HEADER_1

    BlockHeader.parse(_HEADER_170).assert_valid_pow()


def test_an_inventory_writes_the_hash_the_way_a_header_writes_one() -> None:
    """The trap a self-consistent round trip cannot see.

    An `inv` announcing the genesis block carries the thirty-two octets
    block 1's header carries for its parent. Reversed, it would carry the
    printed hash verbatim -- an announcement every peer would answer with
    a `notfound`, and one no round trip against this library's own
    serializer could tell from the right one.
    """
    # what the vendored file says: the octets and the printed hash are
    # each other reversed. Neither side of this comes from btclib
    assert bytes.fromhex(_GENESIS)[::-1] == _HEADER_1[4:36]

    item = Inventory(InventoryType.MSG_BLOCK, _GENESIS)
    assert item.hash.hex() == _GENESIS
    assert item.serialize()[4:] == _HEADER_1[4:36]

    # and the way back, which is the half a serializer alone leaves
    # untested
    assert Inventory.parse(item.serialize()).hash.hex() == _GENESIS
    assert Inventory.parse(item.serialize()) == item


def test_a_locator_writes_its_hashes_the_same_way() -> None:
    """The same octets, in the message that asks rather than announces."""
    for locator_message in (GetBlocks, GetHeaders):
        payload = locator_message(70016, [_GENESIS], _BLOCK_1).serialize()

        # the version, then the count, then the hash: the locator's one
        # entry is where the genesis block's octets are
        assert payload[:4] == bytes.fromhex("80110100")
        assert payload[4:5] == b"\x01"
        assert payload[5:37] == _HEADER_1[4:36]
        assert payload[37:] == bytes.fromhex(_BLOCK_1)[::-1]

        parsed = locator_message.parse(payload)
        assert parsed.locator[0].hex() == _GENESIS
        assert parsed.hash_stop.hex() == _BLOCK_1


def test_the_type_code_is_four_octets_little_endian() -> None:
    """Core's `READWRITE(obj.type, obj.hash)`, the type a `uint32_t`."""
    assert Inventory(InventoryType.MSG_TX).serialize()[:4] == bytes.fromhex("01000000")
    assert Inventory(InventoryType.MSG_WTX).serialize()[:4] == bytes.fromhex("05000000")
    # the witness bit is the high bit of the third octet's neighbour, so
    # a code carrying it is where a big-endian reading would be obvious
    witness_tx = Inventory(InventoryType.MSG_WITNESS_TX)
    assert witness_tx.serialize()[:4] == bytes.fromhex("01000040")


def test_the_codes_are_the_ones_protocol_h_defines() -> None:
    """`GetDataMsg`, value by value, and the composites Core names.

    `MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG` is not among them: BIP144
    reserved it, Core's line for it is commented out as unused, and a
    library naming it would publish a code the protocol has not got.
    """
    assert int(InventoryType.UNDEFINED) == 0
    assert int(InventoryType.MSG_TX) == 1
    assert int(InventoryType.MSG_BLOCK) == 2
    assert int(InventoryType.MSG_FILTERED_BLOCK) == 3
    assert int(InventoryType.MSG_CMPCT_BLOCK) == 4
    assert int(InventoryType.MSG_WTX) == 5

    assert MSG_WITNESS_FLAG == 1 << 30
    assert int(InventoryType.MSG_WITNESS_TX) == 0x40000001
    assert int(InventoryType.MSG_WITNESS_BLOCK) == 0x40000002
    assert not hasattr(InventoryType, "MSG_FILTERED_WITNESS_BLOCK")

    # the composites are what a caller writes, and the flag ORed in by
    # hand is the same value rather than a second spelling of it
    assert InventoryType.MSG_TX | MSG_WITNESS_FLAG == InventoryType.MSG_WITNESS_TX


def test_the_type_code_is_not_a_bitfield() -> None:
    """Why `ServiceFlags`' `IntFlag` does not transfer to this field.

    An `IntFlag` composes its members, and these do not compose: one
    through five are exclusive kinds, so `MSG_TX | MSG_CMPCT_BLOCK` is
    the *value* of `MSG_WTX` without being a witness transaction and a
    compact block at once. Under an `IntFlag` that arithmetic is the
    type's own -- `MSG_TX in InventoryType.MSG_WTX` would be true, and a
    `wtx` announcement would test as a `tx` one.
    """
    assert int(InventoryType.MSG_TX) | int(InventoryType.MSG_CMPCT_BLOCK) == int(
        InventoryType.MSG_WTX
    )
    assert issubclass(InventoryType, enum.IntEnum)
    assert not issubclass(InventoryType, enum.Flag)


def test_a_type_code_no_member_names_round_trips() -> None:
    """The envelope's rule about an unknown command, one layer down.

    An `IntEnum` refuses a value it has no member for, so an unnamed code
    is handed back as the plain integer it is rather than raising -- and
    the octets a peer sent come back as they arrived.
    """
    for code in (6, 0x7F, MSG_WITNESS_FLAG | 5, 0xFFFFFFFF):
        item = Inventory(code, _GENESIS)
        assert item.type_code == code
        assert not isinstance(item.type_code, InventoryType)
        assert Inventory.parse(item.serialize()) == item
        assert item.serialize()[:4] == code.to_bytes(4, "little")

    # and a code a member does name is that member, so the two spellings
    # are one object rather than two that compare equal
    assert isinstance(Inventory(2, _GENESIS).type_code, InventoryType)


def test_the_witness_bit_reads_as_a_bit() -> None:
    """`Inventory.is_witness`, and what it spares a caller.

    The alternative is comparing the code against `MSG_WITNESS_TX` and
    `MSG_WITNESS_BLOCK`, which is the same question asked in a way that
    is wrong the day a BIP names a third composite -- and wrong today for
    a code Core has not named at all.
    """
    assert Inventory(InventoryType.MSG_WITNESS_TX).is_witness
    assert Inventory(InventoryType.MSG_WITNESS_BLOCK).is_witness
    assert not Inventory(InventoryType.MSG_TX).is_witness
    assert not Inventory(InventoryType.MSG_WTX).is_witness
    assert not Inventory().is_witness

    # the composite Core does not name, which is where a comparison
    # against the two members answers wrongly and this does not
    assert Inventory(InventoryType.MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG).is_witness


def test_the_round_trip_of_every_message_here() -> None:
    """Each parses back to the object it was written from."""
    items = [
        Inventory(InventoryType.MSG_WTX, _GENESIS),
        Inventory(0x1234, _BLOCK_1),
    ]
    for vector_message in (Inv, GetData, NotFound):
        message = vector_message(items)
        assert vector_message.parse(message.serialize()) == message

        # the empty one, which is a message Core sends: a `notfound`
        # naming nothing, an `inv` with nothing to announce
        assert vector_message.parse(b"\x00") == vector_message()
        assert vector_message().serialize() == b"\x00"

    for locator_message in (GetBlocks, GetHeaders):
        asked = locator_message(70016, [_BLOCK_1, _GENESIS], _GENESIS)
        assert locator_message.parse(asked.serialize()) == asked

        # the locator Core sends for "everything you have": no entries
        # and a stop hash of zeros
        empty = locator_message()
        assert locator_message.parse(empty.serialize()) == empty
        assert empty.serialize() == bytes(4) + b"\x00" + bytes(32)

    headers = _headers()
    assert Headers.parse(headers.serialize()) == headers
    assert Headers.parse(b"\x00") == Headers()
    assert Headers().serialize() == b"\x00"


def test_the_command_each_class_travels_under() -> None:
    """`to_message` writes the command the class holds, once.

    One constant per class, read by both directions, is what keeps the
    name a payload serializes under and the name a caller matches on from
    drifting apart -- which is how btclib_node came to send `"sendcmpt"`
    and `"cmptblock"` to the whole network, both misspelled and neither
    compared with anything.
    """
    # `Any`, because `Payload` declares no `parse` and no two of these
    # answer with the same type: `tests/p2p/payload_test.py` reads the
    # asymmetry off the types the same way
    spellings: tuple[tuple[Any, str], ...] = (
        (Inv, "inv"),
        (GetData, "getdata"),
        (NotFound, "notfound"),
        (GetBlocks, "getblocks"),
        (GetHeaders, "getheaders"),
        (Headers, "headers"),
    )
    for payload_type, command in spellings:
        payload = payload_type()
        message = payload.to_message(_MAINNET)

        assert payload_type.command == command
        assert message.command == command
        assert message.magic == _MAINNET
        assert message.payload == payload.serialize()
        # and the way back, which is the caller's `if` and not a table
        assert payload_type.parse(Message.parse(message.serialize()).payload) == payload


def test_one_body_under_three_commands_is_three_types() -> None:
    """An `inv`, a `getdata` and a `notfound` of one vector are not one.

    The command is what tells them apart, so it is what the subclass sets
    -- a field holding it would let a caller build an `inv` that
    serializes under "getdata", and the generated `__eq__` compares the
    class before the fields.
    """
    items = [Inventory(InventoryType.MSG_TX, _GENESIS)]
    assert Inv(items).serialize() == GetData(items).serialize()
    assert GetBlocks(0, [_GENESIS]).serialize() == GetHeaders(0, [_GENESIS]).serialize()

    # `object`, so that the comparison is the one made at runtime: mypy
    # answers a `!=` between two classes it knows are different without
    # running it, which is a check of the annotations and not of `__eq__`
    inv: object = Inv(items)
    assert inv != GetData(items)
    assert inv != NotFound(items)
    get_blocks: object = GetBlocks(0, [_GENESIS])
    assert get_blocks != GetHeaders(0, [_GENESIS])


def test_headers_writes_the_transaction_count_core_ignores() -> None:
    """A zero after every header, and no field holding it.

    Core writes each header as a block with no transactions --
    `msg_headers.serialize` builds a `CBlock` per header for exactly that
    -- and reads the count back as `ReadCompactSize(vRecv); // ignore tx
    count; assume it is 0`.
    """
    assert _headers().serialize() == (
        b"\x02" + _HEADER_1 + b"\x00" + _HEADER_170 + b"\x00"
    )
    # eighty-one octets an entry, which is what says the zero is written
    # once per header and not once per message
    assert len(Headers([BlockHeader.parse(_HEADER_1)]).serialize()) == 1 + 80 + 1


def test_headers_refuses_a_transaction_count_that_is_not_zero() -> None:
    """What dropping the field costs, paid where it is cheapest.

    Core reads any count and throws it away, so it would accept these
    octets; this library would then hold a `headers` it could not write
    back, which is the malleability `Verack.parse` refuses a payload over
    and `Version.parse` refuses a relay flag of `0x02` over.
    """
    payload = b"\x01" + _HEADER_1 + b"\x01"
    with pytest.raises(BTClibValueError, match="invalid transaction count: 1"):
        Headers.parse(payload)

    # a non-canonical encoding of the zero needs no refusal of its own,
    # btclib's var_int being canonical-only already
    with pytest.raises(BTClibValueError, match="non-canonical var_int"):
        Headers.parse(b"\x01" + _HEADER_1 + b"\xfd\x00\x00")


def test_a_locator_version_is_ignored_by_core_and_stored_here() -> None:
    """The other ignored field, and why it is a field where the other is not.

    Core writes the protocol version it negotiated in front of a locator
    and discards what it reads; its test framework writes zero and says
    so. Ignored is not constant, so the field varies over messages
    peers really send -- where the `headers` transaction count does not
    vary at all, and is dropped for that reason.
    """
    for version in (0, 70016, 60002, -1, 0x7FFFFFFF, -0x80000000):
        asked = GetHeaders(version, [_GENESIS])
        assert GetHeaders.parse(asked.serialize()).version == version
        assert asked.serialize()[:4] == version.to_bytes(4, "little", signed=True)


def test_the_counts_are_bounded_before_anything_is_built() -> None:
    """The check that is the whole point of having one.

    A count is the peer's to choose and btclib's own `var_int.parse`
    allows 33,554,432 of anything, so a parser that builds first turns
    nine octets into as many objects. The refusal here reads the count
    and stops, with no payload behind it at all, and it does not answer
    to `check_validity`.
    """
    bounded = (
        (Inv, MAX_INV_SZ, "invalid items count", b""),
        (GetData, MAX_INV_SZ, "invalid items count", b""),
        (NotFound, MAX_INV_SZ, "invalid items count", b""),
        (Headers, MAX_HEADERS_RESULTS, "invalid headers count", b""),
        (GetBlocks, MAX_LOCATOR_SZ, "invalid locator count", bytes(4)),
        (GetHeaders, MAX_LOCATOR_SZ, "invalid locator count", bytes(4)),
    )
    for payload_type, cap, message, prefix in bounded:
        for check_validity in (True, False):
            for count in (cap + 1, var_int.MAX_SIZE):
                octets = prefix + var_int.serialize(count)
                with pytest.raises(BTClibValueError, match=message):
                    payload_type.parse(BytesIO(octets), check_validity=check_validity)

        # and the bound itself is a count this reads: what is refused at
        # the cap is the buffer and no longer the number
        octets = prefix + var_int.serialize(cap)
        with pytest.raises(BTClibValueError, match="not enough|invalid decoded length"):
            payload_type.parse(BytesIO(octets))


def test_more_entries_than_a_peer_accepts_are_refused() -> None:
    """The same bounds at the object boundary, where they do answer.

    Not the same check as the one in `parse`: this one is
    `check_validity`'s, and the one read off a count before anything is
    built is not.
    """
    item = Inventory(InventoryType.MSG_TX, _GENESIS)
    assert len(Inv([item] * MAX_INV_SZ).items) == MAX_INV_SZ
    with pytest.raises(BTClibValueError, match="invalid items count"):
        NotFound([item] * (MAX_INV_SZ + 1))

    header = BlockHeader.parse(_HEADER_1)
    assert len(Headers([header] * MAX_HEADERS_RESULTS).headers) == MAX_HEADERS_RESULTS
    with pytest.raises(BTClibValueError, match="invalid headers count"):
        Headers([header] * (MAX_HEADERS_RESULTS + 1))

    assert len(GetBlocks(0, [_GENESIS] * MAX_LOCATOR_SZ).locator) == MAX_LOCATOR_SZ
    with pytest.raises(BTClibValueError, match="invalid locator count"):
        GetHeaders(0, [_GENESIS] * (MAX_LOCATOR_SZ + 1))

    # and an object built past the bound is refused when it is written,
    # which is what `check_validity=False` postpones rather than waives
    too_many = Inv([item] * (MAX_INV_SZ + 1), check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid items count"):
        too_many.serialize()


def test_what_no_field_of_this_width_holds_is_refused() -> None:
    """`assert_valid` over every field, at the object boundary."""
    with pytest.raises(BTClibValueError, match="invalid type_code"):
        Inventory(-1, _GENESIS)
    with pytest.raises(BTClibValueError, match="invalid type_code"):
        Inventory(1 << 32, _GENESIS)
    with pytest.raises(BTClibValueError, match="invalid hash length"):
        Inventory(1, b"\x00" * 31)

    with pytest.raises(BTClibValueError, match="invalid version"):
        GetBlocks(1 << 31, [], _GENESIS)
    with pytest.raises(BTClibValueError, match="invalid version"):
        GetHeaders(-(1 << 31) - 1, [], _GENESIS)
    with pytest.raises(BTClibValueError, match="invalid locator hash length"):
        GetBlocks(0, [b"\x00" * 33])
    with pytest.raises(BTClibValueError, match="invalid hash_stop length"):
        GetHeaders(0, [], b"")

    # the widest value each field holds is a value, which is what says
    # the bound and not the field is what was refused
    assert Inventory(0xFFFFFFFF, _GENESIS).serialize()
    assert GetBlocks((1 << 31) - 1, [], _GENESIS).serialize()
    assert GetBlocks(-(1 << 31), [], _GENESIS).serialize()


def test_a_wrong_type_is_a_type_error() -> None:
    """A value of a type the signature does not declare, at every field."""
    with pytest.raises(BTClibTypeError, match="invalid type_code type"):
        Inventory(1.5, _GENESIS)  # type: ignore[arg-type]
    # a bool is an int and would read as MSG_TX or UNDEFINED, which the
    # range check cannot tell from a code whose value that is
    with pytest.raises(BTClibTypeError, match="invalid type_code type"):
        Inventory(True, _GENESIS)
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        Inventory(1, 1.5)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid version type"):
        GetBlocks(1.5, [], _GENESIS)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid version type"):
        GetHeaders(True, [], _GENESIS)

    # a str and a bytes are Sequences, so each argument is asked whole:
    # what fails must be the argument, not its first character
    for wrong in (1, _GENESIS, b"\x00" * 36):
        with pytest.raises(BTClibTypeError, match="invalid items type"):
            Inv(wrong)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid locator type"):
            GetBlocks(0, wrong)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid headers type"):
            Headers(wrong)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid item type"):
        GetData([NetworkAddress()])  # type: ignore[list-item]
    with pytest.raises(BTClibTypeError, match="invalid header type"):
        Headers([NetworkAddress()])  # type: ignore[list-item]


def test_the_octets_of_a_field_are_read_where_they_end() -> None:
    """Every truncation is refused, and the field names itself."""
    item = Inventory(InventoryType.MSG_TX, _GENESIS).serialize()
    with pytest.raises(BTClibValueError, match="inventory type code"):
        Inventory.parse(item[:3])
    with pytest.raises(BTClibValueError, match="inventory hash"):
        Inventory.parse(item[:20])

    asked = GetHeaders(70016, [_GENESIS], _BLOCK_1).serialize()
    with pytest.raises(BTClibValueError, match="locator protocol version"):
        GetHeaders.parse(asked[:3])
    with pytest.raises(BTClibValueError, match="locator hash"):
        GetHeaders.parse(asked[:20])
    with pytest.raises(BTClibValueError, match="hash_stop"):
        GetHeaders.parse(asked[:50])

    with pytest.raises(BTClibValueError, match="inventory hash"):
        Inv.parse(b"\x01" + item[:20])
    with pytest.raises(BTClibValueError, match="invalid decoded length"):
        Headers.parse(b"\x01" + _HEADER_1[:40])


def test_a_stream_is_read_one_entry_at_a_time() -> None:
    """What the vector parsers rest on: each structure leaves the rest alone."""
    first = Inventory(InventoryType.MSG_TX, _GENESIS)
    second = Inventory(InventoryType.MSG_BLOCK, _BLOCK_1)
    stream = BytesIO(first.serialize() + second.serialize() + b"junk")

    assert Inventory.parse(stream) == first
    assert Inventory.parse(stream) == second
    assert stream.read() == b"junk"

    # and a whole payload does the same, which is how a caller reading a
    # stream of messages takes them one at a time
    stream = BytesIO(Inv([first]).serialize() + _headers().serialize())
    assert Inv.parse(stream) == Inv([first])
    assert Headers.parse(stream) == _headers()
    assert not stream.read()


def test_octets_after_a_payload_are_refused() -> None:
    """Octets are one whole object, and the message names itself."""
    with pytest.raises(BTClibValueError, match="bytes after the inv payload"):
        Inv.parse(Inv().serialize() + b"\x00")
    with pytest.raises(BTClibValueError, match="bytes after the getdata payload"):
        GetData.parse(GetData().serialize() + b"\x00")
    with pytest.raises(BTClibValueError, match="bytes after the notfound payload"):
        NotFound.parse(NotFound().serialize() + b"\x00")
    with pytest.raises(BTClibValueError, match="bytes after the getblocks payload"):
        GetBlocks.parse(GetBlocks().serialize() + b"\x00")
    with pytest.raises(BTClibValueError, match="bytes after the getheaders payload"):
        GetHeaders.parse(GetHeaders().serialize() + b"\x00")
    with pytest.raises(BTClibValueError, match="bytes after the headers payload"):
        Headers.parse(Headers().serialize() + b"\x00")
    with pytest.raises(BTClibValueError, match="bytes after the inventory entry"):
        Inventory.parse(Inventory().serialize() + b"\x00")


def test_the_defaults_are_the_message_that_asks_for_everything() -> None:
    """What a caller writes where the protocol's own default is wanted."""
    assert Inventory() == Inventory(InventoryType.UNDEFINED, bytes(32))
    assert Inventory().serialize() == bytes(36)
    assert Inv() == Inv(())
    assert GetBlocks() == GetBlocks(0, (), bytes(32))
    assert Headers() == Headers(())

    # a locator with a stop hash of zeros is "as many as you will give
    # me", which is Core's own default for the field
    assert GetHeaders().hash_stop == bytes(32)


def test_frozen() -> None:
    """Refuse assignment to any field: a message is a value."""
    item = Inventory(InventoryType.MSG_TX, _GENESIS)

    with pytest.raises(FrozenInstanceError):
        item.hash = b""  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        Inv([item]).items = ()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        GetBlocks().version = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        Headers().headers = ()  # type: ignore[misc]

    assert replace(item, hash=bytes.fromhex(_BLOCK_1)) == Inventory(
        InventoryType.MSG_TX, _BLOCK_1
    )
    assert replace(Inv([item]), items=()) == Inv()

    # an entry is hashable, being what a set of announcements holds; a
    # `headers` is not, `BlockHeader` being a mutable dataclass
    assert len({item, Inventory(InventoryType.MSG_TX, _GENESIS)}) == 1
    with pytest.raises(TypeError, match="unhashable"):
        hash(_headers())


def test_the_sequence_fields_are_tuples() -> None:
    """So that a frozen message is what its fields say it is."""
    item = Inventory(InventoryType.MSG_TX, _GENESIS)
    assert Inv([item]).items == (item,)
    assert Inv((item,)) == Inv([item])
    assert GetBlocks(0, [_GENESIS]).locator == (bytes.fromhex(_GENESIS),)
    assert Headers([BlockHeader.parse(_HEADER_1)]).headers == (
        BlockHeader.parse(_HEADER_1),
    )
