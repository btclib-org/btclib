# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.p2p.payload`, which is a decision rather than a codec.

Nothing here reads octets Bitcoin Core wrote: the module holds no wire
format, only the shape every payload type of this package has and the one
line that puts one in an envelope. What these tests hold is that the
shape is uniform -- that every payload type this package has answers
`command`, `serialize` and `to_message` the same way -- so that the
payload types still to come (issue #1083) have something to be uniform
with.

The walk is over `Payload.__subclasses__` rather than a list, which is
what makes it a promise: a payload type added to this package and given a
command nobody wrote down fails here rather than being held to nothing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from btclib.block import Block
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.p2p import (
    Addr,
    AddrV2,
    BlockFilterType,
    BlockPayload,
    BlockTxn,
    CFCheckpt,
    CFHeaders,
    CFilter,
    CmpctBlock,
    FeeFilter,
    GetAddr,
    GetBlocks,
    GetBlockTxn,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    InventoryType,
    Mempool,
    Message,
    NotFound,
    Payload,
    Ping,
    Pong,
    PrefilledTransaction,
    SendAddrV2,
    SendCmpct,
    SendHeaders,
    TxPayload,
    Verack,
    Version,
    WtxidRelay,
)
from btclib.p2p.message import Message as MessageClass
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_MAINNET = bytes.fromhex("f9beb4d9")

# the block after genesis, which is the smallest valid block there is:
# a `block` payload holds a `Block`, and one cannot be invented -- the
# proof of work `Block.assert_valid` asks for has to have been done
_BLOCK_1 = Block.parse(
    (Path(__file__).parent.parent / "block" / "_data" / "block_1.bin").read_bytes()
)

_TX = Tx(1, 0, [TxIn(OutPoint(b"\x11" * 32, 0))], [TxOut(1000, b"\x51")])

# every payload type of this package, with a value of each: the walk
# below is what says the list is complete
_PAYLOADS: tuple[Payload, ...] = (
    Version(70016, 0, 0, None, None, 1, b"/btclib/", 1, relay=True),
    Verack(),
    Addr(),
    AddrV2(),
    SendAddrV2(),
    Ping(1),
    Pong(1),
    Inv([Inventory(InventoryType.MSG_TX, bytes(32))]),
    GetData([Inventory(InventoryType.MSG_WITNESS_BLOCK, bytes(32))]),
    NotFound([Inventory(InventoryType.MSG_WTX, bytes(32))]),
    GetBlocks(70016, [bytes(32)], bytes(32)),
    GetHeaders(70016, [bytes(32)], bytes(32)),
    Headers(),
    GetCFilters(BlockFilterType.BASIC, 1, bytes(32)),
    CFilter(BlockFilterType.BASIC, bytes(32), b"\x00"),
    GetCFHeaders(BlockFilterType.BASIC, 1, bytes(32)),
    CFHeaders(BlockFilterType.BASIC, bytes(32), bytes(32), [bytes(32)]),
    GetCFCheckpt(BlockFilterType.BASIC, bytes(32)),
    CFCheckpt(BlockFilterType.BASIC, bytes(32), [bytes(32)]),
    TxPayload(_TX, include_witness=False),
    BlockPayload(_BLOCK_1, include_witness=False),
    SendCmpct(announce=True),
    CmpctBlock(_BLOCK_1.header, 1, [0x0102_0304_0506], [PrefilledTransaction(1, _TX)]),
    GetBlockTxn(_BLOCK_1.header.hash, [0, 2, 5]),
    BlockTxn(_BLOCK_1.header.hash, [_TX]),
    GetAddr(),
    Mempool(),
    SendHeaders(),
    WtxidRelay(),
    FeeFilter(1000),
)

_IDS = tuple(type(payload).__name__ for payload in _PAYLOADS)


def _payload_subclasses() -> set[type[Any]]:
    """Return every concrete payload type of the library.

    Two things are skipped, and each for its own reason: a name starting
    with an underscore is a shared body rather than a message type --
    `keepalive._NoncePayload`, `inventory._InventoryPayload` and
    `inventory._LocatorPayload` are those -- and a class defined outside
    `btclib` is another test's, `__subclasses__` being a live registry
    that whatever ran before this leaves its own subclasses in.
    """
    found: set[type[Any]] = set()
    pending = list(Payload.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        if not cls.__name__.startswith("_") and cls.__module__.startswith("btclib"):
            found.add(cls)
    return found


def test_every_payload_type_is_driven_here() -> None:
    """The inventory is a promise only if omission is what fails."""
    assert {type(payload) for payload in _PAYLOADS} == _payload_subclasses()


@pytest.mark.parametrize("payload", _PAYLOADS, ids=_IDS)
def test_a_payload_knows_the_command_that_carries_it(payload: Payload) -> None:
    """The constant is on the class, so the two directions read one name.

    Which is the whole of what a payload type adds to an ordinary wire
    class here: btclib_node writes the command as a string literal inside
    each `serialize` and dispatches on a separate table, and two of its
    literals are misspellings nothing compares against.
    """
    command = type(payload).command
    assert isinstance(command, str)
    assert command == command.strip().lower()
    assert 0 < len(command) <= 12

    message = payload.to_message(_MAINNET)
    assert message.command == command
    assert message.magic == _MAINNET
    assert message.payload == payload.serialize()


@pytest.mark.parametrize("payload", _PAYLOADS, ids=_IDS)
def test_the_round_trip_through_an_envelope(payload: Payload) -> None:
    """What a caller does with a message, both ways.

    The way back is the caller's `if` and not a table here, which is this
    module's decision: `Message.parse` answers with octets under a
    command, and matching the command to a type is the branch
    `net_processing.cpp` is a chain of too.
    """
    octets = payload.to_message(_MAINNET).serialize()
    message = Message.parse(octets)

    # `Any`, because `Payload` declares no `parse`: a subclass has one
    # for its own return type and the base has nothing to call it from,
    # which is `src/btclib/p2p/payload.py`'s asymmetry read off the types
    cls: Any = type(payload)
    assert message.command == cls.command
    assert cls.parse(message.payload) == payload
    assert message.serialize() == octets


@pytest.mark.parametrize("payload", _PAYLOADS, ids=_IDS)
def test_to_message_forwards_check_validity(payload: Payload) -> None:
    """The flag reaches both halves: the payload's and the envelope's."""
    assert payload.to_message(_MAINNET, check_validity=False) == payload.to_message(
        _MAINNET
    )

    # the envelope's own refusal is still the envelope's, which is what
    # says the two are composed rather than merged
    with pytest.raises(BTClibValueError, match="invalid magic"):
        payload.to_message(b"\x00")
    with pytest.raises(BTClibTypeError, match="invalid octets type"):
        payload.to_message(1)  # type: ignore[arg-type]


def test_the_message_a_payload_makes_is_the_envelopes_own_class() -> None:
    """No subclass, no wrapper: `to_message` answers with a `Message`.

    The envelope is untouched by any of this, which is the decision's
    point: `message.py` imports nothing of the payload types, so parsing
    one costs nothing of them either.
    """
    assert type(Ping(1).to_message(_MAINNET)) is MessageClass


def test_there_is_no_table_from_a_command_to_a_type() -> None:
    """The asymmetry, asserted so that adding one is a failing test.

    A `payload_from_message` here would be the registry issue #1082 kept
    out of the envelope, moved one module along: it would import every
    payload type, and it would make a command nobody has a branch for an
    error rather than octets. The caller's `if` is what there is instead.
    """
    for name in dir(Payload):
        assert "from_message" not in name

    # and the envelope goes on reading a command this package has no type
    # for, which is the property a table would end
    unknown = Message(_MAINNET, "notaBIPyet", b"\x00\xff")
    assert Message.parse(unknown.serialize()) == unknown
    assert unknown.command not in {type(p).command for p in _PAYLOADS}


def test_a_payload_type_cannot_be_instantiated_without_a_serialization() -> None:
    """The abstract half of the base, which is what `to_message` rests on."""

    class Incomplete(Payload):
        command = "incomplete"

    with pytest.raises(TypeError, match="abstract"):
        Incomplete()  # type: ignore[abstract]
