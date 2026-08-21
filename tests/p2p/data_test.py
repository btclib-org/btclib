# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.p2p.data` module.

**The authority is the vendored chain data, and it is unusually strong
here.** There is no captured `tx` or `block` message to drive these: the
Bitcoin Wiki's Protocol page annotates neither, and Bitcoin Core
publishes no vector file for them. What it does not need to, because the
payload of a `tx` message is a transaction and of a `block` message a
block, and `tests/block/_data` and `tests/tx/_data` hold real ones whose
own hashes pin them -- `tests/_data/README.md` records the height and
hash of every block file and the txid and wtxid of the transaction.

**The pair that decides the question this module is about is already in
the tree.** `block_481824_complete.bin` is that block as an RPC hands it
over and `block_481824.bin` is the same block with every witness
stripped, which is precisely `include_witness` True and False over one
object: two files nobody derived from the class under test, so a
serializer agreeing with itself cannot pass on them. The transaction is
the same shape one level down -- its txid is the hash256 of the stripped
encoding and its wtxid that of the full one, and both are recorded
outside this library.

**And the header authenticates the block more strongly than a captured
message would.** A capture is pinned by the four-octet checksum in its
own header, which anybody can recompute over anything; a mainnet header
is pinned by its proof of work, so no other eighty octets hash below the
target it declares. `assert_valid_pow` is that check, run here.

Everything else is a round trip, a refusal, or a reading of BIP144 and of
Core's test/functional/test_framework/messages.py.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

import btclib.p2p
from btclib.block import Block, BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.p2p import BlockPayload, Message, NetworkAddress, TxPayload
from btclib.p2p.limits import MAX_PROTOCOL_MESSAGE_LENGTH
from btclib.script import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_BLOCK_DATA = Path(__file__).parent.parent / "block" / "_data"
_TX_DATA = Path(__file__).parent.parent / "tx" / "_data"

# the block after genesis, the smallest there is, and the one block this
# tree has in both of the encodings `include_witness` chooses between
_BLOCK_1 = (_BLOCK_DATA / "block_1.bin").read_bytes()
_COMPLETE = (_BLOCK_DATA / "block_481824_complete.bin").read_bytes()
_STRIPPED = (_BLOCK_DATA / "block_481824.bin").read_bytes()

# the vendored segwit transaction, whose file is named after its txid and
# whose wtxid tests/_data/README.md records beside it
_TX_ID = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970"
_WTX_ID = "fa54c948e34e30d4196a560036ff6ac7e306906d189760a066edd4caf571776b"
_TX_BIN = (_TX_DATA / f"{_TX_ID}.bin").read_bytes()

_BLOCK_481824 = "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"

_MAINNET = bytes.fromhex("f9beb4d9")


def _legacy_tx() -> Tx:
    """Return a transaction with no witness: one input, one output."""
    return Tx(
        1,
        0,
        [TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF)],
        [TxOut(1000, b"\x51")],
    )


def test_the_vendored_block_pair_authenticates_itself() -> None:
    """Proof of work, and two files that are one block written twice.

    The header is the same eighty octets in both, so the work behind it
    covers both, and what tells the files apart is exactly the witness
    data no header commits to directly -- which is why the coinbase
    commitment is checked here too, `Block.assert_valid` being what asks
    for it.
    """
    header = BlockHeader.parse(_COMPLETE[:80])
    header.assert_valid_pow()
    assert header.hash.hex() == _BLOCK_481824
    assert _STRIPPED[:80] == _COMPLETE[:80]

    # a segwit block, so the two files really are two encodings and not
    # one file copied: `Block.assert_valid` checks the BIP141 commitment
    # over the witnesses the complete one carries
    block = Block.parse(_COMPLETE)
    assert block.is_segwit
    assert len(_COMPLETE) > len(_STRIPPED)


def test_the_two_encodings_of_a_block_are_the_two_vendored_files() -> None:
    """The flag decides which file comes out, and nothing else does.

    Neither file was produced by this class, which is what makes this a
    check rather than a round trip: a serializer that wrote the marker on
    the wrong side would agree with itself and disagree here.
    """
    block = Block.parse(_COMPLETE)

    assert BlockPayload(block, include_witness=True).serialize() == _COMPLETE
    assert BlockPayload(block, include_witness=False).serialize() == _STRIPPED


def test_the_two_encodings_of_a_transaction_are_pinned_by_two_hashes() -> None:
    """The txid is the stripped encoding's, the wtxid the full one's.

    BIP141's definition of the two identifiers, which is a statement
    about the octets rather than about the object: both hashes were
    recorded by whoever pulled the file, so each encoding is checked
    against a number this library did not compute.
    """
    tx = Tx.parse(_TX_BIN)

    full = TxPayload(tx, include_witness=True).serialize()
    stripped = TxPayload(tx, include_witness=False).serialize()

    assert full == _TX_BIN
    assert hash256(full)[::-1].hex() == _WTX_ID
    assert hash256(stripped)[::-1].hex() == _TX_ID
    assert full != stripped


def test_parse_answers_the_flag_with_what_the_octets_carried() -> None:
    """BIP144's marker, read by `Tx.parse` and `Block.parse` already.

    Both directions of both messages, on the two vendored files and on
    the transaction: what came in with a witness goes back out with one,
    and what came in stripped goes back out stripped.
    """
    for octets, expected in ((_COMPLETE, True), (_STRIPPED, False)):
        payload = BlockPayload.parse(octets)
        assert payload.include_witness is expected
        assert payload.serialize() == octets

    with_witness = TxPayload.parse(_TX_BIN)
    assert with_witness.include_witness is True
    assert with_witness.serialize() == _TX_BIN

    legacy_octets = _legacy_tx().serialize(include_witness=False)
    without = TxPayload.parse(legacy_octets)
    assert without.include_witness is False
    assert without.serialize() == legacy_octets


def test_a_transaction_with_no_witness_is_one_encoding_and_two_payloads() -> None:
    """The asymmetry, which is the decision's price and is named.

    A marker is written only where there is something to mark, so both
    answers write the same octets over a transaction that carries no
    witness. The encoding round-trips exactly; the object does not, and
    `parse` says `False` because that is the only answer those octets
    support.
    """
    tx = _legacy_tx()
    asked = TxPayload(tx, include_witness=True)
    stripped = TxPayload(tx, include_witness=False)

    assert asked != stripped
    assert asked.serialize() == stripped.serialize()
    assert TxPayload.parse(asked.serialize()) == stripped

    # and where the wire *can* tell the two apart, the object round-trips
    # as everything else in this package does
    segwit = TxPayload(Tx.parse(_TX_BIN), include_witness=True)
    assert TxPayload.parse(segwit.serialize()) == segwit


def test_the_flag_is_stored_and_not_reduced_against_the_object() -> None:
    """Why `__init__` does not fold `include_witness` into `is_segwit`.

    `Tx` is a mutable dataclass, so an answer reduced when the payload
    was built is an answer that goes stale: the transaction below carries
    no witness when the payload is made and one when it is written, and
    the flag the caller gave is what decides the octets at that moment --
    which is where `Tx.serialize` reads its own.
    """
    payload = TxPayload(_legacy_tx(), include_witness=True)
    assert payload.include_witness is True
    assert not payload.tx.is_segwit

    payload.tx.vin[0].script_witness = Witness([b"\x51"])
    assert payload.serialize() == payload.tx.serialize(include_witness=True)
    assert payload.serialize() != payload.tx.serialize(include_witness=False)


def test_the_command_each_class_travels_under() -> None:
    """`to_message` writes the command the class holds, and the way back."""
    spellings: tuple[tuple[Any, str], ...] = (
        (TxPayload(Tx.parse(_TX_BIN), include_witness=True), "tx"),
        (BlockPayload(Block.parse(_BLOCK_1), include_witness=False), "block"),
    )
    for payload, command in spellings:
        message = payload.to_message(_MAINNET)

        assert type(payload).command == command
        assert message.command == command
        assert message.magic == _MAINNET
        assert message.payload == payload.serialize()
        # and the caller's `if`, which is what there is instead of a table
        assert (
            type(payload).parse(Message.parse(message.serialize()).payload) == payload
        )


def test_a_block_message_stays_under_the_envelopes_own_bound() -> None:
    """Why nothing here adds a length bound of its own.

    `MAX_PROTOCOL_MESSAGE_LENGTH` is `btclib.p2p.limits`' and the
    envelope's, read off the header's length field before a payload is
    allocated. A block that satisfies `MAX_BLOCK_WEIGHT` cannot exceed
    it: the weight is three times the stripped size plus the size, so the
    size is short of four million by three times a stripped size that is
    at least a header and a transaction count.
    """
    block = Block.parse(_COMPLETE)
    payload = BlockPayload(block, include_witness=True)

    assert block.weight <= 4_000_000
    assert len(payload.serialize()) < MAX_PROTOCOL_MESSAGE_LENGTH
    assert block.weight == 3 * block.stripped_size + block.size

    # and the bound is enforced where it belongs, on octets no block of
    # that weight produces
    with pytest.raises(BTClibValueError, match="invalid payload length"):
        Message(_MAINNET, "block", bytes(MAX_PROTOCOL_MESSAGE_LENGTH + 1))


def test_a_wrong_type_is_a_type_error() -> None:
    """A value of a type the signature does not declare, at every field."""
    tx = _legacy_tx()
    block = Block.parse(_BLOCK_1)

    with pytest.raises(BTClibTypeError, match="invalid tx type"):
        TxPayload(block, include_witness=True)  # type: ignore[arg-type]
    with pytest.raises(BTClibTypeError, match="invalid block type"):
        BlockPayload(tx, include_witness=True)  # type: ignore[arg-type]

    # a kind and not a truth: `"no"` is true, and reading it for its truth
    # would write the wire serialization where the stripped one was meant
    for wrong in ("no", 0, 1):
        with pytest.raises(BTClibTypeError, match="invalid include_witness type"):
            TxPayload(tx, wrong)  # type: ignore[arg-type]
        with pytest.raises(BTClibTypeError, match="invalid include_witness type"):
            BlockPayload(block, wrong)  # type: ignore[arg-type]

    # and the refusal survives `check_validity=False`, `Tx.serialize` and
    # `Block.serialize` asking it unconditionally where they use it
    with pytest.raises(BTClibTypeError, match="invalid include_witness type"):
        TxPayload(tx, "no", check_validity=False).serialize(  # type: ignore[arg-type]
            check_validity=False
        )


def test_an_invalid_object_is_refused_unless_the_caller_says_not_to() -> None:
    """`check_validity` reaches the class that owns the rule."""
    empty = Tx(1, 0, [], [], check_validity=False)

    with pytest.raises(BTClibValueError, match="Missing inputs"):
        TxPayload(empty, include_witness=False)
    assert TxPayload(empty, include_witness=False, check_validity=False).tx is empty

    # and the flag reaches the serialization too, which is the half that
    # says it switches the check off rather than the half that says it is
    # there
    payload = TxPayload(empty, include_witness=False, check_validity=False)
    assert payload.serialize(check_validity=False)
    with pytest.raises(BTClibValueError, match="Missing inputs"):
        payload.serialize()

    headerless = Block(BlockHeader.parse(_BLOCK_1[:80]), [], check_validity=False)
    with pytest.raises(BTClibValueError, match="block with no transactions"):
        BlockPayload(headerless, include_witness=True)
    unchecked = BlockPayload(headerless, include_witness=True, check_validity=False)
    assert unchecked.block is headerless


def test_the_octets_of_a_payload_are_read_where_they_end() -> None:
    """Truncation and trailing octets, both refused by the class below.

    Neither refusal is this module's: a `tx` payload is a transaction and
    a `block` payload a block, so `Tx.parse` and `Block.parse` are what
    say where the octets end, and a second reader here would be a second
    rule to keep true.
    """
    with pytest.raises(BTClibValueError, match="not enough|invalid decoded length"):
        TxPayload.parse(_TX_BIN[:20])
    with pytest.raises(BTClibValueError, match="bytes after the transaction"):
        TxPayload.parse(_TX_BIN + b"\x00")

    with pytest.raises(BTClibValueError, match="not enough|invalid decoded length"):
        BlockPayload.parse(_BLOCK_1[:100])
    with pytest.raises(BTClibValueError, match="bytes after the block"):
        BlockPayload.parse(_BLOCK_1 + b"\x00")


def test_a_stream_is_read_one_payload_at_a_time() -> None:
    """A caller's stream is the caller's, which the wrapper must not undo."""
    stream = BytesIO(_TX_BIN + _BLOCK_1 + b"junk")

    assert TxPayload.parse(stream) == TxPayload.parse(_TX_BIN)
    assert BlockPayload.parse(stream) == BlockPayload.parse(_BLOCK_1)
    assert stream.read() == b"junk"


def test_frozen() -> None:
    """Refuse assignment to either field: a payload is a value."""
    payload = TxPayload(_legacy_tx(), include_witness=True)

    with pytest.raises(FrozenInstanceError):
        payload.include_witness = False  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        BlockPayload(Block.parse(_BLOCK_1), include_witness=False).block = None  # type: ignore[assignment,misc]

    # re-encoding for another peer is `replace`, which is what the field
    # being a field buys
    assert replace(payload, include_witness=False) == TxPayload(
        payload.tx, include_witness=False
    )

    # and neither is hashable, `Tx` and `Block` being mutable dataclasses
    with pytest.raises(TypeError, match="unhashable"):
        hash(payload)


def test_the_package_publishes_neither_tx_nor_block() -> None:
    """The suffix, which is what keeps two `Tx` out of one namespace.

    `from btclib.p2p import *` must not bind a `Tx` other than
    `btclib.tx.Tx`, and the command a payload travels under is where the
    unsuffixed name would have come from. btclib_node's
    `p2p/messages/data.py` declares both and imports btclib's as `TxData`
    and `BlockData`, which is the collision this avoids rather than
    renames.
    """
    published = set(btclib.p2p.__all__)
    assert {"TxPayload", "BlockPayload"} <= published
    assert not published & {"Tx", "Block"}
    assert (TxPayload.command, BlockPayload.command) == ("tx", "block")

    # and a payload holds its object rather than being one, so a wrong
    # wrapper is a type error and never a silently different message
    with pytest.raises(BTClibTypeError, match="invalid tx type"):
        TxPayload(NetworkAddress(), include_witness=True)  # type: ignore[arg-type]
