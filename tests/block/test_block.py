#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.block` module.

The `_data/block_*.bin` files are consensus bytes, so there is no upstream
repository to cite: `bitcoin-cli getblock <hash> 0` returns each of them,
except `block_481824.bin`, which is that block serialized *without*
witness data as a pre-segwit node sees it and which no RPC hands over --
`Block.parse(complete).serialize(include_witness=False)` reproduces it.
`Block.parse` recomputes the hash from the bytes on every run, so these
files verify themselves. tests/_data/README.md lists the heights, hashes
and sizes.
"""

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from os import path
from pathlib import Path

import pytest

from btclib.block import Block, BlockHeader
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS
from btclib.script.witness import Witness


def test_block_1() -> None:
    """Test first block after genesis."""
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert len(block.transactions) == 1
    assert block.size == 215
    assert block.weight == 536
    assert block.height is None
    assert not block.has_segwit_tx()
    assert block == Block.parse(block.serialize())
    assert block == Block.from_dict(block.to_dict())

    header = block.header
    assert header.version == 1
    assert header.previous_block_hash == NETWORKS["mainnet"].genesis_block
    merkle_root = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    assert header.merkle_root.hex() == merkle_root
    timestamp = datetime(2009, 1, 9, 2, 54, 25, tzinfo=timezone.utc)
    assert header.time == timestamp
    assert header.bits.hex() == "1d00ffff"
    assert header.nonce == 0x9962E301

    hash_ = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    assert header.hash.hex() == hash_
    assert header.difficulty == 1
    assert header == BlockHeader.parse(header.serialize())
    assert header == BlockHeader.from_dict(header.to_dict())


def test_exceptions() -> None:
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    # a truncated header is reported as truncated, whichever field the
    # missing bytes fall in. Read past the end of a stream returns what
    # there was without raising, so these three used to be diagnosed by
    # accident: "invalid timestamp (before genesis)" for a time read from
    # no bytes at all, "invalid bits length" for a short slice, and
    # "invalid nonce" only because the bound was 0 < nonce and a short
    # read is zero -- which is why relaxing that bound needed this check
    for truncated in (68, 74, 76, 79):
        err_msg = f"invalid decoded length: {truncated} instead of 80"
        with pytest.raises(BTClibValueError, match=err_msg):
            BlockHeader.parse(block_bytes[:truncated])

    # a 0xff prefix announcing eight bytes that are not there: the
    # truncation is now caught, rather than read as a transaction count of
    # zero and surfaced as an IndexError from outside the library contract
    with pytest.raises(BTClibValueError, match="not enough binary data for var_int"):
        Block.parse(block_bytes[:80] + b"\xff")

    header_bytes = block_bytes[:80]

    header = BlockHeader.parse(header_bytes)
    header.version = 0
    with pytest.raises(BTClibValueError, match="invalid version: "):
        header.assert_valid()
    header.version = 0x7FFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid version: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.previous_block_hash = b"\xff" * 33
    with pytest.raises(BTClibValueError, match="invalid previous_block_hash length: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.merkle_root = b"\xff" * 33
    with pytest.raises(BTClibValueError, match="invalid merkle_root length: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.bits = b"\xff" * 5
    with pytest.raises(BTClibValueError, match="invalid bits length: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    # one second before genesis
    header.time = datetime(2009, 1, 3, 18, 15, 4, tzinfo=timezone.utc)
    err_msg = "invalid timestamp \\(before genesis\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    # naive: timestamp() would read it as local time, so both the
    # genesis check and the serialization would depend on the machine
    header.time = header.time.replace(tzinfo=None)
    err_msg = "naive timestamp \\(no time zone\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.nonce = 0x100000000
    with pytest.raises(BTClibValueError, match="invalid nonce: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.nonce += 1
    with pytest.raises(BTClibValueError, match="invalid proof-of-work: "):
        header.assert_valid_pow()


def test_block_header_keywords() -> None:
    """Test that every BlockHeader field is a valid keyword argument."""
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        header_bytes = file_.read()[:80]

    header = BlockHeader.parse(header_bytes)
    assert header == BlockHeader(
        version=header.version,
        previous_block_hash=header.previous_block_hash,
        merkle_root=header.merkle_root,
        time=header.time,
        bits=header.bits,
        nonce=header.nonce,
    )

    # the same instant in another time zone is the same header
    other_zone = header.time.astimezone(timezone(timedelta(hours=14)))
    assert other_zone.hour != header.time.hour
    header.time = other_zone
    assert header.serialize() == header_bytes


def test_block_170() -> None:
    """Test first block with a transaction."""
    fname = "block_170.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert len(block.transactions) == 2
    assert block.size == 490
    assert block.weight == 1636
    assert block.height is None
    assert not block.has_segwit_tx()
    assert block == Block.parse(block.serialize())
    assert block == Block.from_dict(block.to_dict())

    header = block.header
    assert header.version == 1
    prev_block = "000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55"
    assert header.previous_block_hash.hex() == prev_block
    merkle_root = "7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"
    assert header.merkle_root.hex() == merkle_root
    timestamp = datetime(2009, 1, 12, 3, 30, 25, tzinfo=timezone.utc)
    assert header.time == timestamp
    assert header.bits.hex() == "1d00ffff"
    assert header.nonce == 0x709E3E28

    hash_ = "00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee"
    assert header.hash.hex() == hash_
    assert header.difficulty == 1
    assert header == BlockHeader.parse(header.serialize())
    assert header == BlockHeader.from_dict(header.to_dict())


def test_block_200000() -> None:
    fname = "block_200000.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert len(block.transactions) == 388
    assert block.size == 247_533
    assert block.weight == 989_800
    assert block.height == 200_000
    assert not block.has_segwit_tx()
    assert block == Block.parse(block.serialize())
    assert block == Block.from_dict(block.to_dict())

    header = block.header
    assert header.version == 2
    prev_block = "00000000000003a20def7a05a77361b9657ff954b2f2080e135ea6f5970da215"
    assert header.previous_block_hash.hex() == prev_block
    merkle_root = "a08f8101f50fd9c9b3e5252aff4c1c1bd668f878fffaf3d0dbddeb029c307e88"
    assert header.merkle_root.hex() == merkle_root
    assert header.time == datetime(2012, 9, 22, 10, 45, 59, tzinfo=timezone.utc)
    assert header.bits.hex() == "1a05db8b"
    assert header.nonce == 0xF7D8D840

    hash_ = "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"
    assert header.hash.hex() == hash_
    assert 0 <= header.difficulty - 2_864_140 < 1
    assert header == BlockHeader.parse(header.serialize())
    assert header == BlockHeader.from_dict(header.to_dict())

    block.transactions.pop()
    err_msg = "invalid merkle root: "
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid()

    block.transactions.pop(0)
    err_msg = "first transaction is not a coinbase"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        _ = block.height


def test_block_merkle_mutation() -> None:
    """A block duplicating a trailing subtree is rejected (CVE-2012-2459).

    Block 200,000 has 388 transactions, so the level of 97 nodes is the
    first odd one; appending a copy of the last four transactions makes
    the tree hash the two identical subtrees rooted there and yields the
    very same merkle root, i.e. the header of the honest block also
    commits to this one. Core rejects it as bad-txns-duplicate.
    """
    fname = "block_200000.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    block.transactions += block.transactions[-4:]

    # the header is untouched: the root does not tell the two apart
    err_msg = "duplicate transaction"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid()


def test_block_481824() -> None:
    """Test first block with segwit transaction as seen from legacy nodes."""
    prev_block = "000000000000000000cbeff0b533f8e1189cf09dfbebf57a8ebe349362811b80"
    merkle_root = "6438250cad442b982801ae6994edb8a9ec63c0a0ba117779fbe7ef7f07cad140"
    hash_ = "0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893"
    for i, fname in enumerate(["block_481824.bin", "block_481824_complete.bin"]):
        filename = path.join(path.dirname(__file__), "_data", fname)
        with open(filename, "rb") as file_:
            block_bytes = file_.read()

        block = Block.parse(block_bytes)
        assert len(block.transactions) == 1866
        assert block.height == 481_824
        assert block == Block.parse(block.serialize())
        assert block == Block.from_dict(block.to_dict())

        header = block.header
        assert header.version == 0x20000002
        assert header.previous_block_hash.hex() == prev_block
        assert header.merkle_root.hex() == merkle_root
        timestamp = datetime(2017, 8, 24, 1, 57, 37, tzinfo=timezone.utc)
        assert header.time == timestamp
        assert header.bits.hex() == "18013ce9"
        assert header.nonce == 0x2254FF22

        assert header.hash.hex() == hash_
        assert 0 <= header.difficulty - 888_171_856_257 < 1
        assert header == BlockHeader.parse(header.serialize())
        assert header == BlockHeader.from_dict(header.to_dict())

        if i:  # segwit nodes see the witness data
            assert block.has_segwit_tx()
            assert block.size == 989_323
            assert block.weight == 3_954_548
            assert block.vsize == 988_637
        else:  # legacy nodes see NO witness data
            assert not block.has_segwit_tx()
            assert block.size == 988_519
            assert block.weight == 3_953_744
            assert block.vsize == 988_436


def test_block_witness_commitment() -> None:
    """A block whose witness data was replaced is rejected (BIP141).

    Block 481,824 is the first segwit one; the signature tampered with
    below belongs to a transaction whose txid, and hence the merkle root
    of the header, is unchanged by the edit. Only the coinbase
    commitment tells the two apart, as Core does with
    bad-witness-merkle-match.
    """
    fname = "block_481824_complete.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    commitment = "6c3c4dff76b5760d58694147264d208689ee07823e5694c4872f856eacf5a5d8"
    assert block.witness_commitment is not None
    assert block.witness_commitment.hex() == commitment

    tx = block.transactions[12]
    tx_id = tx.id
    stack = tx.vin[0].script_witness.stack
    signature = bytearray(stack[0])
    signature[-2] ^= 0xFF
    tx.vin[0].script_witness = Witness([bytes(signature), *stack[1:]])
    assert tx.id == tx_id  # the txid tree is blind to it
    with pytest.raises(BTClibValueError, match="invalid witness commitment: "):
        block.assert_valid()

    # the last commitment output is the one that counts, so appending
    # another cannot pass a stale one off as valid; the merkle root is
    # not recomputed here, the coinbase txid having changed
    block = Block.parse(block_bytes)
    coinbase = block.transactions[0]
    coinbase.vout.append(deepcopy(coinbase.vout[1]))
    coinbase.vout[-1].script_pub_key.script = (
        bytes.fromhex("6a24aa21a9ed") + b"\x00" * 32
    )
    assert block.witness_commitment == b"\x00" * 32
    with pytest.raises(BTClibValueError, match="invalid witness commitment: "):
        block.assert_valid_witness_commitment()


def test_block_witness_nonce() -> None:
    """The coinbase witness must hold the 32-byte nonce, and nothing else.

    The coinbase witness is not covered by the txid it is part of, so
    these blocks have the merkle root of the honest one; Core rejects
    them as bad-witness-nonce-size.
    """
    fname = "block_481824_complete.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    for stack in ([], [b"\x00" * 31], [b"\x00" * 32] * 2):
        block = Block.parse(block_bytes)
        block.transactions[0].vin[0].script_witness = Witness(stack)
        with pytest.raises(BTClibValueError, match="invalid witness nonce: "):
            block.assert_valid()


def test_block_unexpected_witness() -> None:
    """Witness data is not allowed in a block that does not commit to it.

    Block 170 predates segwit, so its coinbase carries no commitment
    output: the witness handed to its second transaction could be
    replaced by anyone, the merkle root never having seen it. Core
    rejects the block as unexpected-witness.
    """
    fname = "block_170.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert block.witness_commitment is None

    block.transactions[1].vin[0].script_witness = Witness([b"\x00" * 32])
    with pytest.raises(BTClibValueError, match="unexpected witness"):
        block.assert_valid()


def test_dataclasses_json_dict(generated_files_dir: Path) -> None:
    fname = "block_481824.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as binfile_:
        block = binfile_.read()

    # dataclass
    block_data = Block.parse(block)
    assert isinstance(block_data, Block)

    # dict
    block_dict = block_data.to_dict()
    assert isinstance(block_dict, dict)
    filename = path.join(generated_files_dir, "block_481824.json")
    with open(filename, "w", encoding="ascii") as file_:
        json.dump(block_dict, file_, indent=4)
        file_.write("\n")  # end-of-file-fixer
    assert block_data == Block.from_dict(block_dict)

    block_header = block_data.header.serialize()

    # dataclass
    block_header_data = BlockHeader.parse(block_header)
    assert isinstance(block_header_data, BlockHeader)

    # dict
    block_header_d = block_header_data.to_dict()
    assert isinstance(block_header_d, dict)
    filename = path.join(generated_files_dir, "block_header_481824.json")
    with open(filename, "w", encoding="ascii") as file_:
        json.dump(block_header_d, file_, indent=4)
        file_.write("\n")  # end-of-file-fixer
    assert block_header_data == BlockHeader.from_dict(block_header_d)


def test_target_from_compact_bits() -> None:
    """The compact form of a target, over the range nBits can express.

    Core's SetCompact is the reference: it shifts rather than
    multiplying, and it flags as an overflow what does not fit, which
    CheckProofOfWork then rejects the header for. btclib used to raise
    OverflowError out of to_bytes for the second, and to compute the
    first through float arithmetic, pow(256, -1) being a float.
    """
    header = BlockHeader(check_validity=False)

    # exponent above 3: the significand shifted up, which is the case
    # every real header takes
    header.bits = bytes.fromhex("1d00ffff")  # the genesis block target
    assert header.target.hex() == f"{'00' * 4}{'ff' * 2}{'00' * 26}"

    # exponent below 3: the significand shifted *down*, discarding the
    # low bytes rather than multiplying by a fractional power of 256
    header.bits = bytes.fromhex("0200ffff")
    assert int.from_bytes(header.target, "big") == 0xFFFF >> 8
    header.bits = bytes.fromhex("0100ffff")
    assert int.from_bytes(header.target, "big") == 0xFFFF >> 16
    header.bits = bytes.fromhex("0000ffff")
    assert int.from_bytes(header.target, "big") == 0

    # exponent 3 exactly: neither shift
    header.bits = bytes.fromhex("0300ffff")
    assert int.from_bytes(header.target, "big") == 0xFFFF

    # and what 32 bytes cannot hold
    for bits in ("22ffffff", "ff000001", "fdffffff"):
        header.bits = bytes.fromhex(bits)
        err_msg = "invalid proof-of-work target: "
        with pytest.raises(BTClibValueError, match=err_msg):
            _ = header.target


def test_block_without_transactions() -> None:
    """A block with no coinbase is not a block with nothing in it.

    One byte is all it takes: a var_int of zero where the transaction
    count goes, which transactions[0] used to answer with an IndexError.
    """
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    # the count follows the 80 bytes of the header
    emptied = block_bytes[:80] + b"\x00"
    with pytest.raises(BTClibValueError, match="block with no transactions"):
        Block.parse(emptied)

    header = Block.parse(block_bytes).header
    with pytest.raises(BTClibValueError, match="block with no transactions"):
        Block(header, [])


def test_assert_valid_does_not_rewrite_the_header() -> None:
    """A read is a read: assert_valid used to coerce nonce in place.

    serialize() and to_dict() call assert_valid, so both nominally
    read-only operations rewrote a field of the header they were reading.
    The coercion is in __init__ now, where from_dict's json -- the reason
    it exists -- goes through it.
    """
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        header_bytes = file_.read()[:80]

    header = BlockHeader.parse(header_bytes)
    nonce = header.nonce

    # a read leaves the header alone, which is the whole of the fix: the
    # coercion used to run here, so a to_dict() rebound the field
    assert header.to_dict()["nonce"] == nonce
    assert header.nonce is nonce
    assert header.serialize() == header_bytes
    assert header.nonce is nonce

    # a float nonce is reported instead of being repaired in place. It
    # used to be coerced and the header serialized as if nothing had
    # happened; dropping the coercion outright would have let the float
    # reach to_bytes and leave through an AttributeError
    header.nonce = float(nonce)  # type: ignore[assignment]
    with pytest.raises(BTClibTypeError, match="invalid nonce type: float"):
        header.assert_valid()
    assert isinstance(header.nonce, float)

    header = BlockHeader.parse(header_bytes)
    header.version = "1"  # type: ignore[assignment]
    with pytest.raises(BTClibTypeError, match="invalid version type: str"):
        header.assert_valid()

    # and the coercion still happens where it belongs: from_dict is the
    # reason it exists, json having no integer type of its own
    coerced = BlockHeader(
        version=1.0,  # type: ignore[arg-type]
        previous_block_hash=header.previous_block_hash,
        merkle_root=header.merkle_root,
        time=header.time,
        bits=header.bits,
        nonce=float(nonce),  # type: ignore[arg-type]
    )
    assert isinstance(coerced.nonce, int)
    assert isinstance(coerced.version, int)
    assert coerced.serialize() == header_bytes


def test_a_candidate_header_can_be_built() -> None:
    """Structural validity and proof-of-work are different questions.

    assert_valid used to end in assert_valid_pow, so a header being mined
    -- structurally valid, no work found yet -- could not be built,
    serialized, or hashed through the ordinary API. Hashing it is mining.
    """
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        header_bytes = file_.read()[:80]

    mined = BlockHeader.parse(header_bytes)

    # the same header with the nonce not yet found: the constructor used
    # to raise BTClibValueError("invalid proof-of-work") on both of these
    for nonce in (0, mined.nonce + 1):
        candidate = BlockHeader(
            version=mined.version,
            previous_block_hash=mined.previous_block_hash,
            merkle_root=mined.merkle_root,
            time=mined.time,
            bits=mined.bits,
            nonce=nonce,
        )
        candidate.assert_valid()
        assert len(candidate.serialize()) == 80
        assert len(candidate.hash) == 32
        # and the work is still asked for, when it is asked for
        with pytest.raises(BTClibValueError, match="invalid proof-of-work: "):
            candidate.assert_valid_pow()

    # a nonce of zero is a nonce: consensus places no lower bound on it,
    # and it is where mining starts. It used to be rejected, which also
    # meant btclib could not read a consensus-valid block that had one
    zero_nonce = header_bytes[:76] + bytes(4)
    parsed = BlockHeader.parse(zero_nonce)
    assert parsed.nonce == 0
    assert parsed.serialize() == zero_nonce

    # the round trip still works for the mined header, work and all
    assert mined.serialize() == header_bytes
    mined.assert_valid_pow()


def test_a_block_still_requires_the_work() -> None:
    """Block.assert_valid asserts it, as Core's CheckBlock does.

    That is what keeps the vendored block_*.bin files self-verifying:
    Block.parse recomputes the hash from the bytes on every run.
    """
    fname = "block_1.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    block.assert_valid()

    # one bit of the nonce flipped is a block whose work no longer holds
    forged = bytearray(block_bytes)
    forged[76] ^= 0x01
    with pytest.raises(BTClibValueError, match="invalid proof-of-work: "):
        Block.parse(bytes(forged))
