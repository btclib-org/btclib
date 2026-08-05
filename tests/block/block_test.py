# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from btclib.block import Block, BlockHeader
from btclib.block.limits import (
    MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT,
    WITNESS_SCALE_FACTOR,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx import TxOut
from tests.conftest import JsonGolden


def test_block_1() -> None:
    """Test first block after genesis."""
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert len(block.transactions) == 1
    assert block.size == 215
    assert block.stripped_size == 215
    # 215 * 4, the header and the transaction count included: Core's
    # GetBlockWeight, and 324 more than the 536 of its one transaction
    assert block.weight == 860
    assert block.sig_op_count == 1
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
    """Verify the error each truncation or malformed header field raises."""
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    # a truncated header is reported as truncated, whichever field the
    # missing bytes fall in. Read past the end of a stream returns what
    # there was without raising, so without this check the diagnosis is
    # an accident of the field: "invalid timestamp (before genesis)" for
    # a time read from no bytes at all, "invalid bits length" for a short
    # slice -- and a truncated nonce reads as zero, which is a valid
    # nonce, so it would not be diagnosed at all
    for truncated in (68, 74, 76, 79):
        err_msg = f"invalid decoded length: {truncated} instead of 80"
        with pytest.raises(BTClibValueError, match=err_msg):
            BlockHeader.parse(block_bytes[:truncated])

    # a 0xff prefix announcing eight bytes that are not there: the
    # truncation is caught, rather than read as a transaction count of
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
    # one second past the last instant four unsigned bytes can hold
    header.time = datetime(2106, 2, 7, 6, 28, 16, tzinfo=timezone.utc)
    err_msg = "invalid timestamp \\(after the last 4-bytes instant\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        header.assert_valid()
    # that instant itself is valid, and serializes to the four 0xff the
    # bound is about: without the bound, serialize would raise
    # OverflowError one second later, for a header assert_valid had just
    # accepted
    header.time = datetime(2106, 2, 7, 6, 28, 15, tzinfo=timezone.utc)
    assert header.serialize()[68:72] == b"\xff" * 4
    # the far end of the range datetime itself can hold: its timestamp()
    # is a float that rounds up to year 10000, so rendering it through
    # fromtimestamp would raise ValueError out of assert_valid
    header.time = datetime.max.replace(tzinfo=timezone.utc)
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
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
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
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert len(block.transactions) == 2
    assert block.size == 490
    assert block.weight == 1960
    # one for the coinbase output, two for the first payment ever made:
    # the p2pk it pays to and the p2pk it spends from
    assert block.sig_op_count == 3
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
    """Verify block 200,000: 388 transactions and a BIP34 height."""
    fname = "block_200000.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert len(block.transactions) == 388
    assert block.size == 247_533
    assert block.weight == 990_132
    assert block.sig_op_count == 822
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
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
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
        filename = Path(__file__).parent / "_data" / fname
        with filename.open("rb") as file_:
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

        # the same 1866 transactions either way, so the same sigops: the
        # count is over the script_sig and script_pub_key bytes, which
        # both serializations carry in full
        assert block.sig_op_count == 3_409

        if i:  # segwit nodes see the witness data
            assert block.has_segwit_tx()
            assert block.size == 989_323
            assert block.stripped_size == 988_519
            assert block.weight == 3_954_880
            assert block.vsize == 988_720
        else:  # legacy nodes see NO witness data
            assert not block.has_segwit_tx()
            assert block.size == 988_519
            assert block.stripped_size == 988_519
            assert block.weight == 3_954_076
            assert block.vsize == 988_519


def test_block_witness_commitment() -> None:
    """A block whose witness data was replaced is rejected (BIP141).

    Block 481,824 is the first segwit one; the signature tampered with
    below belongs to a transaction whose txid, and hence the merkle root
    of the header, is unchanged by the edit. Only the coinbase
    commitment tells the two apart, as Core does with
    bad-witness-merkle-match.
    """
    fname = "block_481824_complete.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
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
    # a new TxOut rather than a rebound script: ScriptPubKey is frozen
    # (issue 165), which is what stops a mutation here reaching every other
    # holder of that ScriptPubKey
    coinbase.vout.append(
        TxOut(
            coinbase.vout[1].value,
            ScriptPubKey(bytes.fromhex("6a24aa21a9ed") + b"\x00" * 32),
        )
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
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
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
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    assert block.witness_commitment is None

    block.transactions[1].vin[0].script_witness = Witness([b"\x00" * 32])
    with pytest.raises(BTClibValueError, match="unexpected witness"):
        block.assert_valid()


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    """Round-trip Block and BlockHeader through their dict and golden json."""
    fname = "block_481824.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as binfile_:
        block = binfile_.read()

    # dataclass
    block_data = Block.parse(block)
    assert isinstance(block_data, Block)

    # dict
    block_dict = block_data.to_dict()
    assert isinstance(block_dict, dict)
    json_golden("block_481824.json", block_dict)
    assert block_data == Block.from_dict(block_dict)

    block_header = block_data.header.serialize()

    # dataclass
    block_header_data = BlockHeader.parse(block_header)
    assert isinstance(block_header_data, BlockHeader)

    # dict
    block_header_d = block_header_data.to_dict()
    assert isinstance(block_header_d, dict)
    json_golden("block_header_481824.json", block_header_d)
    assert block_header_data == BlockHeader.from_dict(block_header_d)


def test_target_from_compact_bits() -> None:
    """The compact form of a target, over the range nBits can express.

    Core's SetCompact is the reference: it shifts rather than
    multiplying, and it flags as an overflow what does not fit, which
    CheckProofOfWork then rejects the header for. Guards against the
    shift running through float arithmetic -- pow(256, -1) is a float --
    and against the overflow escaping as OverflowError out of to_bytes.
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


@pytest.mark.parametrize(
    ("height", "nbits", "difficulty"),
    [
        (0, 486604799, 1.000),
        (33_333, 486594666, 1.183),
        (74_000, 469809688, 352.161),
        (105_000, 453179945, 22012.381),
        (210_000, 436527338, 3438908.960),
        (250_000, 426957810, 37392766.136),
    ],
)
def test_difficulty_from_compact_bits(
    height: int, nbits: int, difficulty: float
) -> None:
    """The nBits of six blocks against the difficulty each stands for.

    petertodd/python-bitcoinlib's `Test_CBlockHeader.test_calc_difficulty`,
    in `bitcoin/tests/test_core.py`, is where the six pairs come from
    (issue 199); tests/_data/README.md pins the revision. Upstream's
    decimal spelling of nBits is kept and converted here, rather than
    written as the hex the field holds: a vector has to be readable
    against the source it is quoted from, and rewriting the base puts a
    hand conversion between the two.

    The four blocks this suite parses reach two distinct difficulties and
    one of the two is 1. Here the exponent of nBits moves over five
    values, which is the range the ratio of two powers of 256 has to be
    checked over.
    """
    header = BlockHeader(bits=nbits.to_bytes(4, "big"), check_validity=False)
    assert round(header.difficulty, 3) == difficulty


def test_block_without_transactions() -> None:
    """A block with no coinbase is not a block with nothing in it.

    One byte is all it takes: a var_int of zero where the transaction
    count goes, refused here rather than left for transactions[0] to
    surface as an IndexError.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    # the count follows the 80 bytes of the header
    emptied = block_bytes[:80] + b"\x00"
    with pytest.raises(BTClibValueError, match="block with no transactions"):
        Block.parse(emptied)

    header = Block.parse(block_bytes).header
    with pytest.raises(BTClibValueError, match="block with no transactions"):
        Block(header, [])


def test_a_block_carries_one_coinbase() -> None:
    """A second coinbase is refused, as Core's bad-cb-multiple.

    No vector can state this. The proof-of-work is checked before the
    transaction list is read, so a block carrying two coinbases is
    refused for its work long before the rule would fire, and adding a
    coinbase to a real block moves the merkle root its header commits
    to -- there is no well-formed block with valid work and two
    coinbases to be had. So the block is built here instead: block
    200000's own coinbase, put back a second time over the transaction
    that followed it.

    The merkle root the block no longer has is checked after this rule,
    which is where Core checks it too (issue #250).
    """
    fname = "block_200000.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    block.transactions[1] = block.transactions[0]
    with pytest.raises(BTClibValueError, match="more than one coinbase"):
        block.assert_valid()


def test_assert_valid_checks_the_coinbase_transaction() -> None:
    """Refuse an invalid coinbase before checking its changed txid.

    Emptying the script_sig violates CheckTransaction's coinbase rule and
    also changes the merkle root. The transaction rule comes first in
    CheckBlock, so a merkle-root error would mean the coinbase itself was
    skipped.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block = Block.parse(file_.read())

    block.transactions[0].vin[0].script_sig = b""
    with pytest.raises(BTClibValueError, match="Invalid coinbase script size"):
        block.assert_valid()


def test_assert_valid_does_not_rewrite_the_header() -> None:
    """A read is a read: assert_valid must not coerce nonce in place.

    serialize() and to_dict() call assert_valid, so a coercion there
    lets nominally read-only operations rewrite a field of the header
    they are reading. Coercion belongs in __init__, where from_dict's
    json -- the reason it exists -- goes through it.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        header_bytes = file_.read()[:80]

    header = BlockHeader.parse(header_bytes)
    nonce = header.nonce

    # a read leaves the header alone: coercion here would let a plain
    # to_dict() rebind the field
    assert header.to_dict()["nonce"] == nonce
    assert header.nonce is nonce
    assert header.serialize() == header_bytes
    assert header.nonce is nonce

    # a float nonce is reported: not repaired in place, the header then
    # serializing as if nothing had happened, and not let through to
    # to_bytes, which would surface it as an AttributeError
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

    Were assert_valid to end in assert_valid_pow, a header being mined
    -- structurally valid, no work found yet -- could not be built,
    serialized, or hashed through the ordinary API. Hashing it is mining.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        header_bytes = file_.read()[:80]

    mined = BlockHeader.parse(header_bytes)

    # the same header with the nonce not yet found: building it must not
    # demand the proof-of-work
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
    # it is where mining starts, and a consensus-valid block can carry one
    zero_nonce = header_bytes[:76] + bytes(4)
    parsed = BlockHeader.parse(zero_nonce)
    assert parsed.nonce == 0
    assert parsed.serialize() == zero_nonce

    # the round trip still works for the mined header, work and all
    assert mined.serialize() == header_bytes
    mined.assert_valid_pow()


@pytest.mark.parametrize(
    ("fname", "delta"),
    [
        ("block_1.bin", 324),
        ("block_170.bin", 324),
        ("block_200000.bin", 332),
        ("block_481824_complete.bin", 332),
    ],
)
def test_the_weight_is_the_block_and_not_its_transactions(
    fname: str, delta: int
) -> None:
    """`Block.weight` is Core's GetBlockWeight, over the whole block.

    The sum of the transactions' weights is a different number, and it is
    the one no rule reads: the header weighs 320 units, and the var_int
    holding the transaction count weighs 4 for the two blocks with fewer
    than 253 transactions and 12 for the two with hundreds. That is the
    delta here, and MAX_BLOCK_WEIGHT bounds the larger of the two.

    Both spellings of Core's formula are asserted, because the comment
    beside it in `consensus/validation.h` is that they are the same one:
    four times the stripped size plus the witness bytes, and three times
    the stripped size plus the size.
    """
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    witness_size = block.size - block.stripped_size
    assert block.weight == block.stripped_size * WITNESS_SCALE_FACTOR + witness_size
    assert block.weight == block.stripped_size * 3 + block.size
    assert block.weight - sum(t.weight for t in block.transactions) == delta


def test_a_block_cannot_announce_too_many_sigops() -> None:
    """Core's bad-blk-sigops, from a block built for the purpose.

    The largest count in this suite is block 481,824's 3,409, 17% of the
    20,000 legacy signature checks the cost limit allows, so no vendored
    block comes near it: block 1's coinbase output script is replaced by
    n OP_CHECKSIG, which is n sigops however unspendable that script is
    -- the count is what the bytes announce, not what executing them
    would do.

    The mutation moves the merkle root as well, so the block is invalid
    twice over, and which answer comes back says where the rule sits:
    Core asks the sigop question last of CheckBlock's own, after every
    transaction has been checked on its own.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    limit = MAX_BLOCK_SIGOPS_COST // WITNESS_SCALE_FACTOR
    assert limit == 20_000

    for count in (limit, limit + 1):
        block = Block.parse(block_bytes)
        coinbase = block.transactions[0]
        # a new TxOut rather than a rebound script: ScriptPubKey is frozen
        coinbase.vout[0] = TxOut(coinbase.vout[0].value, ScriptPubKey(b"\xac" * count))
        # the coinbase script_sig pushes the extranonce and nothing else,
        # so the block's count is the output script's
        assert coinbase.sig_op_count == count
        assert block.sig_op_count == count

        if count == limit:
            # the cost is exactly the cap, which the rule allows: the
            # comparison is a bound the block may reach
            block.assert_valid_sig_op_count()
            continue

        err_msg = f"invalid sigop cost: {(count) * WITNESS_SCALE_FACTOR} > 80000"
        with pytest.raises(BTClibValueError, match=err_msg):
            block.assert_valid_sig_op_count()
        with pytest.raises(BTClibValueError, match=err_msg):
            block.assert_valid()


def test_a_block_cannot_hold_too_many_transactions_or_too_many_bytes() -> None:
    """Core's bad-blk-length, whose two comparisons are neither the weight.

    A transaction weighs at least one unit, so a block cannot hold more
    of them than MAX_BLOCK_WEIGHT over WITNESS_SCALE_FACTOR: a million,
    and the list here holds one more -- the same coinbase a million and
    one times, which costs a list of pointers rather than a gigabyte of
    transactions. That the count is compared before anything is
    serialized is what makes this half testable at all.

    The other half is the stripped size, reached with a single
    million-byte output script.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    limit = MAX_BLOCK_WEIGHT // WITNESS_SCALE_FACTOR
    assert limit == 1_000_000

    block = Block.parse(block_bytes)
    header, coinbase = block.header, block.transactions[0]

    too_many = Block(header, [coinbase] * (limit + 1), check_validity=False)
    err_msg = f"invalid transaction count: {limit + 1} \\* 4 > {MAX_BLOCK_WEIGHT}"
    with pytest.raises(BTClibValueError, match=err_msg):
        too_many.assert_valid_length()

    block = Block.parse(block_bytes)
    coinbase = block.transactions[0]
    coinbase.vout[0] = TxOut(coinbase.vout[0].value, ScriptPubKey(b"\x00" * limit))
    # the 215 bytes of block 1, less the 67-byte p2pk script and its
    # one-byte length, plus a million and the five bytes announcing it
    assert block.stripped_size == 1_000_152
    err_msg = f"invalid stripped size: 1000152 \\* 4 > {MAX_BLOCK_WEIGHT}"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_length()
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid()


def test_a_block_cannot_weigh_more_than_the_cap() -> None:
    """Core's bad-blk-weight, and why it is asked after the commitment.

    Witness bytes are not in the stripped serialization, so a block can
    pass bad-blk-length and still be over MAX_BLOCK_WEIGHT: block
    481,824 weighs 3,954,880 of the 4,000,000, and 46,000 bytes of
    witness handed to its second transaction take it over while the
    stripped size does not move.

    The same bytes in the *coinbase* witness are what Core's comment
    there is about: the block hash does not cover that witness, so the
    weight must not be what answers before the commitment to it has been
    checked -- a block could otherwise be marked permanently invalid for
    bytes anyone could have appended. btclib asks them in that order, and
    this is where that claim is measured.
    """
    fname = "block_481824_complete.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    stuffing = Witness([b"\x00" * 46_000])

    block = Block.parse(block_bytes)
    block.transactions[1].vin[0].script_witness = stuffing
    assert block.stripped_size == 988_519
    block.assert_valid_length()
    assert block.weight == 4_000_886
    err_msg = f"invalid weight: 4000886 > {MAX_BLOCK_WEIGHT}"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_weight()

    block = Block.parse(block_bytes)
    block.transactions[0].vin[0].script_witness = stuffing
    assert block.weight == 4_000_850
    with pytest.raises(BTClibValueError, match="invalid witness nonce: "):
        block.assert_valid()


def test_a_block_still_requires_the_work() -> None:
    """Block.assert_valid asserts it, as Core's CheckBlock does.

    That is what keeps the vendored block_*.bin files self-verifying:
    Block.parse recomputes the hash from the bytes on every run.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    block.assert_valid()

    # one bit of the nonce flipped is a block whose work no longer holds
    forged = bytearray(block_bytes)
    forged[76] ^= 0x01
    with pytest.raises(BTClibValueError, match="invalid proof-of-work: "):
        Block.parse(bytes(forged))
