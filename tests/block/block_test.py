# Copyright (c) The btclib developers
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

from btclib.block import (
    Block,
    BlockHeader,
    bip34_commitment,
    merkle_root_and_mutated_from_transactions,
)
from btclib.block.limits import (
    MAX_BLOCK_SIGOPS_COST,
    MAX_BLOCK_WEIGHT,
    WITNESS_SCALE_FACTOR,
)
from btclib.block.proof_of_work import REGTEST_POW_LIMIT_BITS
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256, merkle_root_and_mutated_from_hashes
from btclib.network import NETWORKS
from btclib.script import ScriptPubKey
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut
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
    # the upper boundary itself, not only past it: `<= 0x7fffffff`
    # weakened to `<` would refuse the one version every other test
    # vector already carries, and no vector for it means no signal
    header.version = 0x7FFFFFFF
    header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    # a nonce below zero, not only one past the top: `0 <=` loosened to
    # `-1 <=` would let it through, the negative side `> 0x100000000`
    # above never reaches
    header.nonce = -1
    with pytest.raises(BTClibValueError, match="invalid nonce: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.previous_block_hash = b"\xff" * 33
    with pytest.raises(BTClibValueError, match="invalid previous_block_hash length: "):
        header.assert_valid()

    header = BlockHeader.parse(header_bytes)
    header.merkle_root = b"\xff" * 33
    with pytest.raises(BTClibValueError, match="invalid merkle_root length: "):
        header.assert_valid()

    # too short, not just too long: `!= size` weakened to `> size` would
    # still refuse 33 octets and miss 31
    header = BlockHeader.parse(header_bytes)
    header.merkle_root = b"\xff" * 31
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


def test_block_header_defaults() -> None:
    """Every default `__init__` leaves unset, read back off a bare header."""
    header = BlockHeader(check_validity=False)
    assert header.version == 1
    assert header.nonce == 0
    # the epoch itself, not one second either side of it: aware, because
    # a naive one would compare differently depending on the machine
    assert header.time == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_parse_reads_the_timestamp_field_unsigned() -> None:
    """A post-2038 timestamp is not a pre-1970 one misread as negative.

    The field is four unsigned bytes, valid up to 2106 per `assert_valid`;
    `signed=True` would turn one past 2038 negative and `fromtimestamp`
    would still accept the result, silently, rather than raising or even
    landing in the right century.
    """
    time = datetime(2040, 1, 1, tzinfo=timezone.utc)
    header = BlockHeader(
        1,
        bytes(32),
        bytes(32),
        time,
        bytes.fromhex("1d00ffff"),
        0,
        check_validity=False,
    )
    parsed = BlockHeader.parse(
        header.serialize(check_validity=False), check_validity=False
    )
    assert parsed.time == time


def test_check_validity_defaults_to_true_everywhere_it_appears() -> None:
    """`__init__`, `to_dict`, `serialize`, `from_dict`, `parse`: five guards.

    One field breaks two rules at once and is reused throughout: a
    negative version fails `assert_valid` (`0 < version`) and needs
    `signed=True` to survive `serialize` and `parse` without an
    `OverflowError` or a silently different number coming back --
    `to_bytes`/`from_bytes` weakened to `signed=False` would raise on
    the way out and misread on the way back respectively.
    """
    header = BlockHeader(
        -1,
        bytes(32),
        bytes(32),
        datetime(2009, 1, 9, 2, 54, 25, tzinfo=timezone.utc),
        bytes.fromhex("1d00ffff"),
        0,
        check_validity=False,
    )

    with pytest.raises(BTClibValueError, match="invalid version: -0x1"):
        BlockHeader(
            -1,
            bytes(32),
            bytes(32),
            datetime(2009, 1, 9, 2, 54, 25, tzinfo=timezone.utc),
            bytes.fromhex("1d00ffff"),
            0,
        )

    with pytest.raises(BTClibValueError, match="invalid version: -0x1"):
        header.to_dict()
    as_dict = header.to_dict(check_validity=False)
    assert as_dict["version"] == -1

    with pytest.raises(BTClibValueError, match="invalid version: -0x1"):
        header.serialize()
    as_bytes = header.serialize(check_validity=False)
    assert as_bytes[:4] == (-1).to_bytes(4, "little", signed=True)

    with pytest.raises(BTClibValueError, match="invalid version: -0x1"):
        BlockHeader.from_dict(as_dict)
    assert BlockHeader.from_dict(as_dict, check_validity=False) == header

    with pytest.raises(BTClibValueError, match="invalid version: -0x1"):
        BlockHeader.parse(as_bytes)
    assert BlockHeader.parse(as_bytes, check_validity=False) == header

    # `hash` always serializes with check_validity=False, whatever the
    # header's own state: True there would refuse the very header being
    # hashed, which is what mining a not-yet-valid candidate does not do
    assert header.hash


def _coinbase_and_a_transaction_missing_its_outputs() -> tuple[Tx, Tx]:
    """Return a valid coinbase and a second transaction `assert_valid` refuses.

    Shared by the tests below: each exercises a different place that
    must serialize or dict-ify the second transaction without judging
    it, `Block.assert_valid` -- or a real caller's own -- being what
    judges it instead, once.
    """
    coinbase = Tx(
        1,
        0,
        [TxIn(OutPoint(bytes(32), 0xFFFFFFFF), b"\x01\x01", 0xFFFFFFFF, Witness())],
        [TxOut(0, b"\x6a")],
        check_validity=False,
    )
    missing_outputs = Tx(
        1,
        0,
        [TxIn(OutPoint(bytes(32), 0), b"\x00", 0xFFFFFFFF, Witness())],
        [],
        check_validity=False,
    )
    return coinbase, missing_outputs


def test_block_check_validity_defaults_to_true_everywhere_it_appears() -> None:
    """`__init__`, `to_dict`, `serialize`, `from_dict`: the same four guards.

    `BlockHeader`'s own test names, plus the header and every transaction
    dict-ified or read back at their own default in the process.
    """
    coinbase, missing_outputs = _coinbase_and_a_transaction_missing_its_outputs()
    header = BlockHeader(
        0,  # invalid on its own, so the header dict/from_dict calls below
        # cannot pass by accident
        bytes(32),
        bytes(32),
        datetime(2009, 1, 9, 2, 54, 25, tzinfo=timezone.utc),
        bytes.fromhex("1d00ffff"),
        0,
        check_validity=False,
    )
    block = Block(header, [coinbase, missing_outputs], check_validity=False)

    with pytest.raises(BTClibValueError, match="invalid version: "):
        Block(header, [coinbase, missing_outputs])

    with pytest.raises(BTClibValueError, match="invalid version: "):
        block.to_dict()
    as_dict = block.to_dict(check_validity=False)
    assert as_dict["header"]["version"] == 0
    assert as_dict["transactions"][1]["vout"] == []

    with pytest.raises(BTClibValueError, match="invalid version: "):
        block.serialize()
    assert block.serialize(check_validity=False)

    with pytest.raises(BTClibValueError, match="invalid version: "):
        Block.from_dict(as_dict)
    assert Block.from_dict(as_dict, check_validity=False) == block


def test_merkle_root_and_witness_commitment_serialize_without_judging() -> None:
    """The two internal hash loops over transactions, at their own default.

    `merkle_root_and_mutated_from_transactions` and the witness-tree
    loop inside `assert_valid_witness_commitment` each serialize every
    transaction with `check_validity=False`: `True` there would raise
    on the second transaction's own account, rather than leaving that
    to whichever `assert_valid` call the caller made once, outside
    either loop.
    """
    coinbase, missing_outputs = _coinbase_and_a_transaction_missing_its_outputs()

    root, mutated = merkle_root_and_mutated_from_transactions(
        [coinbase, missing_outputs]
    )
    assert root
    assert not mutated

    nonce = bytes(32)
    hashes = [
        b"\x00" * 32,
        hash256(missing_outputs.serialize(True, check_validity=False)),
    ]
    witness_root = merkle_root_and_mutated_from_hashes(hashes, hash256)[0]
    commitment = hash256(witness_root + nonce)
    coinbase.vin[0].script_witness = Witness([nonce])
    coinbase.vout[0] = TxOut(
        0, ScriptPubKey(bytes.fromhex("6a24aa21a9ed") + commitment)
    )

    header = BlockHeader(check_validity=False)
    block = Block(header, [coinbase, missing_outputs], check_validity=False)
    block.assert_valid_witness_commitment()


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

    # a computed root that sorts *above* the claimed one, not only below
    # it: `!= self.header.merkle_root` weakened to `<` would miss this
    # direction, which the vector in test_block_200000 does not exercise
    block.transactions.pop()
    with pytest.raises(BTClibValueError, match="invalid merkle root: "):
        block.assert_valid_merkle_root()


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
    # only version 1 skips the BIP34 decode, not version 0 too: `== 1`
    # weakened to `<= 1` would read this same coinbase as heightless
    block.header.version = 0
    assert block.height == 200_000
    block.header.version = 2
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


def test_vsize_rounds_up_a_weight_that_is_not_a_multiple_of_four() -> None:
    """988,720 above is exact; `/ 4` weakened to `// 4` needs a remainder.

    One more byte of witness moves the weight by one without moving the
    stripped size at all, which is what a witness byte costs.
    """
    fname = "block_481824_complete.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    stack = block.transactions[1].vin[0].script_witness.stack
    block.transactions[1].vin[0].script_witness = Witness([*stack, b"\x00"])
    assert block.weight == 3_954_885
    assert block.vsize == 988_722


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

    # a wrong commitment that sorts *below* the claimed one, not only
    # above it: `!= commitment` weakened to `>` would miss this
    # direction, both other vectors here happening to sort the other way
    block = Block.parse(block_bytes)
    block.transactions[0].vin[0].script_witness = Witness([bytes([21]) * 32])
    computed = "4f367b1b732e90a5f2892968cbdfa0955d089882ca0c377b368063cc24b71228"
    assert computed < commitment
    err_msg = f"invalid witness commitment: {commitment} instead of: {computed}"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_witness_commitment()


def test_witness_commitment_output_may_carry_more_than_the_commitment() -> None:
    """`>= _COMMITMENT_LENGTH`, not `==` or `<=`: trailing bytes are legal.

    Nothing in BIP141 bounds the output script from above, and Core's
    own GetWitnessCommitmentIndex does not either -- the 32 bytes right
    after the prefix are the commitment regardless of what, if
    anything, follows them.
    """
    commitment = bytes(range(32))
    extra_script = bytes.fromhex("6a24aa21a9ed") + commitment + b"\xff\xff"
    tx = Tx(
        1,
        0,
        [TxIn(OutPoint(bytes(32), 0xFFFFFFFF), b"\x00", 0xFFFFFFFF, Witness())],
        [TxOut(0, ScriptPubKey(extra_script))],
        check_validity=False,
    )
    block = Block(BlockHeader(check_validity=False), [tx], check_validity=False)
    assert block.witness_commitment == commitment


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
    "height, nbits, difficulty",
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


def test_difficulty_decodes_bits_once() -> None:
    """The difficulty and the target decode `bits` once (issue #402).

    `difficulty` used to redo the compact arithmetic itself, so masking
    the sign bit in `target_from_bits` alone would leave one header with
    two answers: a target with the bit taken off and a difficulty
    computed with it in. The genesis bits signed are the case that shows
    it -- difficulty 1, which is what the unsigned spelling gives, and
    not the 0.00775 of a target 2^7 easier.
    """
    genesis = BlockHeader(bits="1d00ffff", check_validity=False)
    signed = BlockHeader(bits="1d80ffff", check_validity=False)

    assert signed.target == genesis.target
    assert signed.difficulty == genesis.difficulty == 1

    # a zero target is no ratio to take, and the answer is the refusal
    # assert_valid_pow and block_work give it rather than a
    # ZeroDivisionError out of the library. Both spellings: an exponent
    # that shifts the significand away, and a significand that is only
    # the sign bit
    for bits in ("00000000", "0000ffff", "03800000"):
        header = BlockHeader(bits=bits, check_validity=False)
        with pytest.raises(BTClibValueError, match="zero proof-of-work target: "):
            _ = header.difficulty


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


def test_bip34_commitment_op_int_range_is_minus_one_to_sixteen() -> None:
    """The op-code branch is `-1..16`, not one wider on either side.

    -1 is `OP_1NEGATE` and the boundary itself; -2 is a minimal data
    push instead and the value `op_int` refuses, which is what tells
    `<=` weakened to `!=`, to `<`, and `-1` itself replaced by `~1`
    (also -2) or by `-0` apart: each moves one boundary, and the two
    values here are the two boundaries.
    """
    assert bip34_commitment(-1) == bytes.fromhex("4f")
    assert bip34_commitment(-2) == bytes.fromhex("0182")
    assert bip34_commitment(16) == bytes.fromhex("60")
    assert bip34_commitment(17) == bytes.fromhex("0111")


def test_assert_valid_coinbase_height_reads_the_first_transaction() -> None:
    """`self.transactions[0]`, on a coinbase a second transaction is not.

    Block 200,000 is BIP34 and multi-transaction, so a `vin[0]`
    weakened to the *last* transaction's reads a script_sig that never
    started with the height commitment to begin with.
    """
    fname = "block_200000.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block = Block.parse(file_.read())

    block.assert_valid_coinbase_height(200_000)


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


def test_assert_valid_checks_the_first_transaction_and_not_the_last() -> None:
    """`self.transactions[0]` and not `[-1]`, on a block that tells them apart.

    Block 1 above has one transaction, where the two names the same
    object: `self.transactions[0].assert_valid()` weakened to `[-1]`
    needs a second transaction to be told from the loop that already
    validates every one but the first.
    """
    fname = "block_200000.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block = Block.parse(file_.read())

    assert len(block.transactions) > 1
    block.transactions[0].vin[0].script_sig = b"\x00" * 101
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
    "fname, delta",
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

    # the cap itself, not only one past it: `> MAX_BLOCK_WEIGHT` weakened
    # to `>=` would refuse a block every node on the network accepts
    block = Block.parse(block_bytes)
    block.transactions[1].vin[0].script_witness = Witness([b"\x00" * 45_114])
    assert block.weight == MAX_BLOCK_WEIGHT
    block.assert_valid_weight()


def test_the_length_and_weight_caps_are_reachable_not_only_crossable() -> None:
    """The count, the stripped size and the weight, each at its own cap.

    Three `>` comparisons weakened to `>=` would each refuse the one
    value the rule is written to allow, and none of the three vectors
    above happens to land on it.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    limit = MAX_BLOCK_WEIGHT // WITNESS_SCALE_FACTOR
    parsed = Block.parse(block_bytes)

    # the count cap: a million transactions is not too many, whatever
    # `assert_valid_length` finds wrong with them next
    at_cap = Block(
        parsed.header, [parsed.transactions[0]] * limit, check_validity=False
    )
    with pytest.raises(BTClibValueError, match="invalid stripped size: "):
        at_cap.assert_valid_length()

    # the stripped-size cap, this time genuinely unrefused: the 215
    # bytes of block 1, less its 68-byte scripted output, plus one this
    # size exactly
    block = Block.parse(block_bytes)
    block.transactions[0].vout[0] = TxOut(
        block.transactions[0].vout[0].value, ScriptPubKey(b"\x00" * 999_848)
    )
    assert block.stripped_size == limit
    block.assert_valid_length()


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


def test_assert_valid_pow_makes_derive_targets_range_checks() -> None:
    """Four targets are refused before the hash is looked at.

    `fNegative`, a zero target, `fOverflow` and a target above the
    network's pow limit: the four disjuncts of the one condition in
    Core's `DeriveTarget`, which `CheckProofOfWorkImpl` answers with a
    bare false for all four. btclib says which of the four it was, and
    the order is Core's -- 0x1d80ffff is above mainnet's limit as well as
    negative, and it is refused as negative (issue #403).
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        header_bytes = file_.read()[:80]

    header = BlockHeader.parse(header_bytes)
    # the regression guard for the whole change: the first mainnet block
    # after genesis carries mainnet's limit as its bits, so it sits on
    # the boundary all four checks are drawn around
    header.assert_valid_pow()

    # 0x22ffffff is not among them: it overflows *and* is negative, and
    # Core reads fNegative first, so it is the row that would not tell
    # the two apart. 0xff000001 overflows with the sign bit clear
    for bits_hex, err_msg in (
        ("1d80ffff", "negative proof-of-work target: "),
        ("0000ffff", "zero proof-of-work target: "),
        ("ff000001", "invalid proof-of-work target: "),
        ("207fffff", "proof-of-work target above the limit: "),
    ):
        header.bits = bytes.fromhex(bits_hex)
        with pytest.raises(BTClibValueError, match=err_msg):
            header.assert_valid_pow()


@pytest.mark.parametrize("bits_hex", ["03800000", "1d800000"])
def test_the_zero_target_check_is_only_as_good_as_the_target(bits_hex: str) -> None:
    """Two nBits Core reads as zero, and so does btclib.

    `SetCompact` masks the significand with 0x007fffff before computing
    the value, so `nWord` is zero for both of these and `DeriveTarget`
    refuses the header on `bnTarget == 0`. btclib used to read the sign
    bit as magnitude, which made 0x03800000 a target of 2^23 and
    0x1d800000 one of 2^215, and the zero check fired for neither: the
    check was only as good as the number it was handed (issue #402).
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        header_bytes = file_.read()[:80]

    header = BlockHeader.parse(header_bytes)
    header.bits = bytes.fromhex(bits_hex)
    with pytest.raises(BTClibValueError, match="zero proof-of-work target: "):
        header.assert_valid_pow()


def test_the_pow_limit_is_the_callers_to_state() -> None:
    """A header carries no network, so nothing but the caller knows one.

    Block 1's hash is far below regtest's target, so a header claiming
    regtest's bits on mainnet is the block Core rejects and btclib used
    to accept (issue #403). What tells the two apart is the limit passed
    in, and Block.assert_valid forwards it so a block is answered for the
    same network its header is.
    """
    fname = "block_1.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        block_bytes = file_.read()

    block = Block.parse(block_bytes)
    block.header.bits = REGTEST_POW_LIMIT_BITS

    # the work satisfies the target it claims, and the target is one no
    # mainnet block may claim
    assert block.header.hash <= block.header.target
    with pytest.raises(BTClibValueError, match="target above the limit: "):
        block.assert_valid()

    # and the same block is a block on the network those bits belong to
    block.assert_valid(REGTEST_POW_LIMIT_BITS)
