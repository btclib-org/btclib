# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx` module.

`_data/<txid>.bin` is consensus bytes rather than a vendored vector: the
file is named after the txid `Tx.parse` recomputes from it, so a corrupted
copy announces itself, and `bitcoin-cli getrawtransaction <txid>` returns
those bytes given a node with the transaction index.
tests/_data/README.md has its size and wtxid.
"""

import dataclasses
import inspect
from collections.abc import MutableSequence
from pathlib import Path
from typing import Any

import pytest

from btclib import var_int
from btclib.consensus import MAX_BLOCK_WEIGHT, WITNESS_SCALE_FACTOR
from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey, Witness, sig_op_count
from btclib.tx import OutPoint, Tx, TxIn, TxOut, join
from btclib.tx.limits import (
    MAX_TX_IN_COUNT,
    MAX_TX_OUT_COUNT,
    MIN_TX_IN_SIZE,
    MIN_TX_OUT_SIZE,
)
from btclib.tx.tx import _assert_valid_coinbase
from tests.conftest import JsonGolden


def test_tx() -> None:
    """Round-trip Tx through parse, serialize and dict, segwit included."""
    # default constructor
    tx = Tx(check_validity=False)
    assert not tx.is_segwit
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase
    assert tx.version == 1
    assert tx.lock_time == 0
    assert not tx.vin
    assert not tx.vout
    assert tx.nVersion == tx.version
    assert tx.nLockTime == tx.lock_time
    tx_id = "d21633ba23f70118185227be58a63527675641ad37967e2aa461559f577aec43"
    assert tx.id.hex() == tx_id
    assert tx.hash == tx.id
    assert tx.size == 10
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4

    with pytest.raises(BTClibValueError, match="Missing inputs"):
        Tx(vout=[TxOut(0, ScriptPubKey(""))])
    with pytest.raises(BTClibValueError, match="Missing outputs"):
        Tx(vin=[TxIn(script_sig="0000")])

    tx_2 = Tx.from_dict(tx.to_dict(check_validity=False), check_validity=False)
    assert tx_2.is_segwit == tx.is_segwit
    assert tx_2 == tx

    tx_2 = Tx.parse(
        tx.serialize(include_witness=True, check_validity=False), check_validity=False
    )
    assert tx_2.is_segwit == tx.is_segwit
    assert tx_2 == tx

    tx_2 = Tx.parse(
        tx.serialize(include_witness=False, check_validity=False), check_validity=False
    )
    assert not tx_2.is_segwit
    assert tx_2 == tx

    # non-default constructor, no segwit
    prev_out = OutPoint(
        "9dcfdb5836ecfe146bdaa896605ba21222f83cd014dd47adde14fab2aba7de9b", 1
    )
    script_sig = b""
    sequence = 0xFFFFFFFF
    tx_in = TxIn(prev_out, script_sig, sequence)

    tx.vin = [tx_in]
    with pytest.raises(BTClibValueError, match="Missing outputs"):
        tx.assert_valid()

    tx_out1 = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    tx_out2 = TxOut(
        6381891, "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
    )
    version = 1
    lock_time = 0
    tx = Tx(version, lock_time, [tx_in], [tx_out1, tx_out2])
    assert not tx.is_segwit
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase
    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.nVersion == tx.version
    assert tx.nLockTime == tx.lock_time
    tx_id = "4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c"
    assert tx.id.hex() == tx_id
    assert tx.hash == tx.id
    assert tx.size == 126
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4

    tx_2 = Tx.from_dict(tx.to_dict())
    assert tx_2.is_segwit == tx.is_segwit
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=True))
    assert tx_2.is_segwit == tx.is_segwit
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=False))
    assert not tx_2.is_segwit
    assert tx_2 == tx

    # non-default constructor, with segwit
    version = 1
    lock_time = 0
    tx = Tx(version, lock_time, [tx_in], [tx_out1, tx_out2])
    stack = [
        "",
        "30440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d01",
        "30440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f4401",
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
    ]
    tx.vin[0].script_witness = Witness(stack)
    assert tx.is_segwit
    assert any(bool(w) for w in tx.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase
    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.nVersion == tx.version
    assert tx.nLockTime == tx.lock_time
    tx_id = "4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c"
    assert tx.id.hex() == tx_id
    hash_ = "d39eb3e3954be4bdc0b3be2d980124b1e1e11fb414b886b52939b07d95a58a8f"
    assert tx.hash.hex() == hash_
    assert tx.size == 380
    assert tx.vsize == 190
    assert tx.weight == 758

    tx_2 = Tx.from_dict(tx.to_dict())
    assert tx_2.is_segwit == tx.is_segwit
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=True))
    assert tx_2.is_segwit == tx.is_segwit
    assert tx_2 == tx

    tx_2 = Tx.parse(tx.serialize(include_witness=False))
    assert not tx_2.is_segwit
    assert tx_2 != tx

    tx.version = 0
    tx.assert_valid()


def test_exceptions() -> None:
    """Refuse a version or lock time that four bytes cannot hold."""
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid version: "):
        tx.assert_valid()

    tx = Tx.parse(tx_bytes)
    tx.lock_time = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid lock time: "):
        tx.assert_valid()


def test_the_four_byte_fields_at_their_bounds() -> None:
    """Zero and 0xFFFFFFFF are in the range, -1 and one more are out.

    Both ends of both fields, and the accepted end is the half a refusal
    test cannot state: a bound one too tight or one too loose refuses a
    transaction that is in a block, which is the direction that cannot be
    noticed from the outside.
    """
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0))
    tx_out = TxOut(1, "")

    for value in (0, 1, 0xFFFFFFFE, 0xFFFFFFFF):
        Tx(value, 0, [tx_in], [tx_out]).assert_valid()
        Tx(1, value, [tx_in], [tx_out]).assert_valid()

    for value in (-1, 0xFFFFFFFF + 1):
        with pytest.raises(BTClibValueError, match="invalid version: "):
            Tx(value, 0, [tx_in], [tx_out])
        with pytest.raises(BTClibValueError, match="invalid lock time: "):
            Tx(1, value, [tx_in], [tx_out])


def test_the_top_of_the_four_byte_range_round_trips() -> None:
    """Version and lock_time are unsigned on the wire, and above 2^31 too.

    Read or written as signed, a version of 0xFFFFFFFF comes back as -1
    and 0x80000000 does not serialize at all, so a transaction below
    0x80000000 cannot tell the two spellings apart. Both are valid
    versions, which is the other half of the boundary: `assert_valid`
    takes the whole four-byte range and `assert_standard` refuses this
    end of it -- what Core's own field is, signed in v27.2 and unsigned
    in v31.1, is a different question, and no assertion here needs it.
    """
    tx = Tx(
        0xFFFFFFFF,
        0xFFFFFFFF,
        [TxIn(OutPoint(b"\x01" * 32, 0))],
        [TxOut(1, "")],
    )
    tx_bytes = tx.serialize(include_witness=True)
    assert tx_bytes.endswith(b"\xff" * 4)  # the lock time, little endian
    assert tx_bytes.startswith(b"\xff" * 4)  # and the version before it

    parsed = Tx.parse(tx_bytes)
    assert parsed.version == 0xFFFFFFFF
    assert parsed.lock_time == 0xFFFFFFFF
    assert parsed == tx


def test_a_standard_version_is_core_v31_1s_window() -> None:
    """Versions 1 through 3 are standard; 0, 4 and a set top bit are not.

    Core v31.1's policy.h: 1 and 2 are standard for v27.2 and v31.1
    alike, 3 is v31.1's own addition, BIP431's TRUC, and everything
    outside 1..3 is refused, immediately below and above it as well as
    every version whose top bit is set (issue #387).

    What the low end is worth saying is that these are valid versions:
    `assert_valid` takes zero and takes 0xFFFFFFFF, standardness being the
    narrower question and the only one asked about relay.
    """
    tx = Tx(1, 0, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(1, "")])

    for version in (1, 2, 3):
        tx.version = version
        tx.assert_standard()

    for version in (0, 4, 0x80000000, 0xFFFFFFFF):
        tx.version = version
        tx.assert_valid()
        with pytest.raises(BTClibValueError, match="invalid version: "):
            tx.assert_standard()


def test_the_coinbase_script_size_window() -> None:
    """A coinbase script_sig is 2 to 100 bytes, both included.

    Consensus writes the rule as an inclusive range, so both ends are a
    valid coinbase and one byte outside either is not: a bound one off
    would reject a block that is in the chain, or accept one that is not.
    """
    tx_out = TxOut(1, "")

    for size in (2, 3, 99, 100):
        Tx(vin=[TxIn(OutPoint(), b"\x00" * size)], vout=[tx_out]).assert_valid()

    for size in (0, 1, 101, 200):
        with pytest.raises(BTClibValueError, match="Invalid coinbase script size"):
            Tx(vin=[TxIn(OutPoint(), b"\x00" * size)], vout=[tx_out])


def test_an_invalid_input_or_output_fails_the_transaction() -> None:
    """assert_valid asks every input and every output, not only the sums.

    A negative sequence and a negative amount are each invalid on their
    own while leaving every transaction-level check happy -- the output
    total is still inside MoneyRange -- so nothing but the delegation
    catches them.
    """
    prev_out = OutPoint(b"\x01" * 32, 0)

    tx_in = TxIn(prev_out, b"", -1, check_validity=False)
    tx = Tx(1, 0, [tx_in], [TxOut(1, "")], check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid sequence: "):
        tx.assert_valid()

    tx_out = TxOut(-1, "", check_validity=False)
    tx = Tx(1, 0, [TxIn(prev_out)], [tx_out], check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
        tx.assert_valid()


def test_sig_op_count_adds_the_two_sides() -> None:
    """The count is the sum of both lists, which is not a mix of them.

    One sigop in the inputs and one in the outputs is the case that says
    so: a bitwise operator in place of the sum answers one or zero for it,
    and answers correctly for a transaction whose inputs announce none.
    """
    check_sig = b"\xac"  # OP_CHECKSIG, one sigop wherever it is

    tx = Tx(
        1,
        0,
        [TxIn(OutPoint(b"\x01" * 32, 0), check_sig)],
        [TxOut(1, check_sig)],
    )
    assert sig_op_count(tx.vin[0].script_sig) == 1
    assert sig_op_count(tx.vout[0].script_pub_key.script) == 1
    assert tx.sig_op_count == 2


def test_output_total_is_bounded() -> None:
    """The outputs are bounded one by one and then as a sum.

    Two outputs of MAX_MONEY are two valid amounts, and a transaction
    paying out twice the money there will ever be: CheckTransaction has
    both checks, so btclib needs both, each with the right bound
    (issue 167).
    """
    max_money = 2_100_000_000_000_000
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0))

    # one output of exactly MAX_MONEY is valid: MoneyRange is inclusive
    Tx(vin=[tx_in], vout=[TxOut(max_money, "")]).assert_valid()

    err_msg = "invalid satoshi amount: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[tx_in], vout=[TxOut(max_money + 1, "")])

    # each output within MoneyRange, their sum outside it
    err_msg = "invalid total output amount: "
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[tx_in], vout=[TxOut(max_money, ""), TxOut(1, "")])
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[tx_in], vout=[TxOut(max_money // 2 + 1, "")] * 2)


def test_one_outpoint_is_spent_once() -> None:
    """An outpoint named twice is refused, as `bad-txns-inputs-duplicate`.

    Core's CheckTransaction has the rule and CVE-2018-17144 is what it
    was worth: the transaction spends one output twice, so anything
    computing over its inputs -- a fee, a total, an ancestor set --
    answers for a transaction that cannot be mined.
    """
    out_point = OutPoint(b"\x01" * 32, 0)
    tx_out = TxOut(1000, "")

    err_msg = "the same outpoint is spent twice"
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[TxIn(out_point), TxIn(out_point)], vout=[tx_out])

    # the sequence is no part of the outpoint, so two inputs differing
    # only there are the same double spend
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[TxIn(out_point, b"", 0), TxIn(out_point, b"", 1)], vout=[tx_out])

    # a psbt's transaction is refused as well: `unsigned_template` drops
    # the two rules that transaction cannot satisfy while it is being
    # built, and nothing makes a duplicate one of them
    tx = Tx(vin=[TxIn(out_point)], vout=[tx_out])
    tx.vin.append(TxIn(out_point))
    with pytest.raises(BTClibValueError, match=err_msg):
        tx.assert_valid(unsigned_template=True)

    # and what the refusal must not take with it: two outputs of one
    # transaction, and one output index of two transactions, are two
    # outpoints either way
    Tx(
        vin=[TxIn(out_point), TxIn(OutPoint(b"\x01" * 32, 1))],
        vout=[tx_out],
    ).assert_valid()
    Tx(
        vin=[TxIn(out_point), TxIn(OutPoint(b"\x02" * 32, 0))],
        vout=[tx_out],
    ).assert_valid()


def test_standard() -> None:
    """Verify assert_standard refuses a version assert_valid accepts."""
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid version: "):
        tx.assert_standard()

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF
    tx.assert_valid()

    tx = Tx.parse(tx_bytes)
    tx.version = 0xFFFFFFFF
    with pytest.raises(BTClibValueError, match="invalid version: "):
        tx.assert_standard()


def test_coinbase_block_1() -> None:
    """Round-trip block 1's coinbase and count its single sigop."""
    coinbase_out = "00f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac"
    tx_out = TxOut.parse(coinbase_out)
    assert tx_out.serialize().hex() == coinbase_out

    coinbase_inp = (  # prev_out
        "0000000000000000000000000000000000000000000000000000000000000000ffffffff"
        "0704ffff001d0104"  # script_sig
        "ffffffff"  # sequence
    )
    tx_in = TxIn.parse(coinbase_inp)
    assert tx_in.serialize().hex() == coinbase_inp
    assert tx_in.prev_out.is_coinbase

    coinbase = f"0100000001{coinbase_inp}01{coinbase_out}00000000"
    tx = Tx.parse(coinbase)
    assert tx.serialize(include_witness=True).hex() == coinbase
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 1

    assert tx.vin[0].script_sig == tx_in.script_sig
    assert tx.vout[0].script_pub_key == tx_out.script_pub_key

    tx_id = "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
    assert tx.id.hex() == tx_id
    assert tx.id == tx.hash

    assert tx.size == 134
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4
    assert not tx.is_segwit
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert tx.is_coinbase

    # the p2pk output announces one signature check; the coinbase
    # script_sig announces none, pushing the extranonce and nothing else
    assert tx.sig_op_count == 1
    assert sig_op_count(tx.vin[0].script_sig) == 0
    assert sig_op_count(tx.vout[0].script_pub_key.script) == 1


def test_the_other_two_flags_stay_keyword_only() -> None:
    """`unsigned_template` and `is_coinbase` sit behind a star as well.

    tests/check_validity_test.py states the rule for the flag it is named
    after, and these are the two in this module that are not it: the hazard
    is the same one, a parameter added in front of a positional flag taking
    its slot in silence, and a keyword-only one makes that call a TypeError
    instead. `_assert_valid_coinbase` is private and reached here directly,
    a keyword call being all `Tx.assert_valid` can say about it.
    """
    tx = Tx(1, 0, [TxIn(OutPoint(b"\x01" * 32, 0))], [TxOut(1, "")])

    with pytest.raises(TypeError, match="positional argument"):
        tx.assert_valid(True)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="positional argument"):
        _assert_valid_coinbase(tx.vin, False)  # type: ignore[call-arg]

    # and what the refusal must not take with it
    tx.assert_valid(unsigned_template=True)
    _assert_valid_coinbase(tx.vin, is_coinbase=False)


def test_a_coinbase_input_belongs_to_a_coinbase_only() -> None:
    """The null outpoint is refused where the transaction is not a coinbase.

    Two inputs make `is_coinbase` false whatever they are, so the null
    outpoint among them spends an output that does not exist and creates
    the coinbase's money outside a coinbase. Core's CheckTransaction has
    the rule; here it was the only statement of `btclib/tx` that the
    directory's own tests never reached -- a script_engine vector did,
    which is a verdict on the engine and no test of this one.
    """
    coinbase_in = TxIn(OutPoint())
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0))
    tx_out = TxOut(1, "")

    err_msg = "coinbase input in a non-coinbase transaction"
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[tx_in, coinbase_in], vout=[tx_out])
    with pytest.raises(BTClibValueError, match=err_msg):
        Tx(vin=[coinbase_in, tx_in], vout=[tx_out])

    # and what the refusal must not take with it: the coinbase itself,
    # whose single input is that very outpoint, with a script_sig of the
    # size consensus wants
    Tx(vin=[TxIn(OutPoint(), b"\x00\x00")], vout=[tx_out]).assert_valid()


# https://en.bitcoin.it/wiki/Protocol_documentation#tx
def test_wiki_transaction() -> None:
    """Reproduce the wiki's protocol-documentation example transaction."""
    tx_bytes = "01000000016dbddb085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a59233f45bc578380022059af01ca17d00e41837a1d58e97aa31bae584edec28d35bd96923690913bae9a0141049c02bfc97ef236ce6d8fe5d94013c721e915982acd2b12b65d9b7d59e20a842005f8fc4e02532e873d37b96f09d6d4511ada8f14042f46614a4c70c0f14beff5ffffffff02404b4c00000000001976a9141aa0cd1cbea6e7458a7abad512a9d9ea1afb225e88ac80fae9c7000000001976a9140eab5bea436a0484cfab12485efda0b78b4ecc5288ac00000000"
    tx = Tx.parse(tx_bytes)
    assert tx.serialize(include_witness=True).hex() == tx_bytes
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2
    assert tx.vout[0].value == 5000000
    assert tx.vout[1].value == 3354000000

    tx_id = "d4a73f51ab7ee7acb4cf0505d1fab34661666c461488e58ec30281e2becd93e2"
    assert tx.id.hex() == tx_id
    assert tx.hash == tx.id
    assert tx.size == 258
    assert tx.vsize == tx.size
    assert tx.weight == tx.size * 4
    assert not tx.is_segwit
    assert not any(bool(w) for w in tx.vwitness)
    assert not any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase

    # Core's GetLegacySigOpCount, which is the sum over both lists: the
    # two p2pkh outputs announce one check each, and the script_sig
    # answering the p2pkh being spent announces none -- it pushes a
    # signature and a key, and the OP_CHECKSIG that verifies them is in
    # the output this transaction spends, i.e. in another block. Which is
    # what makes the count an underestimate, and what makes it the one a
    # block can be checked against on its own
    assert tx.sig_op_count == 2
    assert sig_op_count(tx.vin[0].script_sig) == 0


def test_single_witness() -> None:
    """Round-trip a one-input segwit transaction, witness included."""
    # 4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
    tx = Tx.parse(tx_bytes)
    assert tx.serialize(include_witness=True).hex() == tx_bytes
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 1
    assert len(tx.vout) == 2

    stack = [
        "",
        "30440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d01",
        "30440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f4401",
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
    ]
    witness = Witness(stack)
    assert tx.vin[0].script_witness == witness

    tx_id = "4e52f7848dab7dd89ef7ba477939574198a170bfcb2fb34355c69f5e0169f63c"
    assert tx.id.hex() == tx_id
    hash_ = "d39eb3e3954be4bdc0b3be2d980124b1e1e11fb414b886b52939b07d95a58a8f"
    assert tx.hash.hex() == hash_
    assert tx.size == 380
    assert tx.vsize == 190
    assert tx.weight == 758
    assert tx.is_segwit
    assert any(bool(w) for w in tx.vwitness)
    assert not tx.is_coinbase


def test_double_witness() -> None:
    """Round-trip a two-input segwit transaction, witness included."""
    tx_bytes = "01000000000102322d4f05c3a4f78e97deda01bd8fc5ff96777b62c8f2daa72b02b70fa1e3e1051600000017160014e123a5263695be634abf3ad3456b4bf15f09cc6afffffffffdfee6e881f12d80cbcd6dc54c3fe390670678ebd26c3ae2dd129f41882e3efc25000000171600145946c8c3def6c79859f01b34ad537e7053cf8e73ffffffff02c763ac050000000017a9145ffd6df9bd06dedb43e7b72675388cbfc883d2098727eb180a000000001976a9145f9e96f739198f65d249ea2a0336e9aa5aa0c7ed88ac024830450221009b364c1074c602b2c5a411f4034573a486847da9c9c2467596efba8db338d33402204ccf4ac0eb7793f93a1b96b599e011fe83b3e91afdc4c7ab82d765ce1da25ace01210334d50996c36638265ad8e3cd127506994100dd7f24a5828155d531ebaf736e160247304402200c6dd55e636a2e4d7e684bf429b7800a091986479d834a8d462fbda28cf6f8010220669d1f6d963079516172f5061f923ef90099136647b38cc4b3be2a80b820bdf90121030aa2a1c2344bc8f38b7a726134501a2a45db28df8b4bee2df4428544c62d731400000000"
    tx = Tx.parse(tx_bytes)
    assert tx.serialize(include_witness=True).hex() == tx_bytes
    assert tx == Tx.from_dict(tx.to_dict())

    assert tx.version == 1
    assert tx.lock_time == 0
    assert len(tx.vin) == 2
    assert len(tx.vout) == 2

    stack1 = [
        "30450221009b364c1074c602b2c5a411f4034573a486847da9c9c2467596efba8db338d33402204ccf4ac0eb7793f93a1b96b599e011fe83b3e91afdc4c7ab82d765ce1da25ace01",
        "0334d50996c36638265ad8e3cd127506994100dd7f24a5828155d531ebaf736e16",
    ]
    witness1 = Witness(stack1)
    assert tx.vin[0].script_witness == witness1

    stack2 = [
        "304402200c6dd55e636a2e4d7e684bf429b7800a091986479d834a8d462fbda28cf6f8010220669d1f6d963079516172f5061f923ef90099136647b38cc4b3be2a80b820bdf901",
        "030aa2a1c2344bc8f38b7a726134501a2a45db28df8b4bee2df4428544c62d7314",
    ]
    witness2 = Witness(stack2)
    assert tx.vin[1].script_witness == witness2

    tx_id = "a4b76807519aba5740f7865396bc4c5ca0eb8aa7c3744ca2db88fcc9e345424c"
    assert tx.id.hex() == tx_id
    hash_ = "0936cb8dba90e11345b9c05f457f139ddce4a5329701af4708b2cf4a02d75adb"
    assert tx.hash.hex() == hash_
    assert tx.size == 421
    assert tx.vsize == 259
    assert tx.weight == 1033
    assert tx.is_segwit
    assert any(bool(w) for w in tx.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert not tx.is_coinbase


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    """Round-trip a segwit Tx through its dict and golden json."""
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as binary_file_:
        tx = Tx.parse(binary_file_.read())

    # Tx dataclass, which is what `fields` reads and `isinstance` cannot
    # say: __init__, __eq__ and every conversion here are written out, so
    # the decorator is left holding the field list and the repr
    assert isinstance(tx, Tx)
    assert [f.name for f in dataclasses.fields(tx)] == [
        "version",
        "lock_time",
        "vin",
        "vout",
    ]
    assert tx.is_segwit
    assert any(bool(w) for w in tx.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx.vin)
    assert tx.vin[0].script_witness
    assert tx.vin[0].script_witness.stack

    # Tx dataclass to dict
    tx_dict = tx.to_dict()
    assert isinstance(tx_dict, dict)
    assert tx_dict["vin"][0]["txinwitness"]["stack"]  # type: ignore[index]

    # against the json committed beside this module, not written to it
    json_golden("tx.json", tx_dict)

    # Tx dataclass from dict
    tx2 = Tx.from_dict(tx_dict)
    assert isinstance(tx2, Tx)
    assert tx.vin[0] == tx2.vin[0]
    assert tx2.vin[0].script_witness
    assert tx2.vin[0].script_witness.stack
    assert tx2.is_segwit
    assert any(bool(w) for w in tx2.vwitness)
    assert any(bool(tx_in.script_witness) for tx_in in tx2.vin)

    assert tx == tx2


def test_join() -> None:
    """Verify join concatenates two transactions and what it refuses."""
    tx_bytes = "010000000001019bdea7abb2fa14dead47dd14d03cf82212a25b6096a8da6b14feec3658dbcf9d0100000000ffffffff02a02526000000000017a914f987c321394968be164053d352fc49763b2be55c874361610000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d014730440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f44016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000"
    tx1 = Tx.parse(tx_bytes)

    tx_bytes = "01000000016dbddb085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a59233f45bc578380022059af01ca17d00e41837a1d58e97aa31bae584edec28d35bd96923690913bae9a0141049c02bfc97ef236ce6d8fe5d94013c721e915982acd2b12b65d9b7d59e20a842005f8fc4e02532e873d37b96f09d6d4511ada8f14042f46614a4c70c0f14beff5ffffffff02404b4c00000000001976a9141aa0cd1cbea6e7458a7abad512a9d9ea1afb225e88ac80fae9c7000000001976a9140eab5bea436a0484cfab12485efda0b78b4ecc5288ac00000000"
    tx2 = Tx.parse(tx_bytes)

    joint_tx = join(
        [tx1, tx2],
        enforce_same_version=True,
        enforce_same_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    )

    joint_tx.assert_valid()
    assert joint_tx.version == tx1.version
    assert joint_tx.lock_time == tx1.lock_time
    assert len(joint_tx.vout) == len(tx1.vout) + len(tx2.vout)
    assert {v.serialize() for v in joint_tx.vin} == {
        v.serialize() for v in tx1.vin
    }.union({v.serialize() for v in tx2.vin})
    assert len(joint_tx.vin) == len(tx1.vin) + len(tx2.vin)
    assert {v.serialize() for v in joint_tx.vout} == {
        v.serialize() for v in tx1.vout
    }.union({v.serialize() for v in tx2.vout})

    # non-shuffled join is deterministic
    assert join(
        [tx1, tx2],
        enforce_same_version=True,
        enforce_same_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    ) == join(
        [tx1, tx2],
        enforce_same_version=True,
        enforce_same_lock_time=True,
        shuffle_inp=False,
        shuffle_out=False,
    )
    # what each flag does is test_join_shuffles_only_when_it_is_told_to's,
    # against a known permutation: these two transactions have two inputs
    # and four outputs between them, so a real shuffle draws the order it
    # was given once in 2! * 4! -- and an attempt that draws it says
    # nothing either way, which is what makes ten of them an assertion
    # about probability rather than about the join

    tx2.version = 2
    with pytest.raises(BTClibValueError, match="Version numbers are not the same"):
        join(
            [tx1, tx2],
            enforce_same_version=True,
            enforce_same_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    tx2 = Tx.parse(tx_bytes)
    tx2.lock_time = 23526
    with pytest.raises(BTClibValueError, match="Lock times are not the same"):
        join(
            [tx1, tx2],
            enforce_same_version=True,
            enforce_same_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    tx2 = Tx.parse(tx_bytes)
    tx2.vin.append(tx1.vin[0])
    with pytest.raises(BTClibValueError, match="common inputs"):
        join(
            [tx1, tx2],
            enforce_same_version=True,
            enforce_same_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    # outputs are concatenated and never merged, and no parameter asks for
    # it: merging two outputs paying one script invalidates every
    # signature already made over the previous set.
    # What says so is the parameter list, rather than a merge_out=True
    # call asserted to raise: that call raises a TypeError whose text is
    # the interpreter's -- CPython's "unexpected keyword argument" -- and
    # not a contract of this library, while the two asserts below are the
    # contract itself, no parameter of that name and no **kwargs to
    # swallow one
    params = inspect.signature(join).parameters
    assert "merge_out" not in params
    assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


def test_join_shuffles_only_when_it_is_told_to(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each flag decides one list, and off means the order it was given.

    A known permutation in place of the system one, because the answer has
    to be an equality rather than a likelihood: a real shuffle of six
    elements draws the order it was given once in 720, and comparing two
    non-shuffled joins with each other is worse still -- with two inputs
    they agree every other attempt. Reversal is that permutation, so each
    list says which of the two branches ran, and each flag is read on its
    own: a join that shuffles what it was told to keep, or keeps what it was
    told to shuffle, is one equality away either way.
    """

    def reverse(_self: object, sequence: MutableSequence[Any]) -> None:
        sequence.reverse()

    monkeypatch.setattr("btclib.tx.tx.secrets.SystemRandom.shuffle", reverse)

    txs = [
        Tx(
            1,
            0,
            [TxIn(OutPoint(bytes([i]) * 32, 0)) for i in group],
            [TxOut(i, "") for i in group],
        )
        for group in ((1, 2, 3), (4, 5, 6))
    ]

    def joined(*, shuffle_inp: bool, shuffle_out: bool) -> tuple[list[int], list[int]]:
        joint_tx = join(
            txs,
            enforce_same_version=True,
            enforce_same_lock_time=True,
            shuffle_inp=shuffle_inp,
            shuffle_out=shuffle_out,
        )
        return (
            [tx_in.prev_out.tx_id[0] for tx_in in joint_tx.vin],
            [tx_out.value for tx_out in joint_tx.vout],
        )

    concatenated = [1, 2, 3, 4, 5, 6]
    permuted = [6, 5, 4, 3, 2, 1]

    assert joined(shuffle_inp=False, shuffle_out=False) == (
        concatenated,
        concatenated,
    )
    assert joined(shuffle_inp=True, shuffle_out=True) == (permuted, permuted)
    assert joined(shuffle_inp=True, shuffle_out=False) == (permuted, concatenated)
    assert joined(shuffle_inp=False, shuffle_out=True) == (concatenated, permuted)


def test_join_compares_by_value_and_not_by_identity() -> None:
    """The three guards of `join` read numbers, not objects.

    `int("1000")` builds a fresh object where the literal 1000 would be one
    CPython has already cached, and 257 inputs put a count past the last
    cached integer. A guard spelled `is not` instead of `!=` accepts every
    case a test with small numbers can build and refuses these three, so
    what reads as one comparison is one only up to 256.
    """
    tx_out = TxOut(1, "")

    def tx_with(offset: int, count: int, version: int, lock_time: int) -> Tx:
        vin = [
            TxIn(OutPoint((offset + i).to_bytes(32, "big"), 0))
            for i in range(1, count + 1)
        ]
        return Tx(version, lock_time, vin, [tx_out])

    def joined(txs: list[Tx]) -> Tx:
        return join(
            txs,
            enforce_same_version=True,
            enforce_same_lock_time=True,
            shuffle_inp=False,
            shuffle_out=False,
        )

    # equal versions that are not the same object, then equal lock times
    same_version = [tx_with(i * 100, 1, int("1000"), 0) for i in range(2)]
    assert joined(same_version).version == 1000

    same_lock_time = [tx_with(i * 100, 1, 1, int("1000")) for i in range(2)]
    assert joined(same_lock_time).lock_time == 1000

    # and a count past 256: the inputs are all distinct, so the list length
    # and the set size have the same value but are distinct integer objects
    many = [tx_with(1000, 129, 1, 0), tx_with(2000, 128, 1, 0)]
    assert len(joined(many).vin) == 257


def test_eq() -> None:
    """Verify comparing a Tx with a non-Tx answers inequality."""
    tx = Tx(check_validity=False)
    # not a Tx: __eq__ answers NotImplemented and equality is False
    assert tx != "not a Tx"


def test_eq_witness(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tx.__eq__ compares the witnesses only if TxIn.__eq__ does not.

    Two halves, and the monkeypatch is only one of them.
    TX_IN_COMPARES_WITNESS reaches `field(compare=...)` at class creation, so
    patching the module global opens the `vwitness` branch of Tx.__eq__ and
    leaves the generated TxIn comparison still reading the witness -- which
    answers the same way, and so says nothing about the branch. The input
    below is the other half: a TxIn whose equality leaves the witness out, as
    the False setting makes the generated one, so what the branch decides is
    the whole of the answer.
    """

    # narrows equality by dropping a field, a test helper never hashed
    class TxInIgnoringWitness(TxIn):  # noqa: PLW1641
        """A TxIn compared on everything but its witness."""

        def __eq__(self, other: object) -> bool:
            if not isinstance(other, TxIn):
                return NotImplemented
            return (self.prev_out, self.script_sig, self.sequence) == (
                other.prev_out,
                other.script_sig,
                other.sequence,
            )

    def tx_with(*stack: str) -> Tx:
        witness = Witness(list(stack))
        return Tx(
            vin=[TxInIgnoringWitness(script_witness=witness, check_validity=False)],
            check_validity=False,
        )

    monkeypatch.setattr("btclib.tx.tx.TX_IN_COMPARES_WITNESS", False)

    # the inputs compare equal either way, so the branch is what answers
    assert tx_with("00").vin == tx_with().vin
    assert tx_with("00") != tx_with()
    assert tx_with("00") == tx_with("00")

    # and the input above answers a non-input the way TxIn does, which is
    # what its NotImplemented is for. Annotated, so that what the comparison
    # is about is the answer rather than the two types
    not_an_input: object = "not an input"
    assert tx_with().vin[0] != not_an_input


def test_the_transaction_count_bounds_are_what_consensus_derives() -> None:
    """Each bound is arithmetic on consensus rather than a choice.

    MAX_BLOCK_WEIGHT divided by the weight of the smallest thing being
    counted, so neither is a number this library picked: a count above
    either names a transaction no miner could produce, which is what makes
    refusing it before allocating for it safe.

    The minimum sizes are checked against a serialization rather than
    believed, an off-by-one in either being a bound too generous by the
    same factor.
    """
    # a TxIn and a TxOut serialize to no less than this, and neither is
    # witness data, so each weighs WITNESS_SCALE_FACTOR times its size
    assert (
        len(
            TxIn(OutPoint(), b"", 0xFFFFFFFF, check_validity=False).serialize(
                check_validity=False
            )
        )
        == MIN_TX_IN_SIZE
    )
    assert (
        len(
            TxOut(0, ScriptPubKey(b""), check_validity=False).serialize(
                check_validity=False
            )
        )
        == MIN_TX_OUT_SIZE
    )

    assert MAX_TX_IN_COUNT == MAX_BLOCK_WEIGHT // (
        MIN_TX_IN_SIZE * WITNESS_SCALE_FACTOR
    )
    assert MAX_TX_OUT_COUNT == MAX_BLOCK_WEIGHT // (
        MIN_TX_OUT_SIZE * WITNESS_SCALE_FACTOR
    )
    # and they are what they compute to, so a change to either constant
    # above is a change a reader of this test sees
    assert MAX_TX_IN_COUNT == 24_390
    assert MAX_TX_OUT_COUNT == 111_111


def test_a_declared_input_or_output_count_is_bounded_before_allocation() -> None:
    """A count no block could hold is refused where it is read (issue 569).

    `var_int.parse`'s own MAX_SIZE answers whether a CompactSize is one a
    sane protocol would write, and 33,554,432 inputs is a sane
    CompactSize: nine octets asking for a list comprehension of 33 million
    objects. What bounds each count instead is the block that would have
    to hold the transaction.

    TxIn.parse and TxOut.parse raise on the first short read, so a count
    with nothing behind it never allocated much either; what the bound
    adds is the answer given for the count itself, before a byte of the
    first input is read, and a refusal that says which number was wrong
    rather than reporting the bytes that failed to follow it.
    """
    version = (2).to_bytes(4, "little")

    with pytest.raises(BTClibValueError, match="var_int too big"):
        Tx.parse(version + var_int.serialize(MAX_TX_IN_COUNT + 1))

    # the output count is read after the inputs, so an empty input list is
    # what gets the parser there
    with pytest.raises(BTClibValueError, match="var_int too big"):
        Tx.parse(
            version + var_int.serialize(0) + var_int.serialize(MAX_TX_OUT_COUNT + 1)
        )

    # and the bound is not off by one: the count itself is not refused,
    # the first input's short read is what answers instead
    with pytest.raises(BTClibValueError, match="not enough data for the outpoint"):
        Tx.parse(version + var_int.serialize(MAX_TX_IN_COUNT))


def test_the_size_and_the_serialization_agree() -> None:
    """The summed widths are the bytes, for a segwit transaction and not.

    `Tx.size` and `Tx.weight` add the widths up rather than take the
    length of a serialization: two ways of computing one quantity, and
    the block rules are checked against the sizes. The segwit case is
    the one with fields the stripped serialization leaves out -- the
    marker, the flag and every witness -- so it is where the two
    spellings have something to disagree about.
    """
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as binary_file_:
        segwit = Tx.parse(binary_file_.read())
    assert segwit.is_segwit

    legacy = Tx(
        version=1,
        lock_time=0,
        vin=[TxIn(OutPoint(b"\x01" * 32, 0), b"\x02" * 253, 0xFFFFFFFF)],
        vout=[TxOut(1000, ScriptPubKey(b"\x03" * 25))],
    )
    assert not legacy.is_segwit

    for tx in (segwit, legacy):
        for include_witness in (True, False):
            assert tx._serialized_size(include_witness) == len(
                tx.serialize(include_witness, check_validity=False)
            )
        assert tx.size == len(tx.serialize(include_witness=True, check_validity=False))
        assert tx.weight == 3 * len(
            tx.serialize(include_witness=False, check_validity=False)
        ) + len(tx.serialize(include_witness=True, check_validity=False))


def test_a_marker_over_empty_witnesses_is_refused() -> None:
    """Core's "Superfluous witness record", and the round trip it keeps.

    `serialize` writes the marker and the flag only when some input
    carries a witness, so octets carrying them over witnesses that are
    all empty are octets `Tx` cannot write back: the transaction they
    parse to re-serializes to the stripped encoding, with a different
    `hash`, and a caller relaying what it parsed would send something
    other than what it received (issue 1104).

    `UnserializeTransaction` in Bitcoin Core's src/primitives/transaction.h
    reads the witnesses and then throws for the same reason -- "It's
    illegal to encode witnesses when all witness stacks are empty" -- so
    a peer sending these is a peer whose message does not deserialize
    there either.
    """
    tx = Tx(
        1,
        0,
        [TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF)],
        [TxOut(1, ScriptPubKey(b"\x51"))],
    )
    stripped = tx.serialize(include_witness=False)
    assert Tx.parse(stripped) == tx

    # the same transaction, with a marker, a flag and one empty witness
    superfluous = stripped[:4] + b"\x00\x01" + stripped[4:-4] + b"\x00" + stripped[-4:]
    with pytest.raises(BTClibValueError, match="superfluous witness record"):
        Tx.parse(superfluous)

    # the refusal is about the octets and not about the transaction, so
    # check_validity -- which gates assert_valid -- does not reach it
    with pytest.raises(BTClibValueError, match="superfluous witness record"):
        Tx.parse(superfluous, check_validity=False)

    # no input at all is refused too, Core's HasWitness being false there
    # as well: the marker still announces what the encoding then lacks
    no_inputs = (
        (1).to_bytes(4, "little")
        + b"\x00\x01"
        + var_int.serialize(0)
        + var_int.serialize(0)
        + (0).to_bytes(4, "little")
    )
    with pytest.raises(BTClibValueError, match="superfluous witness record"):
        Tx.parse(no_inputs, check_validity=False)


def test_a_marker_over_one_non_empty_witness_is_accepted() -> None:
    """The other side of the bound: one witness is enough for the marker.

    The refusal above asks whether *any* input carries a witness, which
    is `is_segwit` and so is what `serialize` writes the marker for. A
    transaction of two inputs where only the second is signed is the
    case that separates the two readings, and it is an ordinary
    encoding: Core writes an empty stack for the unsigned one.
    """
    tx = Tx(
        1,
        0,
        [
            TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF),
            TxIn(OutPoint(b"\x22" * 32, 1), b"", 0xFFFFFFFF, Witness([b"\x03" * 64])),
        ],
        [TxOut(1, ScriptPubKey(b"\x51"))],
    )
    assert tx.is_segwit

    wire = tx.serialize(include_witness=True)
    parsed = Tx.parse(wire)
    assert parsed == tx
    assert parsed.serialize(include_witness=True) == wire
