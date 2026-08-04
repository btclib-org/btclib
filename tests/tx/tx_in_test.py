#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.tx_in` module."""

from dataclasses import FrozenInstanceError
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script import Witness
from btclib.tx import OutPoint, Tx, TxIn
from btclib.tx.tx_in import TX_IN_COMPARES_WITNESS
from tests.conftest import JsonGolden


def test_tx_in() -> None:
    """Round-trip TxIn through bytes and dict, coinbase and segwit."""
    tx_in = TxIn()
    assert tx_in.prev_out == OutPoint()
    assert tx_in.script_sig == b""
    assert tx_in.sequence == 0
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert tx_in.is_coinbase()
    assert not tx_in.is_segwit()
    tx_in2 = TxIn.parse(tx_in.serialize())
    assert not tx_in2.is_segwit()
    assert tx_in == tx_in2
    tx_in2 = TxIn.from_dict(tx_in.to_dict())
    assert not tx_in2.is_segwit()
    assert tx_in == tx_in2

    tx_id = "d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e"
    vout = 0
    prev_out = OutPoint(tx_id, vout)
    script_sig = b""
    sequence = 0
    tx_in = TxIn(prev_out, script_sig, sequence)
    assert tx_in.prev_out == prev_out
    assert tx_in.script_sig == script_sig
    assert tx_in.sequence == sequence
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert not tx_in.is_coinbase()
    assert not tx_in.is_segwit()
    tx_in2 = TxIn.parse(tx_in.serialize())
    assert not tx_in2.is_segwit()
    assert tx_in == tx_in2
    tx_in2 = TxIn.from_dict(tx_in.to_dict())
    assert not tx_in2.is_segwit()
    assert tx_in == tx_in2

    prev_out = OutPoint(
        "9dcfdb5836ecfe146bdaa896605ba21222f83cd014dd47adde14fab2aba7de9b", 1
    )
    script_sig = b""
    sequence = 0xFFFFFFFF
    tx_in = TxIn(prev_out, script_sig, sequence)
    stack = [
        "",
        "30440220421fbbedf2ee096d6289b99973509809d5e09589040d5e0d453133dd11b2f78a02205686dbdb57e0c44e49421e9400dd4e931f1655332e8d078260c9295ba959e05d01",
        "30440220398f141917e4525d3e9e0d1c6482cb19ca3188dc5516a3a5ac29a0f4017212d902204ea405fae3a58b1fc30c5ad8ac70a76ab4f4d876e8af706a6a7b4cd6fa100f4401",
        "52210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae",
    ]
    tx_in.script_witness = Witness(stack)
    assert tx_in.prev_out == prev_out
    assert tx_in.script_sig == script_sig
    assert tx_in.sequence == sequence
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert not tx_in.is_coinbase()
    assert tx_in.is_segwit()
    tx_in2 = TxIn.parse(tx_in.serialize())
    assert not tx_in2.is_segwit()
    assert tx_in == tx_in2 or TX_IN_COMPARES_WITNESS
    tx_in2 = TxIn.from_dict(tx_in.to_dict())
    assert tx_in2.is_segwit()
    assert tx_in == tx_in2

    tx_in.sequence = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid sequence: "):
        tx_in.assert_valid()


def test_default_arguments_are_not_shared() -> None:
    """Verify the default prev_out and witness are built per call."""
    # guards against the defaults being built once, at definition time:
    # mutating a shared default through one TxIn corrupts every other one,
    # and assigning prev_out.vout would even leave the constructor unable
    # to build a valid TxIn for the rest of the process (issue #139)
    tx_in = TxIn()
    assert tx_in.prev_out is not TxIn().prev_out
    assert tx_in.script_witness is not TxIn().script_witness

    # OutPoint and Witness are immutable all the way down, so a shared one
    # could not be corrupted; building them per call is still what the
    # library does, and B008 keeps it that way
    with pytest.raises(FrozenInstanceError):
        tx_in.prev_out.vout = 0  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        tx_in.script_witness.stack = ()  # type: ignore[misc]

    assert TxIn().prev_out.vout == 0xFFFFFFFF
    assert not TxIn().script_witness.stack


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    """Compare a real input's to_dict with its golden json, and back."""
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as binary_file_:
        temp = Tx.parse(binary_file_.read())

    tx_in = temp.vin[0]

    # TxIn dataclass
    assert isinstance(tx_in, TxIn)

    # TxIn dataclass to dict
    tx_in_dict = tx_in.to_dict()
    assert isinstance(tx_in_dict, dict)

    # against the json committed beside this module, not written to it
    json_golden("tx_in.json", tx_in_dict)

    # TxIn dataclass from dict
    tx_in2 = TxIn.from_dict(tx_in_dict)
    assert isinstance(tx_in2, TxIn)

    assert tx_in == tx_in2


def test_script_sig_is_rendered_as_asm_and_hex() -> None:
    """Core's shape on the way out, and both shapes on the way in."""
    script_sig = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0), script_sig, 0)

    dict_ = tx_in.to_dict()
    assert dict_["scriptSig"]["hex"] == script_sig
    assert dict_["scriptSig"]["asm"].startswith("OP_DUP OP_HASH160 ")
    assert TxIn.from_dict(dict_) == tx_in

    # the shape to_dict wrote before it wrote that one
    old = {**dict_, "scriptSig": script_sig}
    assert TxIn.from_dict(old) == tx_in

    with pytest.raises(BTClibValueError, match="asm does not match hex: "):
        TxIn.from_dict({**dict_, "scriptSig": {"asm": "OP_1", "hex": script_sig}})


def test_script_sig_is_not_validated_and_that_is_the_answer() -> None:
    """An input's validity is not its script's (issue 183).

    Three things a check here would have to be, and each belongs
    elsewhere: a script_sig that does not parse still makes a valid input,
    the 1650-byte and push-only limits of Core's IsStandardTx are relay
    policy rather than validity, and the one consensus rule about a
    script_sig at this level -- the coinbase's 2..100 bytes -- is
    Tx.assert_valid's, a lone TxIn with the null prev_out being the
    placeholder a builder starts from.
    """
    prev_out = OutPoint(b"\x01" * 32, 0)

    # not a script at all: a bare OP_PUSHDATA1 with no length byte after it
    TxIn(prev_out, b"\x4c").assert_valid()
    # over the 1650 bytes IsStandardTx allows, and over the 10000 the
    # interpreter allows the script it evaluates
    TxIn(prev_out, b"\x00" * 20000).assert_valid()
    # not push-only: OP_DUP
    TxIn(prev_out, b"v").assert_valid()

    # the placeholder every builder starts from, which a coinbase-input
    # length check here would reject
    TxIn().assert_valid()
    assert TxIn().is_coinbase()
    assert not TxIn().script_sig

    # and the coinbase rule is enforced where the transaction is known
    tx = Tx(vin=[TxIn()], vout=[], check_validity=False)
    with pytest.raises(BTClibValueError, match="Invalid coinbase script size"):
        tx.assert_valid()
