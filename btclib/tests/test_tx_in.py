#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.tx` module."

import json
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.tx import Tx
from btclib.tx_in import OutPoint, TxIn


def test_out_point() -> None:
    out_point = OutPoint()
    assert out_point.tx_id == b"\x00" * 32
    assert out_point.vout == 0xFFFFFFFF
    assert out_point.hash == int.from_bytes(out_point.tx_id, "big")
    assert out_point.n == out_point.vout
    assert out_point.is_coinbase()
    out_point.assert_valid()
    assert out_point == OutPoint.deserialize(out_point.serialize())

    tx_id = bytes.fromhex(
        "d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e"
    )
    vout = 0
    out_point = OutPoint(tx_id, vout)
    assert out_point.tx_id == tx_id
    assert out_point.vout == vout
    assert out_point.hash == int.from_bytes(out_point.tx_id, "big")
    assert out_point.n == out_point.vout
    assert not out_point.is_coinbase()
    out_point.assert_valid()
    assert out_point == OutPoint.deserialize(out_point.serialize())


def test_dataclasses_json_dict_outpoint() -> None:
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "rb") as binary_file_:
        temp = Tx.deserialize(binary_file_.read())

    prev_out_data = temp.vin[0].prev_out

    # dataclass
    assert isinstance(prev_out_data, OutPoint)

    # Tx to/from dict
    tx_in_dict = prev_out_data.to_dict()
    assert isinstance(tx_in_dict, dict)
    assert prev_out_data == OutPoint.from_dict(tx_in_dict)

    datadir = path.join(path.dirname(__file__), "generated_files")

    # Tx dict to/from dict file
    filename = path.join(datadir, "out_point.json")
    with open(filename, "w") as file_:
        json.dump(tx_in_dict, file_, indent=4)
    with open(filename, "r") as file_:
        tx_dict2 = json.load(file_)
    assert isinstance(tx_dict2, dict)
    assert tx_in_dict == tx_dict2


def test_invalid_outpoint() -> None:

    op = OutPoint(b"\x01" * 31, 18, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid OutPoint tx_id: "):
        op.assert_valid()

    op = OutPoint(b"\x01" * 32, -1, check_validity=False)
    with pytest.raises(BTClibValueError, match="negative OutPoint vout: "):
        op.assert_valid()

    op = OutPoint(b"\x01" * 32, 0xFFFFFFFF + 1, check_validity=False)
    with pytest.raises(BTClibValueError, match="OutPoint vout too high: "):
        op.assert_valid()

    op = OutPoint(b"\x00" * 31 + b"\x01", 0xFFFFFFFF, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid OutPoint"):
        op.assert_valid()

    op = OutPoint(b"\x00" * 32, 0, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid OutPoint"):
        op.assert_valid()


def test_tx_in() -> None:
    tx_in = TxIn()
    assert tx_in.prev_out == OutPoint()
    assert tx_in.script_sig == b""
    assert tx_in.sequence == 0
    # assert tx_in.witness == Witness()
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert tx_in.is_coinbase()
    tx_in.assert_valid()
    assert tx_in == TxIn.deserialize(tx_in.serialize())

    tx_id = bytes.fromhex(
        "d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e"
    )
    vout = 0
    prev_out = OutPoint(tx_id, vout)
    script_sig = b"notascript"
    sequence = 0
    # witness 0 Witness()
    tx_in = TxIn(prev_out, script_sig, sequence)
    assert tx_in.prev_out == prev_out
    assert tx_in.script_sig == script_sig
    assert tx_in.sequence == sequence
    # assert tx_in.witness == Witness()
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert not tx_in.is_coinbase()
    tx_in.assert_valid()
    assert tx_in == TxIn.deserialize(tx_in.serialize())


def test_dataclasses_json_dict() -> None:
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "rb") as binary_file_:
        temp = Tx.deserialize(binary_file_.read())

    tx_in_data = temp.vin[0]

    # dataclass
    assert isinstance(tx_in_data, TxIn)

    # Tx to/from dict
    tx_in_dict = tx_in_data.to_dict()
    assert isinstance(tx_in_dict, dict)
    assert tx_in_data == TxIn.from_dict(tx_in_dict)

    datadir = path.join(path.dirname(__file__), "generated_files")

    # Tx dict to/from dict file
    filename = path.join(datadir, "tx_in.json")
    with open(filename, "w") as file_:
        json.dump(tx_in_dict, file_, indent=4)
    with open(filename, "r") as file_:
        tx_dict2 = json.load(file_)
    assert isinstance(tx_dict2, dict)
    assert tx_in_dict == tx_dict2
