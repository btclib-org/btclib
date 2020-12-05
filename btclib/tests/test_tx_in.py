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
from btclib.tx import Tx, Witness
from btclib.tx_in import OutPoint, TxIn
from btclib.utils import bytes_from_octets


def test_out_point() -> None:
    out_point = OutPoint()
    assert out_point.tx_id == b"\x00" * 32
    assert out_point.vout == 0xFFFFFFFF
    assert out_point.hash == int.from_bytes(out_point.tx_id, "big")
    assert out_point.n == out_point.vout
    assert out_point.is_coinbase()
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
    with pytest.raises(BTClibValueError, match="invalid vout: "):
        op.assert_valid()

    op = OutPoint(b"\x01" * 32, 0xFFFFFFFF + 1, check_validity=False)
    with pytest.raises(BTClibValueError, match="invalid vout: "):
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
    assert tx_in.witness == Witness()
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert tx_in.is_coinbase()
    assert tx_in == TxIn.deserialize(tx_in.serialize())

    tx_id = bytes.fromhex(
        "d5b5982254eebca64e4b42a3092a10bfb76ab430455b2bf0cf7c4f7f32db1c2e"
    )
    vout = 0
    prev_out = OutPoint(tx_id, vout)
    script_sig = b""
    sequence = 0
    stack = [
        "",
        "3044022077ecafa04bc23f87057bd54b572a473cf5cc6a945c167fcefe561618b86d097002200eb7c62a855295c8c288ff972c58905861a98260dafb6f8b7587cfda3091e00d01",
        "3045022100f20ba32865985e66985ba2d7ad11950309e253788b2edb27ccf5899e806f43ef02202899d98360f6476fcefbbf1dc1813595f4d0807d13237218de5ffaaeaa85640101",
        "304402206f7f5b0723d61f5d9f2ecbae448646d4cf0cf3ecade5ab50867fdfe8e131ce8f02207f0c260620e41dbdecd6ce574bf2773de248178d33f24aee71627843560137cd01",
        "01",
        "635321024713c6e66da107644c64ab84189840e78310b247cc7fa563d6f98f2a46900a0d21026cb4cc5bbde0e59806657b1780a9a3b333a8acb6fcac48ade7d52e2b34aa30042102b6615b55426b7362cd82897db26b1423e3732f98eaea5cd2c150c49a46003c6521033557edc1a6aec5a28648f6e22deb542e9ee8c9219d5bb5e81d0fe23c8f955ad221039d7f91444b2d4c4e89a1f550fa7d32c5d9b75a49b14c54f10109d95f637bb7de2103d9cdf5c6da8b2fd66fa918916cc93d831f16781c01ca759c9cf60acf94268bbd56ae67029000b275522102d02570ed9db9ee6abd13a6c269758debcfaa1aa6d0857553e5b6a5cf764ffe0a21030968209ccaaae1c0f8ee7a4a3594b3504fd3f89db1c259aedbdce3aba29f219321036069299a8a990474eb34786bf446e724088896a54bf848650c9543f18af602dc53ae68",
    ]
    witness = Witness([bytes_from_octets(v) for v in stack])
    tx_in = TxIn(prev_out, script_sig, sequence, witness)
    assert tx_in.prev_out == prev_out
    assert tx_in.script_sig == script_sig
    assert tx_in.sequence == sequence
    assert tx_in.witness == witness
    assert tx_in.outpoint == tx_in.prev_out
    assert tx_in.scriptSig == tx_in.script_sig
    assert tx_in.nSequence == tx_in.nSequence
    assert not tx_in.is_coinbase()
    TxIn.deserialize(tx_in.serialize())
    # FIXME: witness is lost
    assert tx_in != TxIn.deserialize(tx_in.serialize())

    tx_in.sequence = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid sequence: "):
        tx_in.assert_valid()


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
