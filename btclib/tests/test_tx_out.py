#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.tx_out` module."

import json
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.tx import Tx
from btclib.tx_out import MAX_SATOSHI, TxOut


def test_tx_out() -> None:
    tx_out = TxOut()
    assert tx_out.value == 0
    assert tx_out.script_pub_key == b""
    assert tx_out.script_type == "unknown"
    assert tx_out.network == "mainnet"
    assert tx_out.address == ""
    assert tx_out.nValue == tx_out.value
    assert tx_out.scriptPubKey == tx_out.script_pub_key
    assert tx_out == TxOut.deserialize(tx_out.serialize())

    value = 3259343370
    script_ = bytes.fromhex(
        "0020ed8e9600561000f722bd26e850be7d80f24d174fabeff98baef967325e2b5a86"
    )
    tx_out = TxOut(value, script_)
    assert tx_out.value == value
    assert tx_out.script_pub_key == script_
    assert tx_out.script_type == "p2wsh"
    assert tx_out.network == "mainnet"
    addr = "bc1qak8fvqzkzqq0wg4aym59p0nasrey696040hlnzawl9nnyh3tt2rqzgmhmv"
    assert tx_out.address == addr
    assert tx_out.nValue == tx_out.value
    assert tx_out.scriptPubKey == tx_out.script_pub_key
    assert tx_out == TxOut.deserialize(tx_out.serialize())
    assert tx_out == TxOut.from_address(tx_out.value, tx_out.address)


def test_invalid_tx_out() -> None:
    script_pub_key = bytes.fromhex("6a0b68656c6c6f20776f726c64")
    tx_out = TxOut(-1, script_pub_key, check_validity=False)
    with pytest.raises(BTClibValueError, match="negative value: "):
        tx_out.assert_valid()

    tx_out = TxOut(MAX_SATOSHI + 1, script_pub_key, check_validity=False)
    with pytest.raises(BTClibValueError, match="value too high: "):
        tx_out.assert_valid()


def test_tx_out_from_address() -> None:
    address = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
    assert TxOut.from_address(0, address).address == address
    assert TxOut.from_address(0, address).network == "mainnet"
    address = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert TxOut.from_address(0, address).address == address
    assert TxOut.from_address(0, address).network == "testnet"


def test_dataclasses_json_dict() -> None:
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "rb") as binary_file_:
        temp = Tx.deserialize(binary_file_.read())

    tx_out_data = temp.vout[0]

    # dataclass
    assert isinstance(tx_out_data, TxOut)

    # Tx to/from dict
    tx_out_dict = tx_out_data.to_dict()
    assert isinstance(tx_out_dict, dict)
    assert tx_out_data == TxOut.from_dict(tx_out_dict)

    datadir = path.join(path.dirname(__file__), "generated_files")

    # Tx dict to/from dict file
    filename = path.join(datadir, "tx_out.json")
    with open(filename, "w") as file_:
        json.dump(tx_out_dict, file_, indent=4)
    with open(filename, "r") as file_:
        tx_dict2 = json.load(file_)
    assert isinstance(tx_dict2, dict)
    assert tx_out_dict == tx_dict2
