#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
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
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut


def test_tx_out() -> None:
    tx_out = TxOut(0, b"")
    assert tx_out.value == 0
    assert tx_out.script_pub_key.script == b""
    assert tx_out.script_pub_key.type == "unknown"
    assert tx_out.script_pub_key.network == "mainnet"
    assert tx_out.script_pub_key.addresses == [""]
    assert tx_out.nValue == tx_out.value
    assert tx_out.scriptPubKey == tx_out.script_pub_key.script
    assert tx_out == TxOut.parse(tx_out.serialize())
    assert tx_out == TxOut.from_dict(tx_out.to_dict())

    value = 3259343370
    script = "0020ed8e9600561000f722bd26e850be7d80f24d174fabeff98baef967325e2b5a86"
    tx_out = TxOut(value, script)
    assert tx_out.value == value
    assert tx_out.script_pub_key.script.hex() == script
    assert tx_out.script_pub_key.type == "p2wsh"
    assert tx_out.script_pub_key.network == "mainnet"
    addr = "bc1qak8fvqzkzqq0wg4aym59p0nasrey696040hlnzawl9nnyh3tt2rqzgmhmv"
    assert tx_out.script_pub_key.addresses == [addr]
    assert tx_out.nValue == tx_out.value
    assert tx_out.scriptPubKey == tx_out.script_pub_key.script
    assert tx_out == TxOut.parse(tx_out.serialize())
    assert tx_out == TxOut.from_dict(tx_out.to_dict())
    assert tx_out == TxOut.from_address(
        tx_out.value, tx_out.script_pub_key.addresses[0]
    )


def test_invalid_tx_out() -> None:

    with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
        script = "0020ed8e9600561000f722bd26e850be7d80f24d174fabeff98baef967325e2b5a86"
        TxOut(-1, script)


def test_tx_out_from_address() -> None:
    address = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
    assert TxOut.from_address(0, address).script_pub_key.addresses == [address]
    assert TxOut.from_address(0, address).script_pub_key.network == "mainnet"
    address = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert TxOut.from_address(0, address).script_pub_key.addresses == [address]
    assert TxOut.from_address(0, address).script_pub_key.network == "testnet"


def test_dataclasses_json_dict() -> None:
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "rb") as binary_file_:
        temp = Tx.parse(binary_file_.read())

    tx_out_data = temp.vout[0]

    # dataclass
    assert isinstance(tx_out_data, TxOut)

    # Tx to/from dict
    tx_out_dict = tx_out_data.to_dict()
    assert isinstance(tx_out_dict, dict)
    assert tx_out_data == TxOut.from_dict(tx_out_dict)

    datadir = path.join(path.dirname(__file__), "_generated_files")

    # Tx dict to/from dict file
    filename = path.join(datadir, "tx_out.json")
    with open(filename, "w", encoding="ascii") as file_:
        json.dump(tx_out_dict, file_, indent=4)
    with open(filename, "r", encoding="ascii") as file_:
        tx_dict2 = json.load(file_)
    assert isinstance(tx_dict2, dict)
    assert tx_out_dict == tx_dict2
