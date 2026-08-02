#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.tx_out` module."""

from dataclasses import FrozenInstanceError
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import Tx, TxOut
from tests.conftest import JsonGolden


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


def test_frozen() -> None:
    tx_out = TxOut(1, "0014751e76e8199196d454941c45d1b3a323f1433bd6")

    with pytest.raises(FrozenInstanceError):
        tx_out.value = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        tx_out.script_pub_key = ScriptPubKey(b"")  # type: ignore[misc]

    # and not merely skin-deep: freezing a dataclass is shallow, so were
    # Script a plain dataclass the script could be rebound *through* a
    # frozen TxOut -- corrupting whatever else held that ScriptPubKey,
    # which is the whole class of bug issue 139 is about. Script and
    # ScriptPubKey are frozen too (issue 165)
    with pytest.raises(FrozenInstanceError):
        tx_out.script_pub_key.script = b""  # type: ignore[misc]
    assert tx_out.script_pub_key.script != b""

    # a ScriptPubKey defines __eq__ and so is unhashable, which makes
    # hashing the TxOut holding it a TypeError
    with pytest.raises(TypeError, match="unhashable type"):
        hash(tx_out)


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


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
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

    # against the json committed beside this module, not written to it
    json_golden("tx_out.json", tx_out_dict)


def test_script_pub_key_is_rendered_as_asm_and_hex() -> None:
    """Core's shape on the way out, and both shapes on the way in.

    `scriptPubKey` gets the rendering `scriptSig` gets, because the two
    are the two scripts of one transaction and `Tx.to_dict` would
    otherwise print them in two different shapes.
    """
    script = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    tx_out = TxOut(1, script)

    dict_ = tx_out.to_dict()
    assert dict_["scriptPubKey"] == {
        "asm": "OP_0 751E76E8199196D454941C45D1B3A323F1433BD6",
        "hex": script,
    }
    assert TxOut.from_dict(dict_) == tx_out

    # the shape to_dict wrote before it wrote that one
    assert TxOut.from_dict({**dict_, "scriptPubKey": script}) == tx_out

    with pytest.raises(BTClibValueError, match="asm does not match hex: "):
        TxOut.from_dict({**dict_, "scriptPubKey": {"asm": "OP_1", "hex": script}})


def test_req_sigs_is_gone() -> None:
    """As it is gone from Bitcoin Core, since v22 (bitcoin/bitcoin#20286).

    It answered for a bare multisig and for nothing else, so btclib's was
    a literal `None` in every case: a key whose value was a constant, read
    as "signatures needed to spend this" by anyone who trusted the name.
    """
    tx_out = TxOut(1, "0014751e76e8199196d454941c45d1b3a323f1433bd6")
    assert "reqSigs" not in tx_out.to_dict()

    # a dict that still carries it is read all the same: from_dict never
    # looked at the key, so dropping it breaks no stored dict
    assert TxOut.from_dict({**tx_out.to_dict(), "reqSigs": None}) == tx_out
