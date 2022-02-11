#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.engine` module."

import json
from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script.engine import ALL_FLAGS, verify_input, verify_transaction
from btclib.script.op_codes import OP_CODES
from btclib.script.script import serialize
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import ScriptPubKey, TxOut


def test_valid_taproot() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "TAPROOT" in x["flags"], data):

        tx = Tx.parse(x["tx"])

        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        witness = Witness(x["success"]["witness"])
        tx.vin[index].script_witness = witness
        tx.vin[index].script_sig = bytes.fromhex(x["success"]["scriptSig"])

        flags = x["flags"].split(",")

        verify_input(prevouts, tx, index, flags)


def test_invalid_taproot() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "TAPROOT" in x["flags"] and "failure" in x.keys(), data):

        tx = Tx.parse(x["tx"])

        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        witness = Witness(x["failure"]["witness"])
        tx.vin[index].script_witness = witness
        tx.vin[index].script_sig = bytes.fromhex(x["failure"]["scriptSig"])

        flags = x["flags"].split(",")

        with pytest.raises((BTClibValueError, IndexError, KeyError)):
            verify_input(prevouts, tx, index, flags)


def test_valid_legacy() -> None:
    fname = "tx_valid_legacy.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in data:
        if isinstance(x[0], str):
            continue

        try:
            tx = Tx.parse(x[1])
        except BTClibValueError as e:
            if "invalid satoshi amount:" in str(e):
                continue

        flags = ALL_FLAGS[:]
        for f in x[2].split(","):
            if f in flags:
                flags.remove(f)

        prevouts = []
        for i in x[0]:
            amount = 0 if len(i) == 3 else i[3]
            script_pub_key = ""
            for y in i[2].split(" "):
                if y[:2] == "0x":
                    script_pub_key += y[2:]
                elif y[1:].isdigit():
                    script_pub_key += serialize([int(y)]).hex()
                else:
                    if y[:3] != "OP_":
                        y = "OP_" + y
                    script_pub_key += OP_CODES[y].hex()
            prevouts.append(TxOut(amount, ScriptPubKey(script_pub_key)))

        verify_transaction(prevouts, tx, flags)


def test_invalid_legacy() -> None:
    fname = "tx_invalid_legacy.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in data:
        if isinstance(x[0], str):
            continue

        try:
            tx = Tx.parse(x[1])
        except BTClibValueError as e:
            if "invalid satoshi amount:" not in str(e):
                continue
            if "missing outputs" not in str(e):
                continue

        flags = x[2].split(",")  # different flags handling
        if "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" in flags:
            # we do not support this flag
            continue

        prevouts = []
        for i in x[0]:
            amount = 0 if len(i) == 3 else i[3]
            script_pub_key = ""
            for y in i[2].split(" "):
                if y[:2] == "0x":
                    script_pub_key += y[2:]
                elif y[1:].isdigit():
                    script_pub_key += serialize([int(y)]).hex()
                else:
                    if y[:3] != "OP_":
                        y = "OP_" + y
                    script_pub_key += OP_CODES[y].hex()
            prevouts.append(TxOut(amount, ScriptPubKey(script_pub_key)))

        with pytest.raises((BTClibValueError, IndexError, KeyError)):
            verify_transaction(prevouts, tx, flags)
