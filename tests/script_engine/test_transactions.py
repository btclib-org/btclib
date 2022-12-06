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
import warnings
from btclib.exceptions import BTClibValueError
from btclib.script.engine import verify_input, verify_transaction
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import ScriptPubKey, TxOut
from tests.script_engine import parse_script


def test_valid_taproot() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(path.dirname(__file__)), "script", "_data", fname)

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
    filename = path.join(path.dirname(path.dirname(__file__)), "script", "_data", fname)
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

        flags = [
            "P2SH",
            "SIGPUSHONLY",
            "LOW_S",
            "STRICTENC",
            "DERSIG",
            "CONST_SCRIPTCODE",
            "NULLDUMMY",
            "CLEANSTACK",
            "MINIMALDATA",
            # only standard, not consensus
            # "NULLFAIL",
            # "MINMALIF",
            # "DISCOURAGE_UPGRADABLE_NOPS",
            # "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            "CHECKLOCKTIMEVERIFY",
            "CHECKSEQUENCEVERIFY",
            "WITNESS",
            "WITNESS_PUBKEYTYPE",
            "TAPROOT",
        ]
        for f in x[2].split(","):
            if f in flags:
                flags.remove(f)

        prevouts = []
        for i in x[0]:
            amount = 0 if len(i) == 3 else i[3]
            script_pub_key = parse_script(i[2])
            prevouts.append(TxOut(amount, ScriptPubKey(script_pub_key)))

        verify_transaction(prevouts, tx, flags if flags != ["NONE"] else None)


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

        prevouts = []
        for i in x[0]:
            amount = 0 if len(i) == 3 else i[3]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                script_pub_key = parse_script(i[2])
            prevouts.append(TxOut(amount, ScriptPubKey(script_pub_key)))

        with pytest.raises((BTClibValueError, IndexError, KeyError)):
            verify_transaction(prevouts, tx, flags if flags != ["NONE"] else None)
