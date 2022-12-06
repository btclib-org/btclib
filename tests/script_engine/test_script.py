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
import warnings
from os import path

import pytest

from btclib.script.engine import verify_input
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import ScriptPubKey, TxOut
from tests.script_engine import parse_script


def test_script() -> None:

    fname = "script_tests.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    def test(stack, amount, script_sig_str, script_pub_key_str, flags, result):
        coinbase_input = TxIn(
            sequence=0xFFFFFFFF, prev_out=OutPoint(), script_sig=b"\x00\x00"
        )
        script_pub_key = parse_script(script_pub_key_str)
        coinbase_output = TxOut(
            value=amount, script_pub_key=ScriptPubKey(script_pub_key)
        )
        coinbase = Tx(
            version=1, lock_time=0, vin=[coinbase_input], vout=[coinbase_output]
        )

        script_sig = parse_script(script_sig_str)
        spending_input = TxIn(
            sequence=0xFFFFFFFF,
            prev_out=OutPoint(tx_id=coinbase.id, vout=0),
            script_sig=script_sig,
            script_witness=Witness(stack),
        )
        spending = Tx(
            version=1,
            lock_time=0,
            vin=[spending_input],
            vout=[TxOut(amount, ScriptPubKey(""))],
        )

        verify_input([coinbase_output], spending, 0, flags)

    for x in data:
        if len(x) == 1 and isinstance(x[0], str):
            continue

        amount = 0
        if isinstance(x[0], str):
            i = 0
            stack = []
        else:
            i = 1
            stack = x[0]
            if isinstance(stack[-1], (int, float)):
                amount = int(stack[-1] * 10**8)
                stack = stack[:-1]
        script_sig_str = x[i]
        script_pub_key_str = x[i + 1]
        flags = x[i + 2]
        result = x[i + 3] == "OK"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            if result:
                test(stack, amount, script_sig_str, script_pub_key_str, flags, result)
            else:
                with pytest.raises(Exception):
                    test(
                        stack, amount, script_sig_str, script_pub_key_str, flags, result
                    )
