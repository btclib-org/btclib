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

# from btclib.exceptions import BTClibValueError
# from btclib.script.engine import ALL_FLAGS
from btclib.script.engine import verify_input
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

    error_count = 0
    ok_count = 0

    for index, x in enumerate(data):
        if len(x) == 1 and isinstance(x[0], str):
            continue

        flags = x[2]
        result = x[3] == "OK"

        def test():
            coinbase_input = TxIn(
                sequence=0xFFFFFFFF, prev_out=OutPoint(), script_sig=b"\x00\x00"
            )
            script_pub_key = parse_script(x[1])
            coinbase_output = TxOut(
                value=0, script_pub_key=ScriptPubKey(script_pub_key)
            )
            coinbase = Tx(lock_time=0, vin=[coinbase_input], vout=[coinbase_output])

            script_sig = parse_script(x[0])
            spending_input = TxIn(
                sequence=0xFFFFFFFF,
                prev_out=OutPoint(tx_id=coinbase.id, vout=0),
                script_sig=script_sig,
            )
            spending = Tx(
                lock_time=0, vin=[spending_input], vout=[TxOut(0, ScriptPubKey(""))]
            )

            verify_input([coinbase_output], spending, 0, flags)

        try:
            if result:
                test()
            else:
                with pytest.raises(Exception):
                    test()
            ok_count += 1
        except:
            print()
            print(x)
            print(index, "error")
            error_count += 1

    print()
    print(ok_count)
    print(error_count)

    assert False
