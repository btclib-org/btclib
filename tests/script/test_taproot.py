#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.taproot` module."

import json
from os import path

from btclib.script.script_pub_key import is_p2tr, type_and_payload
from btclib.script.taproot import check_tree_hash
from btclib.script.witness import Witness
from btclib.tx.tx_out import TxOut


def test_valid_script_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r") as file_:
        data = json.load(file_)

    for x in filter(lambda x: "final" in x.keys(), data):

        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        script_sig = x["success"]["scriptSig"]
        assert not script_sig

        witness = Witness(x["success"]["witness"])
        if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
            witness.stack = witness.stack[:-1]

        # check script paths
        if len(witness.stack) < 2:
            continue

        Q = type_and_payload(prevouts[index].script_pub_key.script)[1]

        script = witness.stack[-2]
        control = witness.stack[-1]

        assert check_tree_hash(Q, script, control)
