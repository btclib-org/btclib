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


def test_script() -> None:
    fname = "script_tests.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)
