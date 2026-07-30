#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.script.engine` module."""

import json
import warnings
from os import path

import pytest

from btclib.exceptions import BTClibValueError, ScriptError
from btclib.script import ScriptPubKey
from btclib.script.engine import verify_input
from btclib.script.engine.script import verify_script
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from tests.script_engine import parse_script


def test_script() -> None:
    fname = "script_tests.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, encoding="ascii") as file_:
        data = json.load(file_)

    def test(
        stack: list[str],
        amount: int,
        script_sig_str: str,
        script_pub_key_str: str,
        flags: list[str],
        result: bool,
    ) -> None:
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


def test_script_error_says_what_and_where() -> None:
    """A verification failure names the failure and its position.

    The op code implementations are handed the stack alone and cannot
    know either; the interpreter loop adds the command index and the
    stack depth on the way out.
    """
    tx = Tx(check_validity=False)

    # OP_1, OP_1, OP_RETURN
    with pytest.raises(ScriptError, match="OP_RETURN") as exc_info:
        verify_script(b"\x51\x51\x6a", [], 0, tx, 0, [], False)
    assert exc_info.value.index == 2
    assert exc_info.value.stack_depth == 2
    assert "command 2" in str(exc_info.value)
    assert "stack depth 2" in str(exc_info.value)

    # a ScriptError is a BTClibValueError: catching that keeps working
    with pytest.raises(BTClibValueError):
        verify_script(b"\x51\x51\x6a", [], 0, tx, 0, [], False)


def test_script_error_stack_underflow() -> None:
    """An empty stack is an underflow, not a bare IndexError."""
    tx = Tx(check_validity=False)

    # OP_DUP on nothing
    with pytest.raises(ScriptError, match="stack underflow") as exc_info:
        verify_script(b"\x76", [], 0, tx, 0, [], False)
    assert exc_info.value.index == 0
    assert exc_info.value.stack_depth == 0

    # OP_1, OP_EQUAL: the second pop is the one that underflows
    with pytest.raises(ScriptError, match="stack underflow") as exc_info:
        verify_script(b"\x51\x87", [], 0, tx, 0, [], False)
    assert exc_info.value.index == 1


def test_unknown_op_code_is_not_a_key_error() -> None:
    tx = Tx(check_validity=False)
    with pytest.raises(ScriptError, match="unknown op code: 0xff"):
        verify_script(b"\xff", [], 0, tx, 0, [], False)


def test_unbalanced_conditional_message() -> None:
    """Raised before the loop starts, so with no position to report."""
    tx = Tx(check_validity=False)
    with pytest.raises(BTClibValueError, match="unbalanced conditional"):
        verify_script(b"\x63", [], 0, tx, 0, [], False)
