#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.script.engine` module."""

from typing import Any, NamedTuple

import pytest

from btclib.exceptions import BTClibValueError, ScriptError
from btclib.script import ScriptPubKey
from btclib.script.engine import ALL_FLAGS, verify_input
from btclib.script.engine.script import verify_script
from btclib.script.script import serialize
from btclib.script.taproot import input_script_sig, output_pubkey
from btclib.script.witness import Witness
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from tests import vectors
from tests.script_engine import parse_script


class ScriptVector(NamedTuple):
    stack: list[str]
    amount: int
    script_sig: str
    script_pub_key: str
    flags: list[str]
    valid: bool


def script_vectors() -> list[Any]:
    """One case per vector of Bitcoin Core's script_tests.json.

    A vector is [[witness..., amount]?, scriptSig, scriptPubKey, flags,
    expected_scripterror, comment?], interleaved with comment lines that
    are a one element array of text. The optional leading witness stack
    shifts the rest by one, and the amount is the last entry of that
    stack when it is a number.
    """
    params = []
    data = vectors.load("script_engine", "_data", "script_tests.json")
    for index, x in enumerate(data):
        if len(x) == 1 and isinstance(x[0], str):
            continue  # a comment line between two vectors

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

        vector = ScriptVector(stack, amount, x[i], x[i + 1], x[i + 2], x[i + 3] == "OK")
        # the trailing comment of the vector says what it is testing, and
        # two thirds of them have one; the script itself for the rest
        comment = x[i + 4] if len(x) > i + 4 else ""
        params.append(
            pytest.param(
                vector, id=vectors.vector_id(index, comment or vector.script_pub_key)
            )
        )
    return params


@pytest.mark.parametrize("vector", script_vectors())
def test_script(vector: ScriptVector) -> None:
    def verify() -> None:
        coinbase_input = TxIn(
            sequence=0xFFFFFFFF, prev_out=OutPoint(), script_sig=b"\x00\x00"
        )
        script_pub_key = parse_script(vector.script_pub_key)
        coinbase_output = TxOut(
            value=vector.amount, script_pub_key=ScriptPubKey(script_pub_key)
        )
        coinbase = Tx(
            version=1, lock_time=0, vin=[coinbase_input], vout=[coinbase_output]
        )

        script_sig = parse_script(vector.script_sig)
        spending_input = TxIn(
            sequence=0xFFFFFFFF,
            prev_out=OutPoint(tx_id=coinbase.id, vout=0),
            script_sig=script_sig,
            script_witness=Witness(vector.stack),
        )
        spending = Tx(
            version=1,
            lock_time=0,
            vin=[spending_input],
            vout=[TxOut(vector.amount, ScriptPubKey(""))],
        )

        verify_input([coinbase_output], spending, 0, vector.flags)

    if vector.valid:
        verify()
    else:
        with pytest.raises(Exception):
            verify()


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


def taproot_script_spend(
    script: list[Any], lock_time: int, sequence: int
) -> tuple[list[TxOut], Tx]:
    """A script-path spend of the given tapscript, no signature involved.

    The internal key is the BIP341 NUMS point, the default of
    output_pubkey and input_script_sig, so the key path cannot sign;
    the script path needs no signature unless the script asks for one,
    which is what lets a timelock op code run alone.
    """
    script_tree = [(0xC0, script)]
    q, _ = output_pubkey(None, script_tree)
    tap_script, control = input_script_sig(None, script_tree, 0)
    prevout = TxOut(1000, ScriptPubKey(serialize(["OP_1", q])))
    tx_in = TxIn(
        OutPoint(b"\x01" * 32, 0),
        b"",
        sequence,
        Witness([serialize(tap_script).hex(), control.hex()]),
    )
    tx = Tx(2, lock_time, [tx_in], [TxOut(1000, ScriptPubKey(""))], False)
    return [prevout], tx


def test_tapscript_checklocktimeverify() -> None:
    """OP_CHECKLOCKTIMEVERIFY spent through a taproot script path.

    The BIP341 vectors carry no timelock op code, so the tapscript
    dispatch of OP_CLTV ran on no vector; this spend is the synthetic
    one that runs it: operand 1 against lock_time 100, same time kind,
    sequence not final.
    """
    prevouts, tx = taproot_script_spend(
        ["OP_1", "OP_CHECKLOCKTIMEVERIFY"], lock_time=100, sequence=1
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_tapscript_checksequenceverify() -> None:
    """OP_CHECKSEQUENCEVERIFY spent through a taproot script path.

    Same reason as OP_CLTV above. The passing spend: operand 1 against
    an input sequence of 1, both with bit 31 clear and the same unit
    bit, on a version 2 transaction. The failing one: bit 31 set on the
    input sequence disables its relative lock time, so an OP_CSV that
    still asks for one must fail -- the one raise of the op code no
    Core vector reaches, legacy or tapscript.
    """
    prevouts, tx = taproot_script_spend(
        ["OP_1", "OP_CHECKSEQUENCEVERIFY"], lock_time=0, sequence=1
    )
    verify_input(prevouts, tx, 0, ALL_FLAGS)

    prevouts, tx = taproot_script_spend(
        ["OP_1", "OP_CHECKSEQUENCEVERIFY"], lock_time=0, sequence=1 << 31
    )
    with pytest.raises(BTClibValueError, match="relative lock time disabled"):
        verify_input(prevouts, tx, 0, ALL_FLAGS)


def test_tapscript_upgradable_nop() -> None:
    """An upgradable OP_NOPx in a tapscript is a no-op.

    BIP342 leaves OP_NOP1 and OP_NOP4-OP_NOP10 with their NOP
    semantics, and no vector spends one: this covers the dispatch, and
    ALL_FLAGS deliberately omits DISCOURAGE_UPGRADABLE_NOPS, which is
    policy rather than consensus, so op_nop stays silent.
    """
    prevouts, tx = taproot_script_spend(["OP_1", "OP_NOP4"], lock_time=0, sequence=1)
    verify_input(prevouts, tx, 0, ALL_FLAGS)
