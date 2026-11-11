# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests of the engine's checked integer parameters beyond their refusals.

`_NON_INTEGER_CASES` in `tests/integer_policy_test.py` holds the
refusals. Here are the integers the checks must still take, and the
walks over a script, the interpreter loops among them, which call a
private twin that checks nothing (issue #3023).
"""

from __future__ import annotations

from enum import IntEnum
from io import BytesIO
from typing import NoReturn

import pytest

from btclib.script import script as script_module
from btclib.script import solver as solver_module
from btclib.script.engine import NO_FLAGS, script_op_codes
from btclib.script.engine import script as legacy_engine
from btclib.script.engine import tapscript as tapscript_engine
from btclib.script.engine.script import (
    assert_pub_key_num,
    assert_signature_num,
    script_op_count,
    verify_script,
)
from btclib.script.engine.script_op_codes import read_push_data
from btclib.script.engine.tapscript import verify_script_path_vc0
from btclib.script.script import read_op_code, script_to_asm, serialize
from btclib.script.solver import solver
from btclib.tx import Tx, TxOut


def _push(op_code: int) -> list[bytes]:
    """Return the stack after a push of `op_code` read from `01 02`."""
    stack: list[bytes] = []
    read_push_data(op_code, BytesIO(b"\x01\x02"), stack, False, NO_FLAGS, serialize)
    return stack


class _Count(IntEnum):
    ONE = 1


@pytest.mark.parametrize("one", [1, _Count.ONE], ids=["int", "IntEnum"])
def test_the_integers_the_refusal_must_not_take_with_it(one: int) -> None:
    """The engine's `_NON_INTEGER_CASES` calls with an int they must take.

    An int subclass other than bool is an int too, as `is_integer` says.
    """
    assert_pub_key_num(one)
    assert_signature_num(one, 3)
    assert_signature_num(1, one)
    assert script_op_count(one, 1) == 2
    assert script_op_count(1, one) == 2
    assert _push(one) == [b"\x01"]
    assert read_op_code(b"\x00\x01\x02", one) == (1, 3)


def _refuse(*_: object) -> NoReturn:
    """Stand in for a checked function the walks must not call."""
    msg = "a walk over a script called a checked public function"
    raise AssertionError(msg)


# a script whose run reaches each twin the legacy loop calls
_LEGACY_SCRIPT = bytes.fromhex(
    "".join(
        [
            "0107",  # a push of one byte
            "4c0107",  # the same with OP_PUSHDATA1
            "6d",  # OP_2DROP
            "09" + "30" * 9,  # a junk signature
            "21" + "02" * 33,  # a junk public key
            "ac",  # OP_CHECKSIG, which runs FindAndDelete and answers False
            "91",  # OP_NOT
            "69",  # OP_VERIFY
            "000000",  # the dummy, no signatures and no public keys
            "ae",  # OP_CHECKMULTISIG, which answers True
        ]
    )
)
# the same for the tapscript loop: a push, OP_DROP and OP_1
_TAPSCRIPT = b"\x01\x07\x75\x51"
# OP_RETURN and a push: the solver's push-only walk reads the push
_NULL_DATA = b"\x6a\x01\x07"
# OP_1, a key, OP_1, OP_CHECKMULTISIG: the solver reads m, then walks on
_MULTISIG = b"\x51\x21" + b"\x02" * 33 + b"\x51\xae"


def test_the_walks_call_the_unchecked_twins(monkeypatch: pytest.MonkeyPatch) -> None:
    """The walks run with every checked function made to fail.

    The type checks are the public functions', so a walk calling one of
    them would pay a check per op code.
    """
    asm = script_to_asm(_LEGACY_SCRIPT)
    checked = (
        (legacy_engine, "assert_pub_key_num"),
        (legacy_engine, "assert_signature_num"),
        (legacy_engine, "script_op_count"),
        (script_op_codes, "read_push_data"),
        (script_module, "read_op_code"),
    )
    for module, name in checked:
        monkeypatch.setattr(module, name, _refuse)
    # the engines and the solver import only the twins by name: the public
    # names are set there too, so that a call through an import of one is
    # replaced as well
    imported = (
        (legacy_engine, "read_op_code"),
        (legacy_engine, "read_push_data"),
        (tapscript_engine, "read_push_data"),
        (solver_module, "read_op_code"),
    )
    for module, name in imported:
        monkeypatch.setattr(module, name, _refuse, raising=False)

    tx = Tx(check_validity=False)
    verify_script(_LEGACY_SCRIPT, [], 0, tx, 0, NO_FLAGS, False, True)
    verify_script_path_vc0(_TAPSCRIPT, [], [TxOut(1, b"")], tx, 0, b"", 50, NO_FLAGS)
    assert script_to_asm(_LEGACY_SCRIPT) == asm
    assert solver(_NULL_DATA) == ("nulldata", [])
    assert solver(_MULTISIG) == ("multisig", [b"\x01", b"\x02" * 33, b"\x01"])

    # the control: each replacement is in place, and fails where it is called
    for module, name in checked:
        with pytest.raises(AssertionError, match="^a walk over a script called"):
            getattr(module, name)()
