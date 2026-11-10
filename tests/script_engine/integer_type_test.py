# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that the engine's public integer parameters refuse a non-integer.

`btclib.utils.is_integer` is the policy, a bool being no integer either.
Each public function checks the type before a comparison or a sum meets
it, then leaves the work to a private twin that checks nothing, and the
interpreter loops call the twin (issue #3023).
"""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from enum import IntEnum
from io import BytesIO
from typing import Any, NoReturn

import pytest

from btclib.exceptions import BTClibTypeError
from btclib.script import script as script_module
from btclib.script.engine import NO_FLAGS, script_op_codes
from btclib.script.engine import script as legacy_engine
from btclib.script.engine.script import (
    assert_pub_key_num,
    assert_signature_num,
    script_op_count,
    verify_script,
)
from btclib.script.engine.script_op_codes import read_push_data
from btclib.script.engine.tapscript import verify_script_path_vc0
from btclib.script.script import read_op_code, serialize
from btclib.tx import Tx, TxOut


def _push(op_code: Any) -> list[bytes]:
    """Return the stack after a push of `op_code` read from `01 02`."""
    stack: list[bytes] = []
    read_push_data(op_code, BytesIO(b"\x01\x02"), stack, False, NO_FLAGS, serialize)
    return stack


# each integer parameter, the shortest call that reaches its check, and
# the start of its refusal
_CASES: list[tuple[str, Callable[[Any], object], str]] = [
    ("public key count", assert_pub_key_num, "invalid public key count type"),
    (
        "signature count",
        lambda v: assert_signature_num(v, 3),
        "invalid signature count type",
    ),
    (
        "signature count's public key count",
        lambda v: assert_signature_num(1, v),
        "invalid public key count type",
    ),
    ("op code count", lambda v: script_op_count(v, 1), "invalid op code count type"),
    (
        "op code count increment",
        lambda v: script_op_count(1, v),
        "invalid op code count increment type",
    ),
    ("pushdata op code", _push, "invalid op code type"),
    (
        "op code start",
        lambda v: read_op_code(b"\x00\x01\x02", v),
        "invalid start offset type",
    ),
]


@pytest.mark.parametrize(
    "call, err_msg",
    [(case[1], case[2]) for case in _CASES],
    ids=[case[0] for case in _CASES],
)
@pytest.mark.parametrize(
    "value",
    ["1", b"\x01", Decimal(1), 1.0, None, True, False],
    ids=["str", "bytes", "Decimal", "float", "None", "true", "false"],
)
def test_a_non_integer_is_refused_by_its_type(
    call: Callable[[Any], object], err_msg: str, value: object
) -> None:
    """Each wrong type is refused by its type name, a bool included.

    Unchecked, a str, bytes or None leaves as Python's bare TypeError, a
    float or a Decimal is taken as a number or leaves as a bare TypeError,
    and a bool is taken as the number it equals.
    """
    match = f"^{err_msg}: {type(value).__name__}$"
    with pytest.raises(BTClibTypeError, match=match):
        call(value)


class _Count(IntEnum):
    ONE = 1


@pytest.mark.parametrize("one", [1, _Count.ONE], ids=["int", "IntEnum"])
def test_the_integers_the_refusal_must_not_take_with_it(one: int) -> None:
    """The same calls with an int, which is what the refusal is around.

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
    """Stand in for a checked function the loops must not call."""
    msg = "an interpreter loop called a checked public function"
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


def test_the_loops_call_the_unchecked_twins(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scripts run with every checked function made to fail.

    The type checks are the public functions', so a loop calling one of
    them would pay a check per op code.
    """
    checked = (
        (legacy_engine, "assert_pub_key_num"),
        (legacy_engine, "assert_signature_num"),
        (legacy_engine, "script_op_count"),
        (script_op_codes, "read_push_data"),
        (script_module, "read_op_code"),
    )
    for module, name in checked:
        monkeypatch.setattr(module, name, _refuse)
    # the engine imports only the twin by name: the public name is set
    # there too, so that a call through an import of it is replaced as well
    monkeypatch.setattr(legacy_engine, "read_op_code", _refuse, raising=False)

    tx = Tx(check_validity=False)
    verify_script(_LEGACY_SCRIPT, [], 0, tx, 0, NO_FLAGS, False, True)
    verify_script_path_vc0(_TAPSCRIPT, [], [TxOut(1, b"")], tx, 0, b"", 50, NO_FLAGS)

    # the control: each replacement is in place, and fails where it is called
    for module, name in checked:
        with pytest.raises(AssertionError, match="^an interpreter loop called"):
            getattr(module, name)()
