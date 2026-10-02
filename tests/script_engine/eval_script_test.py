# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `eval_script`: the stack a script stops on is Core's.

Each expectation is read off `EvalScript` in `src/script/interpreter.cpp`
of bitcoin/bitcoin@9be056a8a7 (v31.1), at the lines its case names, and
not off what btclib answers. Core's own tests assert no stack where an op
code refuses, so the source is the ground and these cases are its hand
reading: what an op code pops, and when.
"""

from typing import Any, NamedTuple

import pytest

from btclib.exceptions import BTClibTypeError, ScriptError, ScriptErrorCode
from btclib.script.engine import NO_FLAGS, ScriptFlag
from btclib.script.engine.script import eval_script, verify_script
from btclib.tx.tx import Tx

_PUB = b"\x02" + b"\x11" * 32
_PUSH_PUB = b"\x21" + _PUB
_ZERO_KEY = bytes(33)
_FIVE_BYTES = b"\x01\x02\x03\x04\x05"
_PUSH_FIVE_BYTES = b"\x05" + _FIVE_BYTES
# 0x80000000: a 5-byte number, its top bit being the sequence's disable flag
_PUSH_SEQUENCE_DISABLED = b"\x05\x00\x00\x00\x80\x00"

_CODE = ScriptErrorCode


class _Case(NamedTuple):
    """A script, where it stops, and the lines of Core that say so."""

    script: bytes
    stack: list[bytes]
    flags: ScriptFlag
    code: ScriptErrorCode | None
    position: int | None
    core: str
    initial: tuple[bytes, ...] = ()


# Core's EvalScript in src/script/interpreter.cpp, v31.1, by line
_CASES: dict[str, _Case] = {
    # (false -- false) and return: the false stays
    "OP_VERIFY on a false": _Case(
        b"\x00\x69", [b""], NO_FLAGS, _CODE.VERIFY, 1, "653-665"
    ),
    "OP_VERIFY on nothing": _Case(
        b"\x69", [], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 0, "657-658"
    ),
    # the false result is pushed, then tested, and kept
    "OP_EQUALVERIFY on unequal": _Case(
        b"\x51\x52\x88", [b""], NO_FLAGS, _CODE.EQUALVERIFY, 2, "902-911"
    ),
    "OP_EQUALVERIFY on one element": _Case(
        b"\x51\x88", [b"\x01"], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "892-893"
    ),
    "OP_EQUALVERIFY on nothing": _Case(
        b"\x88", [], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 0, "892-893"
    ),
    "OP_NUMEQUALVERIFY on unequal": _Case(
        b"\x51\x52\x9d", [b""], NO_FLAGS, _CODE.NUMEQUALVERIFY, 2, "988-998"
    ),
    # a CScriptNum is built from stacktop() before anything is popped
    "OP_ADD on a number too long": _Case(
        b"\x51" + _PUSH_FIVE_BYTES + b"\x93",
        [b"\x01", _FIVE_BYTES],
        NO_FLAGS,
        _CODE.SCRIPTNUM,
        2,
        "960-963, 1226-1229",
    ),
    "OP_1ADD on a number too long": _Case(
        _PUSH_FIVE_BYTES + b"\x8b",
        [_FIVE_BYTES],
        NO_FLAGS,
        _CODE.SCRIPTNUM,
        1,
        "927-929, 1226-1229",
    ),
    "OP_WITHIN on a number too long": _Case(
        b"\x51\x52" + _PUSH_FIVE_BYTES + b"\xa5",
        [b"\x01", b"\x02", _FIVE_BYTES],
        NO_FLAGS,
        _CODE.SCRIPTNUM,
        3,
        "1005-1009",
    ),
    # OP_PICK and OP_ROLL pop the index, then fail on it
    "OP_PICK past the stack": _Case(
        b"\x51\x52\x55\x79",
        [b"\x01", b"\x02"],
        NO_FLAGS,
        _CODE.INVALID_STACK_OPERATION,
        3,
        "830-833",
    ),
    "OP_ROLL past the stack": _Case(
        b"\x51\x52\x55\x7a",
        [b"\x01", b"\x02"],
        NO_FLAGS,
        _CODE.INVALID_STACK_OPERATION,
        3,
        "830-833",
    ),
    "OP_PICK of a negative index": _Case(
        b"\x51\x4f\x79",
        [b"\x01"],
        NO_FLAGS,
        _CODE.INVALID_STACK_OPERATION,
        2,
        "830-833",
    ),
    "OP_PICK on a number too long": _Case(
        b"\x51" + _PUSH_FIVE_BYTES + b"\x79",
        [b"\x01", _FIVE_BYTES],
        NO_FLAGS,
        _CODE.SCRIPTNUM,
        2,
        "830, 1226-1229",
    ),
    "OP_PICK on one element": _Case(
        b"\x51\x79", [b"\x01"], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "828-829"
    ),
    # the depth is checked before anything is popped
    "OP_2DROP on one element": _Case(
        b"\x51\x6d", [b"\x01"], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "698-699"
    ),
    "OP_NIP on one element": _Case(
        b"\x51\x77", [b"\x01"], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "807-808"
    ),
    "OP_ROT on two elements": _Case(
        b"\x51\x52\x7b",
        [b"\x01", b"\x02"],
        NO_FLAGS,
        _CODE.INVALID_STACK_OPERATION,
        2,
        "846-847",
    ),
    "OP_TUCK on one element": _Case(
        b"\x51\x7d", [b"\x01"], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "865-866"
    ),
    "OP_EQUAL on one element": _Case(
        b"\x51\x87", [b"\x01"], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "892-893"
    ),
    "OP_2SWAP on three elements": _Case(
        b"\x51\x52\x53\x72",
        [b"\x01", b"\x02", b"\x03"],
        NO_FLAGS,
        _CODE.INVALID_STACK_OPERATION,
        3,
        "759-760",
    ),
    # EvalChecksig fails before the two operands are popped
    "OP_CHECKSIG on a signature STRICTENC refuses": _Case(
        b"\x01\x01" + _PUSH_PUB + b"\xac",
        [b"\x01", _PUB],
        ScriptFlag.STRICTENC,
        _CODE.SIG_DER,
        2,
        "201-209, 1063-1070",
    ),
    "OP_CHECKSIG on a key STRICTENC refuses": _Case(
        b"\x00\x21" + _ZERO_KEY + b"\xac",
        [b"", _ZERO_KEY],
        ScriptFlag.STRICTENC,
        _CODE.PUBKEYTYPE,
        2,
        "218-221, 1063-1070",
    ),
    "OP_CHECKSIG on a failed signature under NULLFAIL": _Case(
        b"\x01\x01" + _PUSH_PUB + b"\xac",
        [b"\x01", _PUB],
        ScriptFlag.NULLFAIL,
        _CODE.SIG_NULLFAIL,
        2,
        "339-342, 1063-1070",
    ),
    "OP_CHECKSIG on one element": _Case(
        _PUSH_PUB + b"\xac", [_PUB], NO_FLAGS, _CODE.INVALID_STACK_OPERATION, 1, "1063"
    ),
    # a BaseSignatureChecker verifies nothing: the false is a result
    "OP_CHECKSIG that fails to verify": _Case(
        b"\x00" + _PUSH_PUB + b"\xac", [b""], NO_FLAGS, None, None, "1066-1073"
    ),
    "OP_CHECKSIGVERIFY that fails to verify": _Case(
        b"\x00" + _PUSH_PUB + b"\xad",
        [b""],
        NO_FLAGS,
        _CODE.CHECKSIGVERIFY,
        2,
        "1071-1080",
    ),
    "OP_CHECKMULTISIGVERIFY that fails to verify": _Case(
        b"\x00\x00\x51" + _PUSH_PUB + b"\x51\xaf",
        [b""],
        NO_FLAGS,
        _CODE.CHECKMULTISIGVERIFY,
        5,
        "1203-1213",
    ),
    "OP_CHECKMULTISIG that verifies": _Case(
        b"\x00\x00\x00\xae", [b"\x01"], NO_FLAGS, None, None, "1105-1205"
    ),
    # the arguments stay until the signatures are checked, the dummy
    # counted among them
    "OP_CHECKMULTISIG without its dummy": _Case(
        b"\x00\x51" + _PUSH_PUB + b"\x51\xae",
        [b"", b"\x01", _PUB, b"\x01"],
        NO_FLAGS,
        _CODE.INVALID_STACK_OPERATION,
        4,
        "1133-1136",
    ),
    "OP_CHECKMULTISIG with more signatures than keys": _Case(
        b"\x00\x52" + _PUSH_PUB + b"\x51\xae",
        [b"", b"\x02", _PUB, b"\x01"],
        NO_FLAGS,
        _CODE.SIG_COUNT,
        4,
        "1130-1132",
    ),
    "OP_CHECKMULTISIG with too many keys": _Case(
        b"\x01\x15\xae", [b"\x15"], NO_FLAGS, _CODE.PUBKEY_COUNT, 1, "1116-1118"
    ),
    # NULLFAIL is asked as the signatures are popped, the top one first:
    # an empty one goes, a non-empty one stops the script
    "OP_CHECKMULTISIG under NULLFAIL": _Case(
        b"\x00\x01\x01\x00\x52" + _PUSH_PUB + _PUSH_PUB + b"\x52\xae",
        [b"", b"\x01"],
        ScriptFlag.NULLFAIL,
        _CODE.SIG_NULLFAIL,
        7,
        "1183-1191",
    ),
    # the dummy is asked about last, once the arguments are gone
    "OP_CHECKMULTISIG under NULLDUMMY": _Case(
        b"\x01\x01\x00\x51" + _PUSH_PUB + b"\x51\xae",
        [b"\x01"],
        ScriptFlag.NULLDUMMY,
        _CODE.SIG_NULLDUMMY,
        5,
        "1193-1202",
    ),
    # BaseSignatureChecker::CheckLockTime and CheckSequence answer false
    "OP_CHECKLOCKTIMEVERIFY": _Case(
        b"\x51\xb1",
        [b"\x01"],
        ScriptFlag.CHECKLOCKTIMEVERIFY,
        _CODE.UNSATISFIED_LOCKTIME,
        1,
        "546-556",
    ),
    "OP_CHECKLOCKTIMEVERIFY without its flag": _Case(
        b"\x51\xb1", [b"\x01"], NO_FLAGS, None, None, "524-527"
    ),
    "OP_CHECKSEQUENCEVERIFY": _Case(
        b"\x51\xb2",
        [b"\x01"],
        ScriptFlag.CHECKSEQUENCEVERIFY,
        _CODE.UNSATISFIED_LOCKTIME,
        1,
        "574-590",
    ),
    "OP_CHECKSEQUENCEVERIFY on the disable flag": _Case(
        _PUSH_SEQUENCE_DISABLED + b"\xb2",
        [b"\x00\x00\x00\x80\x00"],
        ScriptFlag.CHECKSEQUENCEVERIFY,
        None,
        None,
        "585-586",
    ),
    "OP_RETURN": _Case(b"\x51\x6a", [b"\x01"], NO_FLAGS, _CODE.OP_RETURN, 1, "667-669"),
    "a disabled op code": _Case(
        b"\x51\x7e", [b"\x01"], NO_FLAGS, _CODE.DISABLED_OPCODE, 1, "457-472"
    ),
    "a push running past the end": _Case(
        b"\x51\x4c", [b"\x01"], NO_FLAGS, _CODE.BAD_OPCODE, 1, "445-446"
    ),
    # the end of the loop, which has no op code to point at
    "a branch never closed": _Case(
        b"\x51\x63\x51", [b"\x01"], NO_FLAGS, _CODE.UNBALANCED_CONDITIONAL, None, "1235"
    ),
    "a script too long": _Case(
        b"\x61" * 10001, [], NO_FLAGS, _CODE.SCRIPT_SIZE, None, "428-430"
    ),
    "the altstack is not the stack": _Case(
        b"\x51\x6b", [], NO_FLAGS, None, None, "677-684"
    ),
    "a script that ends": _Case(
        b"\x93", [b"\x03"], NO_FLAGS, None, None, "945-990", (b"\x01", b"\x02")
    ),
}


@pytest.mark.parametrize("name", _CASES)
def test_the_stack_where_core_stops(name: str) -> None:
    """Return the stack, and the error, at the stop Core's lines say."""
    case = _CASES[name]
    stack, error = eval_script(case.script, case.initial, case.flags)
    assert stack == case.stack, case.core
    if case.code is None:
        assert error is None
    else:
        assert isinstance(error, ScriptError)
        assert error.code == case.code
        assert error.index == case.position
        assert error.stack_depth == (len(stack) if case.position is not None else None)


def test_the_stack_is_a_new_list() -> None:
    """The stack the script starts on is not written to."""
    initial = [b"\x01", b"\x02"]
    stack, error = eval_script(b"\x93", initial)
    assert error is None
    assert stack == [b"\x03"]
    assert initial == [b"\x01", b"\x02"]


def test_verify_script_stops_on_the_same_stack() -> None:
    """`verify_script` leaves its caller's stack where `eval_script` stops."""
    tx = Tx(check_validity=False)
    for name, case in _CASES.items():
        if case.code is None or len(case.script) > 100:
            continue
        stack = list(case.initial)
        with pytest.raises(ScriptError) as exc_info:
            verify_script(case.script, stack, 0, tx, 0, case.flags, False)
        assert stack == case.stack, name
        assert exc_info.value.code == case.code, name
        assert exc_info.value.index == case.position, name


@pytest.mark.parametrize(
    "script, stack, flags",
    [
        ("51", (), NO_FLAGS),
        (b"\x51", [b"\x01", 2], NO_FLAGS),
        (b"\x51", b"\x01", NO_FLAGS),
        (b"\x51", (), 0),
    ],
    ids=["script", "stack element", "stack", "flags"],
)
def test_the_arguments_are_checked(script: Any, stack: Any, flags: Any) -> None:
    """A malformed argument is refused, and a failing script is an answer."""
    with pytest.raises(BTClibTypeError):
        eval_script(script, stack, flags)
