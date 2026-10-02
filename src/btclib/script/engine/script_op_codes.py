# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Script legacy op codes.

One function per op code, each the matching case of Core's EvalScript;
script.py and tapscript.py hold the interpreter loops that dispatch
them. These contracts are shared by every function here rather than
restated on each:

- an operand read as a number is a CScriptNum: at most 4 bytes on
  input, minimally encoded where MINIMALDATA asks, while a result may
  be pushed at 5 bytes and is refused only when an op code consumes it
  again -- Core's asymmetry, kept deliberately
- a pop from a stack too short raises IndexError, which the loop
  reports as Core's INVALID_STACK_OPERATION, and every other refusal
  is a ScriptError carrying the ScriptErrorCode Core fails with at the
  same place; the loop re-raises both with the index of the failing
  command added. The op codes that check the depth themselves do so
  only where popping would not fail on its own, where a number is read
  first and Core checks the depth before reading it, or where the
  altstack is the one short: an IndexError cannot say which stack it
  came from.
- an op code reads its operands, tests them, then pops, as Core's
  EvalScript does, so a refusal leaves them on the stack.
"""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from typing import NoReturn

from btclib.alias import ScriptList
from btclib.exceptions import ScriptError, ScriptErrorCode
from btclib.hashes import hash160, hash256, ripemd160, sha1, sha256
from btclib.script.engine.flags import ScriptFlag
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE, MAX_STACK_SIZE
from btclib.tx.limits import (
    LOCKTIME_THRESHOLD,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
)
from btclib.tx.tx import Tx
from btclib.utils import (
    _message_hex,
    _message_text,
    assert_type,
    decode_num,
    encode_num,
)

__all__ = [
    "ScriptOp",
    "assert_balanced_if",
    "assert_minimal_push",
    "assert_stack_size",
    "op_0notequal",
    "op_1add",
    "op_1negate",
    "op_1sub",
    "op_2drop",
    "op_2dup",
    "op_2over",
    "op_2rot",
    "op_2swap",
    "op_3dup",
    "op_abs",
    "op_add",
    "op_booland",
    "op_boolor",
    "op_checklocktimeverify",
    "op_checksequenceverify",
    "op_checksigverify",
    "op_depth",
    "op_drop",
    "op_dup",
    "op_else",
    "op_endif",
    "op_equal",
    "op_equalverify",
    "op_fromaltstack",
    "op_greaterthan",
    "op_greaterthanorequal",
    "op_hash160",
    "op_hash256",
    "op_if",
    "op_ifdup",
    "op_lessthan",
    "op_lessthanorequal",
    "op_max",
    "op_min",
    "op_negate",
    "op_nip",
    "op_nop",
    "op_not",
    "op_notif",
    "op_numequal",
    "op_numequalverify",
    "op_numnotequal",
    "op_over",
    "op_pick",
    "op_return",
    "op_ripemd160",
    "op_roll",
    "op_rot",
    "op_sha1",
    "op_sha256",
    "op_size",
    "op_sub",
    "op_swap",
    "op_toaltstack",
    "op_tuck",
    "op_verify",
    "op_within",
    "read_push_data",
    "unknown_op_code",
]


# CScriptNum's nDefaultMaxNumSize: an arithmetic op code reads a number
# from four octets at most, so that a script cannot compute with a value
# outside the signed 32-bit range. The two lock-time op codes are the
# exception consensus makes, five octets being what a lock time at or
# above LOCKTIME_THRESHOLD needs -- Core spells the same 5 out at each
# of them
_MAX_NUM_SIZE = 4
_MAX_LOCK_TIME_NUM_SIZE = 5


def _to_num(element: bytes, flags: ScriptFlag, max_size: int) -> int:
    minimaldata = ScriptFlag.MINIMALDATA in flags
    # both refusals are Core's scriptnum_error, which EvalScript catches
    # as SCRIPT_ERR_SCRIPTNUM
    if len(element) > max_size:
        err_msg = f"number longer than {max_size} bytes: {len(element)}"
        raise ScriptError(err_msg, ScriptErrorCode.SCRIPTNUM)
    x = decode_num(element)
    # one comparison covers every non-minimal spelling, negative zero
    # included: `encode_num` writes zero as the empty vector, so `80` and
    # `00` are both something it does not write
    if minimaldata and encode_num(x) != element:
        err_msg = f"non-minimal encoding of {x}: {element.hex()}"
        raise ScriptError(err_msg, ScriptErrorCode.SCRIPTNUM)
    return x


def _assert_operands(stack: list[bytes], count: int, op: str) -> None:
    """Refuse a stack shorter than `count`, before any operand is read.

    Core's EvalScript tests the depth before it builds a CScriptNum, so a
    bad number on a stack too short for the op code is
    INVALID_STACK_OPERATION and not SCRIPTNUM.
    """
    if len(stack) < count:
        err_msg = f"{op} on a stack of less than {count} elements"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)


def _to_bool(element: bytes) -> bool:
    return next(
        (True for x in element[:-1] if x != 0),
        bool(element and element[-1] not in {0x00, 0x80}),
    )


# what every operation in the mappings of script.py and tapscript.py is.
# The op codes taking anything else, op_if and its condition stack among
# them, are driven by those modules directly instead.
# Optional, not "| None": this is an assignment, which Python evaluates
# whatever the __future__ import above defers, and PEP 604 unions are a
# TypeError until 3.10
ScriptOp = Callable[[list[bytes], list[bytes], ScriptFlag], ScriptList | None]


# What the two interpreter loops check as they go, as functions rather
# than as the copies they were inline. Their bodies sit inside the try
# that turns a failure into a ScriptError carrying the command index, so
# a raise there is one inside a try — which is what TRY301 asks to be
# abstracted into exactly this, and the index is what no callee could
# supply itself. Shared as well: the stack size was checked in three
# places and the minimal push in two, in identical words.


def assert_stack_size(stack: list[bytes], altstack: list[bytes]) -> None:
    """Enforce Core's MAX_STACK_SIZE on the two stacks together."""
    if len(stack) + len(altstack) > MAX_STACK_SIZE:
        raise ScriptError(
            f"more than {MAX_STACK_SIZE} stack elements: {len(stack)} + {len(altstack)}",
            ScriptErrorCode.STACK_SIZE,
        )


def assert_minimal_push(
    data: bytes,
    op_code: int,
    flags: ScriptFlag,
    serialize: Callable[[ScriptList], bytes],
) -> None:
    """Enforce MINIMALDATA on a pushdata command.

    The serializer is the caller's: script.py pushes with the legacy
    one, tapscript.py with the taproot one.
    """
    if ScriptFlag.MINIMALDATA not in flags:
        return
    if (len(data) == 1 and (data[0] == 129 or 0 < data[0] <= 16)) or len(data) == 0:
        raise ScriptError(
            f"non-minimal push: OP_0, OP_1NEGATE, or OP_1-OP_16 "
            f"should have been used for {data.hex()!r}",
            ScriptErrorCode.MINIMALDATA,
        )
    if serialize([data])[0] != op_code:
        raise ScriptError(
            f"non-minimal push of {len(data)} bytes with op code {hex(op_code)}",
            ScriptErrorCode.MINIMALDATA,
        )


def read_push_data(
    op_code: int,
    s: BytesIO,
    stack: list[bytes],
    skip_execution: bool,
    flags: ScriptFlag,
    serialize: Callable[[ScriptList], bytes],
) -> None:
    """Read a pushdata command from the stream and push its data.

    The read comes before the skip: the stream must advance past the
    data whether or not the branch executes, and only what executes is
    measured for minimality and pushed. The serializer is a parameter
    for assert_minimal_push's reason, each engine measuring a push
    against its own script language.

    The two refusals are Core's, at the top of its EvalScript loop and
    both *before* the fExec test, which is why they sit before the skip
    and not after it: a push declaring more bytes than the script holds
    is SCRIPT_ERR_BAD_OPCODE, GetOp having failed to read it, and one
    over the element limit is SCRIPT_ERR_PUSH_SIZE. Core rejects either
    inside a branch nothing takes, and so does this. A tapscript holding
    an OP_SUCCESSx never reaches here, the pre-scan having answered for
    it, so the limit holds in both engines.
    """
    assert_type(skip_execution, bool, "skip_execution")
    if op_code < 76:
        data_length = op_code
    else:
        size = 2 ** (op_code - 76)
        length_bytes = s.read(size)
        if len(length_bytes) != size:
            err_msg = f"pushdata length short of {size} bytes: {len(length_bytes)}"
            raise ScriptError(err_msg, ScriptErrorCode.BAD_OPCODE)
        data_length = int.from_bytes(length_bytes, byteorder="little")
    data = s.read(data_length)
    if len(data) != data_length:
        err_msg = f"pushdata of {data_length} bytes, {len(data)} in the script"
        raise ScriptError(err_msg, ScriptErrorCode.BAD_OPCODE)
    if data_length > MAX_SCRIPT_ELEMENT_SIZE:
        err_msg = f"pushdata longer than {MAX_SCRIPT_ELEMENT_SIZE} bytes: {data_length}"
        raise ScriptError(err_msg, ScriptErrorCode.PUSH_SIZE)
    if skip_execution:
        return
    assert_minimal_push(data, op_code, flags, serialize)
    stack.append(data)


def unknown_op_code(op: str) -> NoReturn:
    """Reject a named op code the interpreter does not implement."""
    raise ScriptError(f"unknown op code: {op}", ScriptErrorCode.BAD_OPCODE)


def _assert_minimal_if(
    stack: list[bytes], flags: ScriptFlag, segwit_version: int, op: str
) -> None:
    if segwit_version == 1:
        code = ScriptErrorCode.TAPSCRIPT_MINIMALIF
    elif segwit_version == 0 and ScriptFlag.MINIMALIF in flags:
        code = ScriptErrorCode.MINIMALIF
    else:
        return
    if stack[-1] not in {b"", b"\x01"}:
        raise ScriptError(f"non-minimal {op} condition: {stack[-1].hex()}", code)


def op_if(
    stack: list[bytes],
    condition_stack: list[bool],
    flags: ScriptFlag,
    segwit_version: int,
) -> None:
    """Pop the condition and open a branch that executes on true.

    Inside an unexecuted outer branch nothing is popped and False is
    appended, so nesting is tracked without evaluating anything. The
    minimal-condition rule -- the empty element or 0x01, nothing else
    -- is consensus in tapscript per BIP342 and opt-in through the
    MINIMALIF flag in segwit v0; a legacy script takes any element as
    its condition. Core names the two refusals apart,
    TAPSCRIPT_MINIMALIF and MINIMALIF.
    """
    if not all(condition_stack):
        condition_stack.append(False)
        return

    _assert_minimal_if(stack, flags, segwit_version, "OP_IF")
    condition = _to_bool(stack.pop())

    condition_stack.append(condition)


def op_notif(
    stack: list[bytes],
    condition_stack: list[bool],
    flags: ScriptFlag,
    segwit_version: int,
) -> None:
    """Pop the condition and open a branch that executes on false.

    The unexecuted-branch behaviour and the minimal-condition rule are
    op_if's; only the sense of the popped condition is inverted.
    """
    if not all(condition_stack):
        condition_stack.append(False)
        return

    _assert_minimal_if(stack, flags, segwit_version, "OP_NOTIF")
    condition = _to_bool(stack.pop())

    condition_stack.append(not condition)


def op_else(condition_stack: list[bool]) -> None:
    """Toggle the innermost open branch, refusing one never opened.

    A toggle rather than a one-shot alternative: Core flips
    vfExec.back(), so a second OP_ELSE in the same branch turns it
    back on, and this keeps that.
    """
    if len(condition_stack) == 1:
        err_msg = "OP_ELSE without OP_IF or OP_NOTIF"
        raise ScriptError(err_msg, ScriptErrorCode.UNBALANCED_CONDITIONAL)
    condition_stack[-1] = not condition_stack[-1]


def op_endif(condition_stack: list[bool]) -> None:
    """Close the innermost open branch, refusing one never opened."""
    # Core's SCRIPT_ERR_UNBALANCED_CONDITIONAL on `vfExec.empty()`, which is
    # this list holding the sentinel alone. Popping the sentinel instead
    # leaves `all([])` True, so an OP_ENDIF arriving before its OP_IF let the
    # rest of the script run as if the branch had closed
    if len(condition_stack) == 1:
        err_msg = "OP_ENDIF without OP_IF or OP_NOTIF"
        raise ScriptError(err_msg, ScriptErrorCode.UNBALANCED_CONDITIONAL)
    condition_stack.pop()


def assert_balanced_if(condition_stack: list[bool]) -> None:
    """Reject a conditional the script never closed.

    Core's `if (!vfExec.empty())` once the loop is over, and it is one of
    the two halves of the rule: op_else and op_endif refuse a branch that
    was never opened, this refuses one that was never shut. Counting
    OP_IF, OP_NOTIF and OP_ENDIF over the parsed script instead answers
    only the second half -- the sum is what the depth ends at, so a script
    closing a branch before opening it (`OP_ENDIF OP_1 OP_IF OP_1`) counts
    to zero and Core rejects it.
    """
    if len(condition_stack) != 1:
        raise ScriptError(
            f"unbalanced conditional: {len(condition_stack) - 1} left open",
            ScriptErrorCode.UNBALANCED_CONDITIONAL,
        )


def op_nop(flags: ScriptFlag) -> None:
    """Do nothing, or refuse to under DISCOURAGE_UPGRADABLE_NOPS.

    Serves OP_NOP1 and OP_NOP4..OP_NOP10, the op codes reserved for
    soft forks to redefine; the flag is the policy that keeps them out
    of scripts until a fork gives one a meaning, as BIP65 and BIP112
    did to OP_NOP2 and OP_NOP3.
    """
    if ScriptFlag.DISCOURAGE_UPGRADABLE_NOPS in flags:
        raise ScriptError("upgradable NOP", ScriptErrorCode.DISCOURAGE_UPGRADABLE_NOPS)


def op_dup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push a copy of the top stack element."""
    stack.append(stack[-1])


def op_2dup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push copies of the top two stack elements, keeping their order."""
    if len(stack) < 2:
        err_msg = "OP_2DUP on a stack of less than 2 elements"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    stack.extend(stack[-2:])


def op_drop(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top stack element."""
    stack.pop()


def op_2drop(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top two stack elements."""
    _assert_operands(stack, 2, "OP_2DROP")
    del stack[-2:]


def op_swap(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Exchange the top two stack elements."""
    stack[-1], stack[-2] = stack[-2], stack[-1]


def op_1negate(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push the number -1."""
    stack.append(encode_num(-1))


def op_verify(
    stack: list[bytes],
    altstack: list[bytes],
    flags: ScriptFlag,
    code: ScriptErrorCode = ScriptErrorCode.VERIFY,
) -> None:
    """Pop the top element and fail the script if it is false.

    A false element stays on the stack, as in Core's `(false -- false)`.
    `code` is what the failure is, and it is not always VERIFY: Core
    names the ``*VERIFY`` op codes this completes each with its own
    code, and the end of a script failing on a false element EVAL_FALSE.
    """
    if not _to_bool(stack[-1]):
        raise ScriptError("false top stack element", code)
    stack.pop()


def op_return(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Fail the script unconditionally, leaving the stack as it is."""
    raise ScriptError("OP_RETURN", ScriptErrorCode.OP_RETURN)


def op_equal(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two elements and push whether they are byte-equal.

    Byte equality, not numeric: 0x00 and the empty element are both
    false to op_verify yet unequal here, which op_numequal answers
    the other way.
    """
    _assert_operands(stack, 2, "OP_EQUAL")
    equal = stack[-1] == stack[-2]
    del stack[-2:]
    stack.append(b"\x01" if equal else b"")


def op_equalverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    """Expand to OP_EQUAL followed by OP_VERIFY.

    The ``*VERIFY`` op codes are the pair they contract: the tapscript
    loop re-serializes the returned commands in front of the unread
    script and winds its counters back, so the pair runs without being
    counted twice. The legacy loop runs the first of the pair and then
    tests it.
    """
    return ["OP_EQUAL", "OP_VERIFY"]


def op_checksigverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    """Expand to OP_CHECKSIG followed by OP_VERIFY, as op_equalverify."""
    return ["OP_CHECKSIG", "OP_VERIFY"]


def op_size(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push the byte length of the top element, leaving it in place."""
    stack.append(encode_num(len(stack[-1])))


def op_ripemd160(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top element and push its RIPEMD160 digest."""
    stack.append(ripemd160(stack.pop()))


def op_sha1(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top element and push its SHA1 digest."""
    stack.append(sha1(stack.pop()))


def op_sha256(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top element and push its SHA256 digest."""
    stack.append(sha256(stack.pop()))


def op_hash160(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top element and push RIPEMD160 of its SHA256 digest."""
    stack.append(hash160(stack.pop()))


def op_hash256(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop the top element and push its double SHA256 digest."""
    stack.append(hash256(stack.pop()))


def op_1add(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a number and push it incremented by one."""
    a = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    stack.append(encode_num(a + 1))


def op_1sub(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a number and push it decremented by one."""
    a = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    stack.append(encode_num(a - 1))


def op_negate(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a number and push its negation."""
    a = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    stack.append(encode_num(-a))


def op_abs(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a number and push its absolute value."""
    a = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    stack.append(encode_num(abs(a)))


def op_not(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a number and push whether it is zero."""
    a = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    if a == 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_0notequal(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a number and push whether it is non-zero."""
    a = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    if a == 0:
        stack.append(b"")
    else:
        stack.append(b"\x01")


def op_add(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push their sum."""
    _assert_operands(stack, 2, "OP_ADD")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    stack.append(encode_num(a + b))


def op_sub(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push the deeper one minus the top one."""
    _assert_operands(stack, 2, "OP_SUB")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    stack.append(encode_num(a - b))


def op_booland(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push whether both are non-zero."""
    _assert_operands(stack, 2, "OP_BOOLAND")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a != 0 and b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_boolor(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push whether either is non-zero."""
    _assert_operands(stack, 2, "OP_BOOLOR")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a != 0 or b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequal(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push whether they are equal.

    Numeric equality, not byte equality: without MINIMALDATA, 0x00
    equals the empty element here and not in op_equal.
    """
    _assert_operands(stack, 2, "OP_NUMEQUAL")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequalverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    """Expand to OP_NUMEQUAL followed by OP_VERIFY, as op_equalverify."""
    return ["OP_NUMEQUAL", "OP_VERIFY"]


def op_numnotequal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Pop two numbers and push whether they differ."""
    _assert_operands(stack, 2, "OP_NUMNOTEQUAL")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a != b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthan(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push whether the deeper is below the top."""
    _assert_operands(stack, 2, "OP_LESSTHAN")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a < b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthan(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Pop two numbers and push whether the deeper is above the top."""
    _assert_operands(stack, 2, "OP_GREATERTHAN")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a > b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthanorequal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Pop two numbers and push whether the deeper is at most the top."""
    _assert_operands(stack, 2, "OP_LESSTHANOREQUAL")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a <= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthanorequal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Pop two numbers and push whether the deeper is at least the top."""
    _assert_operands(stack, 2, "OP_GREATERTHANOREQUAL")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    if a >= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_min(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push the smaller."""
    _assert_operands(stack, 2, "OP_MIN")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    stack.append(encode_num(min(a, b)))


def op_max(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop two numbers and push the larger."""
    _assert_operands(stack, 2, "OP_MAX")
    a = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    b = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-2:]
    stack.append(encode_num(max(a, b)))


def op_within(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop max, min and x, and push whether min <= x < max.

    Left-closed and right-open, which is Core's comparison.
    """
    _assert_operands(stack, 3, "OP_WITHIN")
    x = _to_num(stack[-3], flags, _MAX_NUM_SIZE)
    m = _to_num(stack[-2], flags, _MAX_NUM_SIZE)
    M = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    del stack[-3:]
    if m <= x < M:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_toaltstack(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Move the top stack element onto the altstack."""
    altstack.append(stack.pop())


def op_fromaltstack(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    """Move the top altstack element back onto the stack."""
    if not altstack:
        err_msg = "OP_FROMALTSTACK on an empty altstack"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_ALTSTACK_OPERATION)
    stack.append(altstack.pop())


def op_ifdup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push a copy of the top element only if it is true."""
    # Core's `if (CastToBool(vch))`, not a test for the empty element: a
    # one-byte zero and a negative zero are false without being empty, so
    # `<00> OP_IFDUP` duplicates here and does not there, and every op code
    # after it reads a stack one element deeper than Core's
    if _to_bool(stack[-1]):
        stack.append(stack[-1])


def op_depth(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push the number of elements on the stack."""
    stack.append(encode_num(len(stack)))


def op_nip(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Remove the element below the top, leaving the top in place."""
    _assert_operands(stack, 2, "OP_NIP")
    del stack[-2]


def op_over(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push a copy of the element below the top."""
    stack.append(stack[-2])


def op_pick(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a depth n and push a copy of the element n deep.

    Zero is the top; a negative depth is refused, one past the stack
    underflows.
    """
    _assert_operands(stack, 2, "OP_PICK")
    n = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    if n < 0:
        err_msg = f"negative OP_PICK depth: {n}"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    stack.append(stack[-n - 1])


def op_roll(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Pop a depth n and move the element n deep to the top.

    Zero is the top and leaves the stack as it is; a negative depth or
    one past the stack is refused.
    """
    _assert_operands(stack, 2, "OP_ROLL")
    n = _to_num(stack[-1], flags, _MAX_NUM_SIZE)
    stack.pop()
    if n < 0:
        err_msg = f"negative OP_ROLL depth: {n}"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    if len(stack) < n + 1:
        err_msg = f"OP_ROLL depth {n} on a stack of {len(stack)} elements"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    if n == 0:
        return
    new_stack = stack[: -n - 1] + stack[-n:] + [stack[-n - 1]]
    stack.clear()
    stack.extend(new_stack)


def op_rot(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Rotate the top three elements, the third-deep going on top."""
    _assert_operands(stack, 3, "OP_ROT")
    x3 = stack.pop()
    x2 = stack.pop()
    x1 = stack.pop()
    stack.extend((x2, x3, x1))


def op_tuck(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Insert a copy of the top element below the one under it."""
    _assert_operands(stack, 2, "OP_TUCK")
    x2 = stack.pop()
    x1 = stack.pop()
    stack.extend((x2, x1, x2))


def op_3dup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push copies of the top three stack elements, keeping their order."""
    if len(stack) < 3:
        err_msg = "OP_3DUP on a stack of less than 3 elements"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    stack.extend(stack[-3:])


def op_2over(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Push copies of the third and fourth elements, keeping their order."""
    if len(stack) < 4:
        err_msg = "OP_2OVER on a stack of less than 4 elements"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    stack.extend(stack[-4:-2])


def op_2rot(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Move the fifth and sixth elements to the top, keeping their order."""
    if len(stack) < 6:
        err_msg = "OP_2ROT on a stack of less than 6 elements"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    x6 = stack.pop()
    x5 = stack.pop()
    x4 = stack.pop()
    x3 = stack.pop()
    x2 = stack.pop()
    x1 = stack.pop()
    stack.extend((x3, x4, x5, x6, x1, x2))


def op_2swap(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    """Exchange the top pair of elements with the pair below it."""
    _assert_operands(stack, 4, "OP_2SWAP")
    stack[-1], stack[-3] = stack[-3], stack[-1]
    stack[-2], stack[-4] = stack[-4], stack[-2]


def op_checklocktimeverify(
    stack: list[bytes], tx: Tx | None, i: int, flags: ScriptFlag
) -> None:
    """Refuse to spend before the absolute lock time on the stack, BIP65.

    Reads the top element without popping it, as a number of up to 5
    bytes. The refusals are BIP65's: an empty stack, a negative lock
    time, a type mismatch -- block height against timestamp, the two
    sides of the LOCKTIME_THRESHOLD threshold -- a lock time the
    transaction's has not reached, and a final input sequence, which
    would let the transaction bypass its own lock_time. A NOP when the
    flag is off, the op code being a redefined OP_NOP2. Without a
    transaction, Core's `BaseSignatureChecker`, a lock time is never
    reached.
    """
    if ScriptFlag.CHECKLOCKTIMEVERIFY not in flags:
        return
    if not stack:
        err_msg = "OP_CHECKLOCKTIMEVERIFY on an empty stack"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    lock_time = _to_num(stack[-1], flags, _MAX_LOCK_TIME_NUM_SIZE)
    if lock_time < 0:
        err_msg = f"negative lock time: {lock_time}"
        raise ScriptError(err_msg, ScriptErrorCode.NEGATIVE_LOCKTIME)

    # every refusal below is Core's one UNSATISFIED_LOCKTIME, CheckLockTime
    # answering a bool
    unsatisfied = ScriptErrorCode.UNSATISFIED_LOCKTIME
    if tx is None:
        raise ScriptError("no transaction to hold the lock time", unsatisfied)
    # different lock time type
    if tx.lock_time >= LOCKTIME_THRESHOLD > lock_time:
        err_msg = (
            f"block height lock time {lock_time} against "
            f"the timestamp lock time {_message_text(tx.lock_time)} of the transaction"
        )
        raise ScriptError(err_msg, unsatisfied)
    if lock_time >= LOCKTIME_THRESHOLD > tx.lock_time:
        err_msg = (
            f"timestamp lock time {lock_time} against "
            f"the block height lock time {_message_text(tx.lock_time)} of the transaction"
        )
        raise ScriptError(err_msg, unsatisfied)

    if lock_time > tx.lock_time:
        err_msg = f"lock time {lock_time} > {_message_text(tx.lock_time)}"
        raise ScriptError(err_msg, unsatisfied)
    if tx.vin[i].sequence == 0xFFFFFFFF:
        raise ScriptError(f"final sequence for input {i}", unsatisfied)


def op_checksequenceverify(
    stack: list[bytes], tx: Tx | None, i: int, flags: ScriptFlag
) -> None:
    """Refuse to spend before the relative lock time on the stack, BIP112.

    Reads the top element without popping it, as a number of up to 5
    bytes. An operand with bit 31 set asks for nothing, per BIP112;
    otherwise the refusals are an empty stack, a negative operand, a
    transaction version below BIP68's 2, an input sequence with the
    disable bit set, a unit mismatch on bit 22 -- blocks against time
    -- and a relative lock time above the input's. A NOP when the flag
    is off, the op code being a redefined OP_NOP3. Without a
    transaction, Core's `BaseSignatureChecker`, a sequence is never
    reached.
    """
    if ScriptFlag.CHECKSEQUENCEVERIFY not in flags:
        return
    if not stack:
        err_msg = "OP_CHECKSEQUENCEVERIFY on an empty stack"
        raise ScriptError(err_msg, ScriptErrorCode.INVALID_STACK_OPERATION)
    sequence = _to_num(stack[-1], flags, _MAX_LOCK_TIME_NUM_SIZE)
    if sequence < 0:
        err_msg = f"negative sequence: {sequence}"
        raise ScriptError(err_msg, ScriptErrorCode.NEGATIVE_LOCKTIME)
    if not sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
        # CheckSequence answers a bool, as CheckLockTime does
        unsatisfied = ScriptErrorCode.UNSATISFIED_LOCKTIME
        if tx is None:
            raise ScriptError("no transaction to hold the sequence", unsatisfied)
        if tx.version < 2:
            err_msg = f"transaction version {_message_text(tx.version)} < 2"
            raise ScriptError(err_msg, unsatisfied)
        if tx.vin[i].sequence & SEQUENCE_LOCKTIME_DISABLE_FLAG:
            err_msg = f"relative lock time disabled for input {i}"
            raise ScriptError(err_msg, unsatisfied)
        if (
            sequence & SEQUENCE_LOCKTIME_TYPE_FLAG
            != tx.vin[i].sequence & SEQUENCE_LOCKTIME_TYPE_FLAG
        ):
            err_msg = (
                f"relative lock time unit mismatch: {hex(sequence)} against "
                f"the sequence {_message_hex(tx.vin[i].sequence)} of input {i}"
            )
            raise ScriptError(err_msg, unsatisfied)
        if (
            sequence & SEQUENCE_LOCKTIME_MASK
            > tx.vin[i].sequence & SEQUENCE_LOCKTIME_MASK
        ):
            err_msg = (
                f"relative lock time {sequence & SEQUENCE_LOCKTIME_MASK} > "
                f"{tx.vin[i].sequence & SEQUENCE_LOCKTIME_MASK}"
            )
            raise ScriptError(err_msg, unsatisfied)
