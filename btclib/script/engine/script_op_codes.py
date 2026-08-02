# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Bitcoin Script legacy op codes."""

from __future__ import annotations

from collections.abc import Callable
from io import BytesIO
from typing import NoReturn

from btclib.alias import ScriptList
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha1, sha256
from btclib.script.engine.flags import ScriptFlag
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE, MAX_STACK_SIZE
from btclib.tx.tx import Tx
from btclib.utils import decode_num, encode_num


def _to_num(element: bytes, flags: ScriptFlag, max_size: int = 4) -> int:
    minimaldata = ScriptFlag.MINIMALDATA in flags
    if minimaldata and element == b"\x80":
        raise BTClibValueError("non-minimal encoding of zero")
    if len(element) > max_size:
        raise BTClibValueError(f"number longer than {max_size} bytes: {len(element)}")
    if element == b"":
        return 0
    x = decode_num(element)
    if minimaldata and _from_num(x) != element:
        raise BTClibValueError(f"non-minimal encoding of {x}: {element.hex()}")
    return x


def _from_num(x: int) -> bytes:
    return b"" if x == 0 else encode_num(x)


def _to_bool(element: bytes) -> bool:
    return next(
        (True for x in element[:-1] if x != 0),
        bool(element and element[-1] not in (0x00, 0x80)),
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


def check_stack_size(stack: list[bytes], altstack: list[bytes]) -> None:
    """Enforce Core's MAX_STACK_SIZE on the two stacks together."""
    if len(stack) + len(altstack) > MAX_STACK_SIZE:
        raise BTClibValueError(
            f"more than {MAX_STACK_SIZE} stack elements: {len(stack)} + {len(altstack)}"
        )


def check_minimal_push(
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
        raise BTClibValueError(
            f"non-minimal push: OP_0, OP_1NEGATE, or OP_1-OP_16 "
            f"should have been used for {data.hex()!r}"
        )
    if serialize([data])[0] != op_code:
        raise BTClibValueError(
            f"non-minimal push of {len(data)} bytes with op code {hex(op_code)}"
        )


def read_push_data(
    op_code: int,
    s: BytesIO,
    stack: list[bytes],
    skip_execution: bool,
    flags: ScriptFlag,
    serialize: Callable[[ScriptList], bytes],
    element_size_limit: int | None = MAX_SCRIPT_ELEMENT_SIZE,
) -> None:
    """Read a pushdata command from the stream and push its data.

    The read comes before the skip: the stream must advance past the
    data whether or not the branch executes, and only what executes is
    measured for minimality and pushed. The serializer is a parameter
    for check_minimal_push's reason, each engine measuring a push
    against its own script language.

    The two refusals are Core's, at the top of its EvalScript loop and
    both *before* the fExec test, which is why they sit before the skip
    and not after it: a push declaring more bytes than the script holds
    is SCRIPT_ERR_BAD_OPCODE, GetOp having failed to read it, and one
    over the element limit is SCRIPT_ERR_PUSH_SIZE. Core rejects either
    inside a branch nothing takes, and so does this.

    The limit is a parameter, and None turns it off, because tapscript
    cannot answer here: an OP_SUCCESSx anywhere makes the script valid
    with the rest of it unexecuted, so `taproot.parse` defers the
    refusal to the end of its walk and the loop has nothing left to
    measure. Core defers it the same way, by scanning for OP_SUCCESSx
    before it executes anything at all.
    """
    if op_code < 76:
        data_length = op_code
    else:
        size = 2 ** (op_code - 76)
        length_bytes = s.read(size)
        if len(length_bytes) != size:
            err_msg = f"pushdata length short of {size} bytes: {len(length_bytes)}"
            raise BTClibValueError(err_msg)
        data_length = int.from_bytes(length_bytes, byteorder="little")
    data = s.read(data_length)
    if len(data) != data_length:
        err_msg = f"pushdata of {data_length} bytes, {len(data)} in the script"
        raise BTClibValueError(err_msg)
    if element_size_limit is not None and data_length > element_size_limit:
        err_msg = f"pushdata longer than {element_size_limit} bytes: {data_length}"
        raise BTClibValueError(err_msg)
    if skip_execution:
        return
    check_minimal_push(data, op_code, flags, serialize)
    stack.append(data)


def unknown_op_code(op: str) -> NoReturn:
    """Reject a named op code the interpreter does not implement."""
    raise BTClibValueError(f"unknown op code: {op}")


def op_if(
    stack: list[bytes],
    condition_stack: list[bool],
    flags: ScriptFlag,
    segwit_version: int,
) -> None:
    if not all(condition_stack):
        condition_stack.append(False)
        return

    minimalif = segwit_version == 1 or (
        segwit_version == 0 and ScriptFlag.MINIMALIF in flags
    )
    if minimalif and stack[-1] not in [b"", b"\x01"]:
        raise BTClibValueError(f"non-minimal OP_IF condition: {stack[-1].hex()}")
    condition = _to_bool(stack.pop())

    condition_stack.append(condition)


def op_notif(
    stack: list[bytes],
    condition_stack: list[bool],
    flags: ScriptFlag,
    segwit_version: int,
) -> None:
    if not all(condition_stack):
        condition_stack.append(False)
        return

    minimalif = segwit_version == 1 or (
        segwit_version == 0 and ScriptFlag.MINIMALIF in flags
    )
    if minimalif and stack[-1] not in [b"", b"\x01"]:
        raise BTClibValueError(f"non-minimal OP_NOTIF condition: {stack[-1].hex()}")
    condition = _to_bool(stack.pop())

    condition_stack.append(not condition)


def op_else(condition_stack: list[bool]) -> None:
    if len(condition_stack) == 1:
        raise BTClibValueError("OP_ELSE without OP_IF or OP_NOTIF")
    condition_stack[-1] = not condition_stack[-1]


def op_endif(condition_stack: list[bool]) -> None:
    # Core's SCRIPT_ERR_UNBALANCED_CONDITIONAL on `vfExec.empty()`, which is
    # this list holding the sentinel alone. Popping the sentinel instead
    # leaves `all([])` True, so an OP_ENDIF arriving before its OP_IF let the
    # rest of the script run as if the branch had closed
    if len(condition_stack) == 1:
        raise BTClibValueError("OP_ENDIF without OP_IF or OP_NOTIF")
    condition_stack.pop()


def check_balanced_if(condition_stack: list[bool]) -> None:
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
        raise BTClibValueError(
            f"unbalanced conditional: {len(condition_stack) - 1} left open"
        )


def op_nop(flags: ScriptFlag) -> None:
    if ScriptFlag.DISCOURAGE_UPGRADABLE_NOPS in flags:
        raise BTClibValueError("upgradable NOP")


def op_dup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(stack[-1])


def op_2dup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    if len(stack) < 2:
        raise BTClibValueError("OP_2DUP on a stack of less than 2 elements")
    stack.extend(stack[-2:])


def op_drop(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.pop()


def op_2drop(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.pop()
    stack.pop()


def op_swap(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack[-1], stack[-2] = stack[-2], stack[-1]


def op_1negate(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(_from_num(-1))


def op_verify(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    if not _to_bool(stack.pop()):
        raise BTClibValueError("false top stack element")


def op_return(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    raise BTClibValueError("OP_RETURN")


def op_equal(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    a = stack.pop()
    b = stack.pop()
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_equalverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    return ["OP_EQUAL", "OP_VERIFY"]


def op_checksigverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    return ["OP_CHECKSIG", "OP_VERIFY"]


def op_checkmultisigverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    return ["OP_CHECKMULTISIG", "OP_VERIFY"]


def op_size(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(_from_num(len(stack[-1])))


def op_ripemd160(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(ripemd160(stack.pop()))


def op_sha1(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(sha1(stack.pop()))


def op_sha256(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(sha256(stack.pop()))


def op_hash160(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(hash160(stack.pop()))


def op_hash256(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(hash256(stack.pop()))


def op_1add(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a + 1))


def op_1sub(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a - 1))


def op_negate(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(-a))


def op_abs(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(abs(a)))


def op_not(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    if _to_num(stack.pop(), flags) == 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_0notequal(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    a = _to_num(stack.pop(), flags)
    if a == 0:
        stack.append(b"")
    else:
        stack.append(b"\x01")


def op_add(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a + b))


def op_sub(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a - b))


def op_booland(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a != 0 and b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_boolor(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a != 0 or b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequal(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequalverify(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> ScriptList:
    return ["OP_NUMEQUAL", "OP_VERIFY"]


def op_numnotequal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a != b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthan(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a < b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthan(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a > b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthanorequal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a <= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthanorequal(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a >= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_min(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(min(a, b)))


def op_max(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(max(a, b)))


def op_within(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    M = _to_num(stack.pop(), flags)
    m = _to_num(stack.pop(), flags)
    x = _to_num(stack.pop(), flags)
    if m <= x < M:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_toaltstack(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    altstack.append(stack.pop())


def op_fromaltstack(
    stack: list[bytes], altstack: list[bytes], flags: ScriptFlag
) -> None:
    stack.append(altstack.pop())


def op_ifdup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    # Core's `if (CastToBool(vch))`, not a test for the empty element: a
    # one-byte zero and a negative zero are false without being empty, so
    # `<00> OP_IFDUP` duplicates here and does not there, and every op code
    # after it reads a stack one element deeper than Core's
    if _to_bool(stack[-1]):
        stack.append(stack[-1])


def op_depth(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(_from_num(len(stack)))


def op_nip(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    x = stack.pop()
    stack.pop()
    stack.append(x)


def op_over(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack.append(stack[-2])


def op_pick(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    n = _to_num(stack.pop(), flags)
    if n < 0:
        raise BTClibValueError(f"negative OP_PICK depth: {n}")
    stack.append(stack[-n - 1])


def op_roll(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    n = _to_num(stack.pop(), flags)
    if n < 0:
        raise BTClibValueError(f"negative OP_ROLL depth: {n}")
    if len(stack) < n + 1:
        raise BTClibValueError(f"OP_ROLL depth {n} on a stack of {len(stack)} elements")
    if n == 0:
        return
    new_stack = stack[: -n - 1] + stack[-n:] + [stack[-n - 1]]
    stack.clear()
    stack.extend(new_stack)


def op_rot(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    x3 = stack.pop()
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x2)
    stack.append(x3)
    stack.append(x1)


def op_tuck(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x2)
    stack.append(x1)
    stack.append(x2)


def op_3dup(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    if len(stack) < 3:
        raise BTClibValueError("OP_3DUP on a stack of less than 3 elements")
    stack.extend(stack[-3:])


def op_2over(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    if len(stack) < 4:
        raise BTClibValueError("OP_2OVER on a stack of less than 4 elements")
    stack.extend(stack[-4:-2])


def op_2rot(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    if len(stack) < 6:
        raise BTClibValueError("OP_2ROT on a stack of less than 6 elements")
    x6 = stack.pop()
    x5 = stack.pop()
    x4 = stack.pop()
    x3 = stack.pop()
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x3)
    stack.append(x4)
    stack.append(x5)
    stack.append(x6)
    stack.append(x1)
    stack.append(x2)


def op_2swap(stack: list[bytes], altstack: list[bytes], flags: ScriptFlag) -> None:
    stack[-1], stack[-3] = stack[-3], stack[-1]
    stack[-2], stack[-4] = stack[-4], stack[-2]


def op_checklocktimeverify(
    stack: list[bytes], tx: Tx, i: int, flags: ScriptFlag
) -> None:
    if ScriptFlag.CHECKLOCKTIMEVERIFY not in flags:
        return
    if not stack:
        raise BTClibValueError("OP_CHECKLOCKTIMEVERIFY on an empty stack")
    lock_time = _to_num(stack[-1], flags, max_size=5)
    if lock_time < 0:
        raise BTClibValueError(f"negative lock time: {lock_time}")

    # different lock time type
    if tx.lock_time >= 500000000 > lock_time:
        raise BTClibValueError(
            f"block height lock time {lock_time} against "
            f"the timestamp lock time {tx.lock_time} of the transaction"
        )
    if lock_time >= 500000000 > tx.lock_time:
        raise BTClibValueError(
            f"timestamp lock time {lock_time} against "
            f"the block height lock time {tx.lock_time} of the transaction"
        )

    if lock_time > tx.lock_time:
        raise BTClibValueError(f"lock time {lock_time} > {tx.lock_time}")
    if tx.vin[i].sequence == 0xFFFFFFFF:
        raise BTClibValueError(f"final sequence for input {i}")


def op_checksequenceverify(
    stack: list[bytes], tx: Tx, i: int, flags: ScriptFlag
) -> None:
    if ScriptFlag.CHECKSEQUENCEVERIFY not in flags:
        return
    if not stack:
        raise BTClibValueError("OP_CHECKSEQUENCEVERIFY on an empty stack")
    sequence = _to_num(stack[-1], flags, max_size=5)
    if sequence < 0:
        raise BTClibValueError(f"negative sequence: {sequence}")
    if not sequence & (1 << 31):
        if tx.version < 2:
            raise BTClibValueError(f"transaction version {tx.version} < 2")
        if tx.vin[i].sequence & (1 << 31):
            raise BTClibValueError(f"relative lock time disabled for input {i}")
        if sequence & (1 << 22) != tx.vin[i].sequence & (1 << 22):
            raise BTClibValueError(
                f"relative lock time unit mismatch: {hex(sequence)} against "
                f"the sequence {hex(tx.vin[i].sequence)} of input {i}"
            )
        if sequence & 0x0000FFFF > tx.vin[i].sequence & 0x0000FFFF:
            raise BTClibValueError(
                f"relative lock time {sequence & 0x0000FFFF} > "
                f"{tx.vin[i].sequence & 0x0000FFFF}"
            )
