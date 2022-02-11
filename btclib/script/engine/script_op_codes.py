# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Bitcoin Script legacy op codes
"""

from typing import List

from btclib.alias import Command
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha1, sha256
from btclib.tx.tx import Tx
from btclib.utils import decode_num, encode_num


def _to_num(element: bytes, max_size: int = 4) -> int:
    if len(element) > max_size:
        raise BTClibValueError()
    x = decode_num(element)
    return x


def _from_num(x: int) -> bytes:
    return encode_num(x)


def op_if(
    script: List[Command],
    stack: List[bytes],
    altstack: List[bytes],
    minimalif: bool = False,
) -> None:

    a = _to_num(stack.pop())
    condition = int(bool(a))
    if minimalif and a not in [0, 1]:
        raise BTClibValueError()

    level = 1
    for x in range(len(script) - 1, -1, -1):
        if script[x] == "OP_IF":
            level += 1
        if script[x] == "OP_ENDIF":
            level -= 1
        if level == 0:
            break
    if level != 0:
        raise BTClibValueError()

    after_script = script[:x]
    condition_script = script[x:][1:]
    new_condition_script = []

    level = 1

    else_reached = False
    for x in range(len(condition_script) - 1, -1, -1):
        if condition_script[x] == "OP_ELSE":
            if level == 1 and not else_reached:
                else_reached = True
                condition = 1 - condition
            continue
        if condition_script[x] == "OP_IF":
            level += 1
        if condition_script[x] == "OP_ENDIF":
            level -= 1
        if condition:
            new_condition_script.append(condition_script[x])
        if level == 0:
            break

    script.clear()
    script.extend(after_script + new_condition_script[::-1])


def op_notif(
    script: List[Command],
    stack: List[bytes],
    altstack: List[bytes],
    minimalif: bool = False,
) -> None:
    if minimalif and stack[-1] not in [b"", b"\x01"]:
        raise BTClibValueError()
    script.extend(["OP_NOT", "OP_IF"][::-1])


def op_nop(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    pass


def op_dup(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(stack[-1])


def op_2dup(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    if len(stack) < 2:
        raise BTClibValueError()
    stack.extend(stack[-2:])


def op_drop(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.pop()


def op_2drop(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.pop()
    stack.pop()


def op_swap(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack[-1], stack[-2] = stack[-2], stack[-1]


def op_1negate(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    stack.append(_from_num(-1))


def op_verify(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    x = stack.pop()
    for b in x[:-1]:
        if b != 0:
            return
    if not _to_num(x[-1:]):
        raise BTClibValueError()


def op_return(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    raise BTClibValueError()


def op_equal(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    a = stack.pop()
    b = stack.pop()
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_equalverify(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    script.extend(["OP_EQUAL", "OP_VERIFY"][::-1])


def op_checksigverify(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    script.extend(["OP_CHECKSIG", "OP_VERIFY"][::-1])


def op_checkmultisigverify(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    script.extend(["OP_CHECKMULTISIG", "OP_VERIFY"][::-1])


def op_size(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(_from_num(len(stack[-1])))


def op_ripemd160(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    stack.append(ripemd160(stack.pop()))


def op_sha1(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(sha1(stack.pop()))


def op_sha256(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(sha256(stack.pop()))


def op_hash160(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    stack.append(hash160(stack.pop()))


def op_hash256(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    stack.append(hash256(stack.pop()))


def op_1add(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(a + 1))


def op_1sub(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(a - 1))


def op_negate(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(-a))


def op_abs(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(abs(a)))


def op_not(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    x = stack.pop()
    if _to_num(x) == 0:
        stack.append(b"\x01")
    else:
        stack.append(b"\x00")


def op_0notequal(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    a = _to_num(stack.pop())
    if a == 0:
        stack.append(b"")
    else:
        stack.append(b"\x01")


def op_add(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(a + b))


def op_sub(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(a - b))


def op_booland(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a != 0 and b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_boolor(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a != 0 or b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequal(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequalverify(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    script.extend(["OP_NUMEQUAL", "OP_VERIFY"][::-1])


def op_numnotequal(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a != b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthan(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a < b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthan(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a > b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthanorequal(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a <= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthanorequal(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a >= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_min(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(min(a, b)))


def op_max(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(max(a, b)))


def op_within(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    M = _to_num(stack.pop())
    m = _to_num(stack.pop())
    x = _to_num(stack.pop())
    if m <= x < M:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_toaltstack(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    altstack.append(stack.pop())


def op_fromaltstack(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    stack.append(altstack.pop())


def op_ifdup(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    if stack[-1] != b"":
        stack.append(stack[-1])


def op_depth(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(_from_num(len(stack)))


def op_nip(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    x = stack.pop()
    stack.pop()
    stack.append(x)


def op_over(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(stack[-2])


def op_pick(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    n = _to_num(stack.pop())
    stack.append(stack[-n - 1])


def op_roll(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    n = _to_num(stack.pop())
    if len(stack) < n:
        raise BTClibValueError()
    new_stack = stack[: -n - 1] + stack[-n:] + [stack[-n - 1]]
    stack.clear()
    stack.extend(new_stack)


def op_rot(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    x3 = stack.pop()
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x2)
    stack.append(x3)
    stack.append(x1)


def op_tuck(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x2)
    stack.append(x1)
    stack.append(x2)


def op_3dup(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    if len(stack) < 3:
        raise BTClibValueError()
    stack.extend(stack[-3:])


def op_2over(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    if len(stack) < 4:
        raise BTClibValueError()
    stack.extend(stack[-4:-2])


def op_2rot(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    if len(stack) < 6:
        raise BTClibValueError()
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


def op_2swap(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack[-1], stack[-4] = stack[-4], stack[-1]
    stack[-2], stack[-3] = stack[-3], stack[-2]


def op_checklocktimeverify(stack: List[bytes], tx: Tx, i: int) -> None:
    if not stack:
        raise BTClibValueError()
    lock_time = _to_num(stack[-1], 5)
    if lock_time < 0:
        raise BTClibValueError()

    # different lock time type
    if tx.lock_time >= 500000000 > lock_time:
        raise BTClibValueError()
    if lock_time >= 500000000 > tx.lock_time:
        raise BTClibValueError()

    if lock_time > tx.lock_time:
        raise BTClibValueError()
    if tx.vin[i].sequence == 0xFFFFFFFF:
        raise BTClibValueError()


def op_checksequenceverify(stack: List[bytes], tx: Tx, i: int) -> None:
    if not stack:
        raise BTClibValueError()
    sequence = _to_num(stack[-1], 5)
    if sequence < 0:
        raise BTClibValueError()
    if not sequence & (1 << 31):
        if tx.version < 2:
            raise BTClibValueError()
        if tx.vin[i].sequence & (1 << 31):
            raise BTClibValueError()
        if sequence & (1 << 22) != tx.vin[i].sequence & (1 << 22):
            raise BTClibValueError()
        if sequence & 0x0000FFFF > tx.vin[i].sequence & 0x0000FFFF:
            raise BTClibValueError()
