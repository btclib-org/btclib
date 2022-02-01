#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""
Bitcoin Script engine
"""

from typing import List

from btclib.alias import Command
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha1, sha256
from btclib.utils import decode_num, encode_num


def _to_num(element: bytes) -> int:
    x = decode_num(element)
    if x > 0xFFFFFFFF:
        raise BTClibValueError()
    return x


def _from_num(x: int) -> bytes:
    # x %= 0xFFFFFFFF
    # if x > 0xFFFFFFFF:
    #     raise BTClibValueError()
    return encode_num(x)


def op_if(script: List[Command], stack: List[bytes]) -> None:
    condition = int(bool(_to_num(stack.pop())))

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


def op_endif(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_else(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_notif(script: List[Command], stack: List[bytes]) -> None:
    script.extend(["OP_NOT", "OP_IF"][::-1])


def op_nop(script: List[Command], stack: List[bytes]) -> None:
    pass


def op_dup(script: List[Command], stack: List[bytes]) -> None:
    stack.append(stack[-1])


def op_2dup(script: List[Command], stack: List[bytes]) -> None:
    stack.extend(stack[-2:])


def op_drop(script: List[Command], stack: List[bytes]) -> None:
    stack.pop()


def op_2drop(script: List[Command], stack: List[bytes]) -> None:
    stack.pop()
    stack.pop()


def op_swap(script: List[Command], stack: List[bytes]) -> None:
    stack[-1], stack[-2] = stack[-2], stack[-1]


def op_1negate(script: List[Command], stack: List[bytes]) -> None:
    stack.append(_from_num(-1))


def op_verify(script: List[Command], stack: List[bytes]) -> None:
    x = stack.pop()
    if not x:
        raise BTClibValueError()


def op_return(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_equal(script: List[Command], stack: List[bytes]) -> None:
    a = stack.pop()
    b = stack.pop()
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"\x00")


def op_equalverify(script: List[Command], stack: List[bytes]) -> None:
    script.extend(["OP_EQUAL", "OP_VERIFY"][::-1])


def op_checksigverify(script: List[Command], stack: List[bytes]) -> None:
    script.extend(["OP_CHECKSIG", "OP_VERIFY"][::-1])


def op_checkmultisigverify(script: List[Command], stack: List[bytes]) -> None:
    script.extend(["OP_CHECKMULTISIG", "OP_VERIFY"][::-1])


def op_checksigadd(script: List[Command], stack: List[bytes]) -> None:
    stack[-2], stack[-3] = stack[-3], stack[-2]
    script.extend(["OP_CHECKSIG", "OP_ADD"][::-1])


def op_ver(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_reserved(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_reserved1(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_reserved2(script: List[Command], stack: List[bytes]) -> None:
    raise BTClibValueError()


def op_size(script: List[Command], stack: List[bytes]) -> None:
    stack.append(_from_num(len(stack[-1])))


# TODO: implement locktime
def op_checklocktimeverify(script: List[Command], stack: List[bytes]) -> None:
    pass


# TODO: implement locktime
def op_checksequenceverify(script: List[Command], stack: List[bytes]) -> None:
    pass


def op_ripemd160(script: List[Command], stack: List[bytes]) -> None:
    stack.append(ripemd160(stack.pop()))


def op_sha1(script: List[Command], stack: List[bytes]) -> None:
    stack.append(sha1(stack.pop()))


def op_sha256(script: List[Command], stack: List[bytes]) -> None:
    stack.append(sha256(stack.pop()))


def op_hash160(script: List[Command], stack: List[bytes]) -> None:
    stack.append(hash160(stack.pop()))


def op_hash256(script: List[Command], stack: List[bytes]) -> None:
    stack.append(hash256(stack.pop()))


def op_1add(script: List[Command], stack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(a + 1))


def op_1sub(script: List[Command], stack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(a - 1))


def op_negate(script: List[Command], stack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(-a))


def op_abs(script: List[Command], stack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    stack.append(_from_num(abs(a)))


def op_not(script: List[Command], stack: List[bytes]) -> None:
    x = stack.pop()
    if _to_num(x) == 0:
        stack.append(b"\x01")
    else:
        stack.append(b"\x00")


def op_0notequal(script: List[Command], stack: List[bytes]) -> None:
    a = _to_num(stack.pop())
    if a == 0:
        stack.append(b"")
    else:
        stack.append(b"\x01")


def op_add(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(a + b))


def op_sub(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(a - b))


def op_booland(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a != 0 and b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_boolor(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a != 0 or b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequal(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequalverify(script: List[Command], stack: List[bytes]) -> None:
    script.extend(["OP_NUMEQUAL", "OP_VERIFY"][::-1])


def op_numnotequal(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a != b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthan(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a < b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthan(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a > b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthanorequal(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a <= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthanorequal(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    if a >= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_min(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(min(a, b)))


def op_max(script: List[Command], stack: List[bytes]) -> None:
    b = _to_num(stack.pop())
    a = _to_num(stack.pop())
    stack.append(_from_num(max(a, b)))


def op_within(script: List[Command], stack: List[bytes]) -> None:
    M = _to_num(stack.pop())
    m = _to_num(stack.pop())
    x = _to_num(stack.pop())
    if m <= x < M:
        stack.append(b"\x01")
    else:
        stack.append(b"")
