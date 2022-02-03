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

from typing import Callable, List, Mapping

from btclib import var_bytes
from btclib.alias import Command
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha1, sha256, tagged_hash
from btclib.script import parse, sig_hash
from btclib.script.script_pub_key import type_and_payload
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_command, decode_num, encode_num


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


def op_if(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
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


def op_endif(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    raise BTClibValueError()


def op_else(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    raise BTClibValueError()


def op_notif(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    script.extend(["OP_NOT", "OP_IF"][::-1])


def op_nop(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    pass


def op_dup(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(stack[-1])


def op_2dup(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
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
    if x == b"":
        raise BTClibValueError()


def op_return(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    raise BTClibValueError()


def op_equal(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    a = stack.pop()
    b = stack.pop()
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"\x00")


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


def op_ver(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    raise BTClibValueError()


def op_reserved(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    raise BTClibValueError()


def op_reserved1(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    raise BTClibValueError()


def op_reserved2(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    raise BTClibValueError()


def op_size(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.append(_from_num(len(stack[-1])))


# TODO: implement locktime
def op_checklocktimeverify(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    pass


# TODO: implement locktime
def op_checksequenceverify(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    pass


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
    stack.extend(stack[-3:])


def op_2over(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
    stack.extend(stack[-4:-2])


def op_2rot(script: List[Command], stack: List[bytes], altstack: List[bytes]) -> None:
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


# TODO: check stack length


def verify_script(
    script_bytes: bytes,
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    flags: List[str],
) -> None:

    script = parse(script_bytes, taproot=True)

    for x, op_code in enumerate(script):
        if op_code == "OP_CODESEPARATOR":
            script[x] = f"OP_CODESEPARATOR{x}"
    codesep_pos = 0xFFFFFFFF

    operations: Mapping[str, Callable] = {
        "OP_NOP": op_nop,
        "OP_DUP": op_dup,
        "OP_2DUP": op_2dup,
        "OP_DROP": op_drop,
        "OP_2DROP": op_2drop,
        "OP_SWAP": op_swap,
        "OP_IF": op_if,
        "OP_NOTIF": op_notif,
        "OP_1NEGATE": op_1negate,
        "OP_VERIFY": op_verify,
        "OP_EQUAL": op_equal,
        "OP_CHECKSIGVERIFY": op_checksigverify,
        "OP_EQUALVERIFY": op_equalverify,
        "OP_RESERVED": op_reserved,
        "OP_VER": op_ver,
        "OP_RESERVED1": op_reserved1,
        "OP_RESERVED2": op_reserved2,
        "OP_RETURN": op_return,
        "OP_SIZE": op_size,
        "OP_CHECKLOCKTIMEVERIFY": op_checklocktimeverify,
        "OP_CHECKSEQUENCEVERIFY": op_checksequenceverify,
        "OP_RIPEMD160": op_ripemd160,
        "OP_SHA1": op_sha1,
        "OP_SHA256": op_sha256,
        "OP_HASH160": op_hash160,
        "OP_HASH256": op_hash256,
        "OP_1ADD": op_1add,
        "OP_1SUB": op_1sub,
        "OP_NEGATE": op_negate,
        "OP_ABS": op_abs,
        "OP_NOT": op_not,
        "OP_0NOTEQUAL": op_0notequal,
        "OP_ADD": op_add,
        "OP_SUB": op_sub,
        "OP_BOOLAND": op_booland,
        "OP_BOOLOR": op_boolor,
        "OP_NUMEQUAL": op_numequal,
        "OP_NUMEQUALVERIFY": op_numequalverify,
        "OP_NUMNOTEQUAL": op_numnotequal,
        "OP_LESSTHAN": op_lessthan,
        "OP_GREATERTHAN": op_greaterthan,
        "OP_LESSTHANOREQUAL": op_lessthanorequal,
        "OP_GREATERTHANOREQUAL": op_greaterthanorequal,
        "OP_MIN": op_min,
        "OP_MAX": op_max,
        "OP_WITHIN": op_within,
        "OP_CHECKMULTISIGVERIFY": op_checkmultisigverify,
        "OP_TOALTSTACK": op_toaltstack,
        "OP_FROMALTSTACK": op_fromaltstack,
        "OP_IFDUP": op_ifdup,
        "OP_DEPTH": op_depth,
        "OP_NIP": op_nip,
        "OP_OVER": op_over,
        "OP_PICK": op_pick,
        "OP_ROLL": op_roll,
        "OP_ROT": op_rot,
        "OP_TUCK": op_tuck,
        "OP_3DUP": op_3dup,
        "OP_2OVER": op_2over,
        "OP_2ROT": op_2rot,
        "OP_2SWAP": op_2swap,
    }

    altstack = []

    script.reverse()
    while script:
        op = script.pop()
        if isinstance(op, str) and op[:3] == "OP_":

            if op == "OP_CHECKSIG":
                pub_key = stack.pop()
                signature = stack.pop()
                stack.append(b"\x01")
                pass

            elif op == "OP_CHECKMULTISIG":
                pub_key_num = _to_num(stack.pop())
                pub_keys = [stack.pop() for x in range(pub_key_num)]
                signature_num = _to_num(stack.pop())
                signatures = [stack.pop() for x in range(signature_num)]
                if stack.pop() != b"" and "NULLDUMMY" in flags:  # dummy value
                    raise BTClibValueError()
                stack.append(b"\x01")
                pass

            elif op[3:].isdigit():
                stack.append(_from_num(int(op[3:])))
            elif op[:16] == "OP_CODESEPARATOR":
                codesep_pos = int(op[16:])
            elif op in operations:
                operations[op](script, stack, altstack)
            else:
                raise BTClibValueError()

        else:
            stack.append(bytes_from_command(op))

    op_verify([], stack, [])

    if len(stack) and "CLEANSTACK" in flags:
        raise BTClibValueError()