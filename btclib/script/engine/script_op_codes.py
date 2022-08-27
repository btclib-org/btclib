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

from btclib.alias import ScriptList
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha1, sha256
from btclib.tx.tx import Tx
from btclib.utils import decode_num, encode_num


def _to_num(element: bytes, flags: List[str], max_size: int = 4) -> int:
    minimaldata = "MINIMALDATA" in flags
    if minimaldata and element == b"\x80":
        raise BTClibValueError()
    if len(element) > max_size:
        raise BTClibValueError()
    if element == b"":
        return 0
    x = decode_num(element)
    if minimaldata and _from_num(x) != element:
        raise BTClibValueError()
    return x


def _from_num(x: int) -> bytes:
    if x == 0:
        return b""
    return encode_num(x)

def _to_bool(element: bytes):
    for x in element[:-1]:
        if x != 0:
            return True
    if not element or element[-1] in (0x00, 0x80): # positive or negative 0
        return False
    return True


def op_if(
    stack: List[bytes],
    condition_stack: List[bool],
    flags: List[str],
    segwit_version: int,
) -> None:

    if any(not x for x in condition_stack):
        condition_stack.append(False)
        return

    minimalif = False
    if segwit_version == 1:
        minimalif = True
    elif segwit_version == 0 and "MINIMALIF" in flags:
        minimalif = True

    if minimalif and stack[-1] not in [b"", b"\x01"]:
        raise BTClibValueError()
    condition = _to_bool(stack.pop())

    condition_stack.append(condition)


def op_notif(
    stack: List[bytes],
    condition_stack: List[bool],
    flags: List[str],
    segwit_version: int,
) -> ScriptList:

    if any(not x for x in condition_stack):
        condition_stack.append(False)
        return []

    minimalif = False
    if segwit_version == 1:
        minimalif = True
    elif segwit_version == 0 and "MINIMALIF" in flags:
        minimalif = True

    if minimalif and stack[-1] not in [b"", b"\x01"]:
        raise BTClibValueError()
    condition = _to_bool(stack.pop())

    condition_stack.append(not condition)


def op_else(condition_stack: List[bool]) -> None:
    if len(condition_stack) == 1:
        raise BTClibValueError()
    condition_stack[-1] = not condition_stack[-1]


def op_endif(condition_stack: List[bool]) -> None:
    condition_stack.pop()


def op_nop(flags: List[str]) -> None:
    if "DISCOURAGE_UPGRADABLE_NOPS" in flags:
        raise BTClibValueError()


def op_dup(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(stack[-1])


def op_2dup(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    if len(stack) < 2:
        raise BTClibValueError()
    stack.extend(stack[-2:])


def op_drop(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.pop()


def op_2drop(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.pop()
    stack.pop()


def op_swap(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack[-1], stack[-2] = stack[-2], stack[-1]


def op_1negate(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(_from_num(-1))


def op_verify(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    if not _to_bool(stack.pop()):
        raise BTClibValueError()


def op_return(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    raise BTClibValueError()


def op_equal(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    a = stack.pop()
    b = stack.pop()
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_equalverify(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> ScriptList:
    return ["OP_EQUAL", "OP_VERIFY"]


def op_checksigverify(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> ScriptList:
    return ["OP_CHECKSIG", "OP_VERIFY"]


def op_checkmultisigverify(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> ScriptList:
    return ["OP_CHECKMULTISIG", "OP_VERIFY"]


def op_size(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(_from_num(len(stack[-1])))


def op_ripemd160(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(ripemd160(stack.pop()))


def op_sha1(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(sha1(stack.pop()))


def op_sha256(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(sha256(stack.pop()))


def op_hash160(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(hash160(stack.pop()))


def op_hash256(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(hash256(stack.pop()))


def op_1add(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a + 1))


def op_1sub(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a - 1))


def op_negate(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(-a))


def op_abs(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(abs(a)))


def op_not(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    if _to_num(stack.pop(), flags) == 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_0notequal(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    a = _to_num(stack.pop(), flags)
    if a == 0:
        stack.append(b"")
    else:
        stack.append(b"\x01")


def op_add(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a + b))


def op_sub(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(a - b))


def op_booland(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a != 0 and b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_boolor(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a != 0 or b != 0:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequal(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a == b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_numequalverify(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> ScriptList:
    return ["OP_NUMEQUAL", "OP_VERIFY"]


def op_numnotequal(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a != b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthan(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a < b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthan(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a > b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_lessthanorequal(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a <= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_greaterthanorequal(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    if a >= b:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_min(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(min(a, b)))


def op_max(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    b = _to_num(stack.pop(), flags)
    a = _to_num(stack.pop(), flags)
    stack.append(_from_num(max(a, b)))


def op_within(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    M = _to_num(stack.pop(), flags)
    m = _to_num(stack.pop(), flags)
    x = _to_num(stack.pop(), flags)
    if m <= x < M:
        stack.append(b"\x01")
    else:
        stack.append(b"")


def op_toaltstack(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    altstack.append(stack.pop())


def op_fromaltstack(
    stack: List[bytes], altstack: List[bytes], flags: List[str]
) -> None:
    stack.append(altstack.pop())


def op_ifdup(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    if stack[-1] != b"":
        stack.append(stack[-1])


def op_depth(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(_from_num(len(stack)))


def op_nip(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    x = stack.pop()
    stack.pop()
    stack.append(x)


def op_over(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack.append(stack[-2])


def op_pick(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    n = _to_num(stack.pop(), flags)
    if n < 0:
        raise BTClibValueError()
    stack.append(stack[-n - 1])


def op_roll(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    n = _to_num(stack.pop(), flags)
    if n < 0:
        raise BTClibValueError()
    if len(stack) < n + 1:
        raise BTClibValueError()
    if n == 0:
        return
    new_stack = stack[: -n - 1] + stack[-n:] + [stack[-n - 1]]
    stack.clear()
    stack.extend(new_stack)


def op_rot(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    x3 = stack.pop()
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x2)
    stack.append(x3)
    stack.append(x1)


def op_tuck(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    x2 = stack.pop()
    x1 = stack.pop()
    stack.append(x2)
    stack.append(x1)
    stack.append(x2)


def op_3dup(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    if len(stack) < 3:
        raise BTClibValueError()
    stack.extend(stack[-3:])


def op_2over(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    if len(stack) < 4:
        raise BTClibValueError()
    stack.extend(stack[-4:-2])


def op_2rot(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
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


def op_2swap(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack[-1], stack[-3] = stack[-3], stack[-1]
    stack[-2], stack[-4] = stack[-4], stack[-2]


def op_checklocktimeverify(
    stack: List[bytes], tx: Tx, i: int, flags: List[str]
) -> None:
    if "CHECKLOCKTIMEVERIFY" not in flags:
        return
    if not stack:
        raise BTClibValueError()
    lock_time = _to_num(stack[-1], flags, max_size=5)
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


def op_checksequenceverify(
    stack: List[bytes], tx: Tx, i: int, flags: List[str]
) -> None:
    if "CHECKSEQUENCEVERIFY" not in flags:
        return
    if not stack:
        raise BTClibValueError()
    sequence = _to_num(stack[-1], flags, max_size=5)
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
