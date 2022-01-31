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

from typing import List, Tuple

import btclib_libsecp256k1.ssa

from btclib import var_bytes
from btclib.ecc import ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script import Command, parse, sig_hash
from btclib.script.script_pub_key import type_and_payload
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_octets


def op_if(script: List[Command], stack: List[Command], op: str):
    condition = int(bool(stack.pop()))

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


def op_endif(script: List[Command], stack: List[Command], op: str):
    raise BTClibValueError()


def op_else(script: List[Command], stack: List[Command], op: str):
    raise BTClibValueError()


def op_notif(script: List[Command], stack: List[Command], op: str):
    script.extend(["OP_NOT", "OP_IF"][::-1])


def op_nop(script: List[Command], stack: List[Command], op: str):
    pass


def op_dup(script: List[Command], stack: List[Command], op: str):
    stack.append(stack[-1])


def op_2dup(script: List[Command], stack: List[Command], op: str):
    stack.extend(stack[-2:])


def op_drop(script: List[Command], stack: List[Command], op: str):
    stack.pop()


def op_2drop(script: List[Command], stack: List[Command], op: str):
    stack.pop()
    stack.pop()


def op_swap(script: List[Command], stack: List[Command], op: str):
    stack[-1], stack[-2] = stack[-2], stack[-1]


def op_1negate(script: List[Command], stack: List[Command], op: str):
    stack.append(-1)


def op_verify(script: List[Command], stack: List[Command], op: str):
    x = stack.pop()
    if not x:
        raise BTClibValueError()


def op_equal(script: List[Command], stack: List[Command], op: str):
    a = stack.pop()
    b = stack.pop()
    stack.append(int(bool(a == b)))


def op_add(script: List[Command], stack: List[Command], op: str):
    a = stack.pop()
    b = stack.pop()
    stack.append(a + b)


def op_not(script: List[Command], stack: List[Command], op: str):
    x = stack.pop()
    if x in [0, 1, "0", "1"]:
        stack.append(1 - int(x))
    elif x in [b"\x00", b"\x01"]:
        stack.append(1 - int.from_bytes(x, "big"))
    else:
        stack.append(0)


def op_equalverify(script: List[Command], stack: List[Command], op: str):
    script.extend(["OP_EQUAL", "OP_VERIFY"][::-1])


def op_checksigverify(script: List[Command], stack: List[Command], op: str):
    script.extend(["OP_CHECKSIG", "OP_VERIFY"][::-1])


def op_checksigadd(script: List[Command], stack: List[Command], op: str):
    stack[-2], stack[-3] = stack[-3], stack[-2]
    script.extend(["OP_CHECKSIG", "OP_ADD"][::-1])


def op_ver(script: List[Command], stack: List[Command], op: str):
    raise BTClibValueError()


def op_reserved(script: List[Command], stack: List[Command], op: str):
    raise BTClibValueError()


def op_reserved1(script: List[Command], stack: List[Command], op: str):
    raise BTClibValueError()


def op_reserved2(script: List[Command], stack: List[Command], op: str):
    raise BTClibValueError()
