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
from btclib.script import sig_hash
from btclib.script.script import Command, parse
from btclib.script.script_pub_key import (
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_octets


def __unwrap_taproot_script(
    script: bytes, stack: List[bytes]
) -> Tuple[bytes, List[bytes], int]:

    pub_key = type_and_payload(script)[1]
    script_bytes = stack[-2]
    control = stack[-1]

    if not check_output_pubkey(pub_key, script_bytes, control):
        raise BTClibValueError()

    leaf_version = stack[-1][0] & 0xFE

    return script_bytes, stack[:-2], leaf_version


def __taproot_get_hashtype(signature: bytes) -> int:
    sighash_type = 0  # all
    if len(signature) == 65:
        sighash_type = signature[-1]
        if sighash_type == 0:
            raise BTClibValueError()
    return sighash_type


def __taproot_get_annex(witness: Witness) -> bytes:
    annex = b""
    if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
        annex = witness.stack[-1]
        witness.stack = witness.stack[:-1]
    return annex


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


def _verify_taproot_key_path(
    script_pub_key: bytes,
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    sighash_type = __taproot_get_hashtype(stack[0])
    signature = stack[0][:64]
    pub_key = type_and_payload(script_pub_key)[1]
    msg_hash = sig_hash.taproot(tx, i, prevouts, sighash_type, 0, annex, b"")

    assert btclib_libsecp256k1.ssa.verify(msg_hash, pub_key, signature)
    # ssa.assert_as_valid_(msg_hash, pub_key, signature)


def __verify_taproot_script_path_leaf_vc0(
    script_bytes: bytes,
    stack: List[Command],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    script = parse(script_bytes, True)

    if script == ["OP_SUCCESS"]:
        return

    for x in range(len(script)):
        if script[x] == "OP_CODESEPARATOR":
            script[x] = f"OP_CODESEPARATOR{x}"
    codesep_pos = 0xFFFFFFFF

    operations = {
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
        "OP_ADD": op_add,
        "OP_NOT": op_not,
        "OP_CHECKSIGVERIFY": op_checksigverify,
        "OP_CHECKSIGADD": op_checksigadd,
        "OP_EQUALVERIFY": op_equalverify,
    }

    script.reverse()
    while script:
        op = script.pop()
        if op in operations:
            operations[op](script, stack, op)
        elif op == "OP_CHECKSIG":
            pub_key = bytes_from_octets(stack.pop())
            signature = bytes_from_octets(stack.pop())
            if not isinstance(pub_key, int):
                if len(pub_key) == 0:
                    raise BTClibValueError()
                if len(pub_key) == 32 and signature:
                    sighash_type = __taproot_get_hashtype(signature)
                    preimage = b"\xc0"
                    preimage += var_bytes.serialize(script_bytes)
                    tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
                    ext = tapleaf_hash + b"\x00" + codesep_pos.to_bytes(4, "little")
                    msg_hash = sig_hash.taproot(
                        tx, i, prevouts, sighash_type, 1, annex, ext
                    )
                    assert btclib_libsecp256k1.ssa.verify(msg_hash, pub_key, signature)
                    # ssa.assert_as_valid_(msg_hash, pub_key, signature[:64])
            stack.append(int(bool(signature)))
        elif isinstance(op, int):
            stack.append(op)
        elif op[:3] == "OP_" and op[3:].isdigit():
            stack.append(int(op[3:]))
        elif op[:16] == "OP_CODESEPARATOR":
            codesep_pos = int(op[16:])
        else:
            stack.append(op)

    if len(stack) != 1 or stack[0] in ["OP_0", 0]:
        raise BTClibValueError()


def verify_input(prevouts: List[TxOut], tx: Tx, i: int) -> None:

    script = prevouts[i].script_pub_key.script

    if is_p2tr(script):
        witness = tx.vin[i].script_witness
        annex = __taproot_get_annex(witness)
        stack = witness.stack
        if len(stack) == 0:
            raise BTClibValueError()
        elif len(stack) == 1:
            return _verify_taproot_key_path(script, stack, prevouts, tx, i, annex)
        else:
            script_bytes, stack, leaf_version = __unwrap_taproot_script(script, stack)
            if leaf_version == 0xC0:
                args = [script_bytes, stack, prevouts, tx, i, annex]
                return __verify_taproot_script_path_leaf_vc0(*args)
            else:
                return  # unknown leaf version type

    pass


def verify_transaction(prevouts: List[TxOut], tx: Tx) -> None:
    if not len(prevouts) == len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i)
