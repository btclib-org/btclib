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

from typing import List, Tuple, Sequence

from btclib.exceptions import BTClibValueError
from btclib.script.script import Command, parse, serialize
from btclib.script.script_pub_key import (
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.script.witness import Witness
from btclib.script import sig_hash
from btclib.ecc import ssa
from btclib.script.taproot import check_output_pubkey
from btclib.utils import bytes_from_octets
from btclib import var_bytes
from btclib.hashes import tagged_hash


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


def op_if(script: List[Command], stack: List[Command]) -> List[Command]:
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

    return after_script + new_condition_script[::-1]


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

    ssa.assert_as_valid_(msg_hash, pub_key, signature)


def __verify_taproot_script_path_leaf_vc0(
    script: List[Command],
    stack: List[Command],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    print(script)

    if script == ["OP_SUCCESS"]:
        return

    script_bytes = serialize(script)

    if script == ["OP_SUCCESS"]:
        return
    script.reverse()
    while script:
        command = script.pop()
        if isinstance(command, int):
            stack.append(command)
            continue
        if command[:6] == "OP_NOP":
            continue
        elif command == "OP_DUP":
            stack.append(stack[-1])
        elif command == "OP_2DUP":
            stack.extend(stack[-2:])
        elif command == "OP_DROP":
            stack.pop()
        elif command == "OP_SWAP":
            stack[-1], stack[-2] = stack[-2], stack[-1]
        elif command == "OP_CHECKSIG":
            pub_key = bytes_from_octets(stack.pop())
            signature = bytes_from_octets(stack.pop())
            sighash_type = __taproot_get_hashtype(signature)
            preimage = b"\xc0"
            preimage += var_bytes.serialize(script_bytes)
            tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
            ext = tapleaf_hash + b"\x00\xff\xff\xff\xff"
            msg_hash = sig_hash.taproot(tx, i, prevouts, sighash_type, 1, annex, ext)
            stack.append(int(bool(ssa.verify_(msg_hash, pub_key, signature))))
        elif command == "OP_EQUAL":
            a = stack.pop()
            b = stack.pop()
            stack.append(int(bool(a == b)))
        elif command == "OP_ADD":
            a = stack.pop()
            b = stack.pop()
            stack.append(a + b)
        elif command == "OP_VERIFY":
            x = stack.pop()
            if not x:
                raise BTClibValueError()
        elif command == "OP_CHECKSIGVERIFY":
            script.extend(["OP_CHECKSIG", "OP_VERIFY"][::-1])
        elif command == "OP_CHECKSIGADD":
            stack[-2], stack[-3] = stack[-3], stack[-2]
            script.extend(["OP_CHECKSIG", "OP_ADD"][::-1])
        elif command == "OP_EQUALVERIFY":
            script.extend(["OP_EQUAL", "OP_VERIFY"][::-1])
        elif command == "OP_IF":
            script = op_if(script, stack)
        elif command in ["OP_ENDIF", "OP_ELSE"]:
            raise BTClibValueError()
        elif command[:3] == "OP_":
            stack.append(int(command[3:]))
        else:
            stack.append(command)
    # 2147483648
    if len(stack) != 1:
        raise BTClibValueError()
    if stack[0] in ["OP_0", 0]:
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
            _verify_taproot_key_path(script, stack, prevouts, tx, i, annex)
        else:
            script_bytes, stack, leaf_version = __unwrap_taproot_script(script, stack)
            if leaf_version == 0xC0:
                __verify_taproot_script_path_leaf_vc0(
                    parse(script_bytes, True), stack, prevouts, tx, i, annex
                )
            else:
                pass  # unknown leaf version type
        return

    pass


def verify_transaction(prevouts: List[TxOut], tx: Tx) -> None:
    if not len(prevouts) == len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i)
