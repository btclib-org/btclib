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

try:
    from btclib_libsecp256k1.ssa import verify as ssa_verify
except ImportError:
    from btclib.ecc.ssa import verify_ as ssa_verify  # type: ignore

from btclib import var_bytes
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script import sig_hash
from btclib.script.engine import script_op_codes
from btclib.script.engine.script import check_balanced_if
from btclib.script.engine.script_op_codes import _from_num
from btclib.script.script_pub_key import type_and_payload
from btclib.script.taproot import parse
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_command


def get_hashtype(signature: bytes) -> int:
    sighash_type = 0  # all
    if len(signature) == 65:
        sighash_type = signature[-1]
        if sighash_type == 0:
            raise BTClibValueError()
    return sighash_type


def op_checksigadd(stack: List[bytes], altstack: List[bytes], flags: List[str]) -> None:
    stack[-2], stack[-3] = stack[-3], stack[-2]
    return ["OP_CHECKSIG", "OP_ADD"][::-1]


def verify_key_path(
    script_pub_key: bytes,
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    sighash_type = get_hashtype(stack[0])
    signature = stack[0][:64]
    pub_key = type_and_payload(script_pub_key)[1]
    msg_hash = sig_hash.taproot(tx, i, prevouts, sighash_type, 0, annex, b"")

    if not ssa_verify(msg_hash, pub_key, signature[:64]):  # type: ignore
        raise BTClibValueError()


def op_checksig(
    stack: List[bytes],
    script_bytes: bytes,
    codesep_pos: int,
    tx: Tx,
    i: int,
    prevouts: List[TxOut],
    annex: bytes,
    budget: int,
) -> int:
    pub_key = stack.pop()
    signature = stack.pop()
    if len(pub_key) == 0:
        raise BTClibValueError()
    if signature:
        budget -= 50
        if budget < 0:
            raise BTClibValueError()
    if len(pub_key) == 32 and signature:
        sighash_type = get_hashtype(signature)
        preimage = b"\xc0"
        preimage += var_bytes.serialize(script_bytes)
        tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
        ext = tapleaf_hash + b"\x00" + codesep_pos.to_bytes(4, "little")
        msg_hash = sig_hash.taproot(tx, i, prevouts, sighash_type, 1, annex, ext)
        if not ssa_verify(msg_hash, pub_key, signature[:64]):  # type: ignore
            raise BTClibValueError()
    stack.append(_from_num(int(bool(signature))))
    return budget


def verify_script_path_vc0(
    script_bytes: bytes,
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
    sigops_budget: int,
    flags: List[str],
) -> None:

    if any(len(x) > 520 for x in stack):
        raise BTClibValueError()

    script = parse(script_bytes, exit_on_op_success=True)

    check_balanced_if(script)

    if script == ["OP_SUCCESS"]:
        return

    for x, op_code in enumerate(script):
        if op_code == "OP_CODESEPARATOR":
            script[x] = f"OP_CODESEPARATOR{x}"
    codesep_pos = 0xFFFFFFFF

    operations: Mapping[str, Callable] = {
        "OP_DUP": script_op_codes.op_dup,
        "OP_2DUP": script_op_codes.op_2dup,
        "OP_DROP": script_op_codes.op_drop,
        "OP_2DROP": script_op_codes.op_2drop,
        "OP_SWAP": script_op_codes.op_swap,
        "OP_IF": script_op_codes.op_if,
        "OP_NOTIF": script_op_codes.op_notif,
        "OP_1NEGATE": script_op_codes.op_1negate,
        "OP_VERIFY": script_op_codes.op_verify,
        "OP_EQUAL": script_op_codes.op_equal,
        "OP_CHECKSIGVERIFY": script_op_codes.op_checksigverify,
        "OP_CHECKSIGADD": op_checksigadd,
        "OP_EQUALVERIFY": script_op_codes.op_equalverify,
        "OP_RETURN": script_op_codes.op_return,
        "OP_SIZE": script_op_codes.op_size,
        "OP_RIPEMD160": script_op_codes.op_ripemd160,
        "OP_SHA1": script_op_codes.op_sha1,
        "OP_SHA256": script_op_codes.op_sha256,
        "OP_HASH160": script_op_codes.op_hash160,
        "OP_HASH256": script_op_codes.op_hash256,
        "OP_1ADD": script_op_codes.op_1add,
        "OP_1SUB": script_op_codes.op_1sub,
        "OP_NEGATE": script_op_codes.op_negate,
        "OP_ABS": script_op_codes.op_abs,
        "OP_NOT": script_op_codes.op_not,
        "OP_0NOTEQUAL": script_op_codes.op_0notequal,
        "OP_ADD": script_op_codes.op_add,
        "OP_SUB": script_op_codes.op_sub,
        "OP_BOOLAND": script_op_codes.op_booland,
        "OP_BOOLOR": script_op_codes.op_boolor,
        "OP_NUMEQUAL": script_op_codes.op_numequal,
        "OP_NUMEQUALVERIFY": script_op_codes.op_numequalverify,
        "OP_NUMNOTEQUAL": script_op_codes.op_numnotequal,
        "OP_LESSTHAN": script_op_codes.op_lessthan,
        "OP_GREATERTHAN": script_op_codes.op_greaterthan,
        "OP_LESSTHANOREQUAL": script_op_codes.op_lessthanorequal,
        "OP_GREATERTHANOREQUAL": script_op_codes.op_greaterthanorequal,
        "OP_MIN": script_op_codes.op_min,
        "OP_MAX": script_op_codes.op_max,
        "OP_WITHIN": script_op_codes.op_within,
        "OP_TOALTSTACK": script_op_codes.op_toaltstack,
        "OP_FROMALTSTACK": script_op_codes.op_fromaltstack,
        "OP_IFDUP": script_op_codes.op_ifdup,
        "OP_DEPTH": script_op_codes.op_depth,
        "OP_NIP": script_op_codes.op_nip,
        "OP_OVER": script_op_codes.op_over,
        "OP_PICK": script_op_codes.op_pick,
        "OP_ROLL": script_op_codes.op_roll,
        "OP_ROT": script_op_codes.op_rot,
        "OP_TUCK": script_op_codes.op_tuck,
        "OP_3DUP": script_op_codes.op_3dup,
        "OP_2OVER": script_op_codes.op_2over,
        "OP_2ROT": script_op_codes.op_2rot,
        "OP_2SWAP": script_op_codes.op_2swap,
    }

    altstack: List[bytes] = []
    condition_stack: List[bool] = [True]

    op_conditions = ["OP_IF", "OP_NOTIF", "OP_ELSE", "OP_ENDIF"]

    script.reverse()
    while script:

        if len(stack) + len(altstack) > 1000:
            raise BTClibValueError()

        op = script.pop()

        if any(not x for x in condition_stack) and op not in op_conditions:
            continue

        if isinstance(op, str) and op[:3] == "OP_":

            if op == "OP_CHECKSIG":

                sigops_budget = op_checksig(
                    stack,
                    script_bytes,
                    codesep_pos,
                    tx,
                    i,
                    prevouts,
                    annex,
                    sigops_budget,
                )

            elif op == "OP_CHECKLOCKTIMEVERIFY":
                script_op_codes.op_checklocktimeverify(stack, tx, i, flags)
            elif op == "OP_CHECKSEQUENCEVERIFY":
                script_op_codes.op_checksequenceverify(stack, tx, i, flags)

            elif op[3:].isdigit():
                stack.append(_from_num(int(op[3:])))
            elif op[:16] == "OP_CODESEPARATOR":
                codesep_pos = int(op[16:])
            elif op == "OP_IF":
                script_op_codes.op_if(
                    script, stack, condition_stack, flags, segwit_version=1
                )
            elif op == "OP_NOTIF":
                script_op_codes.op_notif(
                    script, stack, condition_stack, flags, segwit_version=1
                )
            elif op == "OP_ELSE":
                script_op_codes.op_else(condition_stack)
            elif op == "OP_ENDIF":
                script_op_codes.op_endif(condition_stack)
            elif op == "OP_NOP":
                pass
            elif "OP_NOP" in op:
                script_op_codes.op_nop(flags)
            elif op in operations:
                r = operations[op](stack, altstack, flags)
                if r:
                    script.extend(r)
            else:
                raise BTClibValueError()

        else:
            stack.append(bytes_from_command(op))

    script_op_codes.op_verify(stack, [], flags)

    if stack:
        raise BTClibValueError()
