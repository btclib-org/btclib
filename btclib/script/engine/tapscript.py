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
    from btclib.ecc.ssa import verify_ as ssa_verify

import btclib.script.engine.script as bitcoin_script
from btclib import var_bytes
from btclib.alias import Command
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script import parse, sig_hash
from btclib.script.engine.script import _from_num
from btclib.script.script_pub_key import type_and_payload
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


def op_checksigadd(
    script: List[Command], stack: List[bytes], altstack: List[bytes]
) -> None:
    stack[-2], stack[-3] = stack[-3], stack[-2]
    script.extend(["OP_CHECKSIG", "OP_ADD"][::-1])


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

    if not ssa_verify(msg_hash, pub_key, signature[:64]):
        raise BTClibValueError()


def verify_script_path_vc0(
    script_bytes: bytes,
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    script = parse(script_bytes, taproot=True)

    if script == ["OP_SUCCESS"]:
        return

    for x, op_code in enumerate(script):
        if op_code == "OP_CODESEPARATOR":
            script[x] = f"OP_CODESEPARATOR{x}"
    codesep_pos = 0xFFFFFFFF

    operations: Mapping[str, Callable] = {
        "OP_NOP": bitcoin_script.op_nop,
        "OP_DUP": bitcoin_script.op_dup,
        "OP_2DUP": bitcoin_script.op_2dup,
        "OP_DROP": bitcoin_script.op_drop,
        "OP_2DROP": bitcoin_script.op_2drop,
        "OP_SWAP": bitcoin_script.op_swap,
        "OP_IF": bitcoin_script.op_if,
        "OP_NOTIF": bitcoin_script.op_notif,
        "OP_1NEGATE": bitcoin_script.op_1negate,
        "OP_VERIFY": bitcoin_script.op_verify,
        "OP_EQUAL": bitcoin_script.op_equal,
        "OP_CHECKSIGVERIFY": bitcoin_script.op_checksigverify,
        "OP_CHECKSIGADD": op_checksigadd,
        "OP_EQUALVERIFY": bitcoin_script.op_equalverify,
        "OP_RESERVED": bitcoin_script.op_reserved,
        "OP_VER": bitcoin_script.op_ver,
        "OP_RESERVED1": bitcoin_script.op_reserved1,
        "OP_RESERVED2": bitcoin_script.op_reserved2,
        "OP_RETURN": bitcoin_script.op_return,
        "OP_SIZE": bitcoin_script.op_size,
        "OP_CHECKLOCKTIMEVERIFY": bitcoin_script.op_checklocktimeverify,
        "OP_CHECKSEQUENCEVERIFY": bitcoin_script.op_checksequenceverify,
        "OP_RIPEMD160": bitcoin_script.op_ripemd160,
        "OP_SHA1": bitcoin_script.op_sha1,
        "OP_SHA256": bitcoin_script.op_sha256,
        "OP_HASH160": bitcoin_script.op_hash160,
        "OP_HASH256": bitcoin_script.op_hash256,
        "OP_1ADD": bitcoin_script.op_1add,
        "OP_1SUB": bitcoin_script.op_1sub,
        "OP_NEGATE": bitcoin_script.op_negate,
        "OP_ABS": bitcoin_script.op_abs,
        "OP_NOT": bitcoin_script.op_not,
        "OP_0NOTEQUAL": bitcoin_script.op_0notequal,
        "OP_ADD": bitcoin_script.op_add,
        "OP_SUB": bitcoin_script.op_sub,
        "OP_BOOLAND": bitcoin_script.op_booland,
        "OP_BOOLOR": bitcoin_script.op_boolor,
        "OP_NUMEQUAL": bitcoin_script.op_numequal,
        "OP_NUMEQUALVERIFY": bitcoin_script.op_numequalverify,
        "OP_NUMNOTEQUAL": bitcoin_script.op_numnotequal,
        "OP_LESSTHAN": bitcoin_script.op_lessthan,
        "OP_GREATERTHAN": bitcoin_script.op_greaterthan,
        "OP_LESSTHANOREQUAL": bitcoin_script.op_lessthanorequal,
        "OP_GREATERTHANOREQUAL": bitcoin_script.op_greaterthanorequal,
        "OP_MIN": bitcoin_script.op_min,
        "OP_MAX": bitcoin_script.op_max,
        "OP_WITHIN": bitcoin_script.op_within,
        "OP_TOALTSTACK": bitcoin_script.op_toaltstack,
        "OP_FROMALTSTACK": bitcoin_script.op_fromaltstack,
        "OP_IFDUP": bitcoin_script.op_ifdup,
        "OP_DEPTH": bitcoin_script.op_depth,
        "OP_NIP": bitcoin_script.op_nip,
        "OP_OVER": bitcoin_script.op_over,
        "OP_PICK": bitcoin_script.op_pick,
        "OP_ROLL": bitcoin_script.op_roll,
        "OP_ROT": bitcoin_script.op_rot,
        "OP_TUCK": bitcoin_script.op_tuck,
        "OP_3DUP": bitcoin_script.op_3dup,
        "OP_2OVER": bitcoin_script.op_2over,
        "OP_2ROT": bitcoin_script.op_2rot,
        "OP_2SWAP": bitcoin_script.op_2swap,
    }

    altstack = []

    script.reverse()
    while script:
        op = script.pop()
        if isinstance(op, str) and op[:3] == "OP_":

            if op == "OP_CHECKSIG":
                pub_key = stack.pop()
                signature = stack.pop()
                if len(pub_key) == 0:
                    raise BTClibValueError()
                if len(pub_key) == 32 and signature:
                    sighash_type = get_hashtype(signature)
                    preimage = b"\xc0"
                    preimage += var_bytes.serialize(script_bytes)
                    tapleaf_hash = tagged_hash(b"TapLeaf", preimage)
                    ext = tapleaf_hash + b"\x00" + codesep_pos.to_bytes(4, "little")
                    msg_hash = sig_hash.taproot(
                        tx, i, prevouts, sighash_type, 1, annex, ext
                    )
                    if not ssa_verify(msg_hash, pub_key, signature[:64]):
                        raise BTClibValueError()
                stack.append(_from_num(int(bool(signature))))

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

    bitcoin_script.op_verify([], stack, [])

    if stack:
        raise BTClibValueError()
