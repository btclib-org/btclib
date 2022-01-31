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

import btclib.script.engine.script as bitcoin_script
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


def get_hashtype(signature: bytes) -> int:
    sighash_type = 0  # all
    if len(signature) == 65:
        sighash_type = signature[-1]
        if sighash_type == 0:
            raise BTClibValueError()
    return sighash_type


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

    assert btclib_libsecp256k1.ssa.verify(msg_hash, pub_key, signature)
    # ssa.assert_as_valid_(msg_hash, pub_key, signature)


def verify_script_path_vc0(
    script_bytes: bytes,
    stack: List[Command],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    script = parse(script_bytes, taproot=True)

    if script == ["OP_SUCCESS"]:
        return

    for x in range(len(script)):
        if script[x] == "OP_CODESEPARATOR":
            script[x] = f"OP_CODESEPARATOR{x}"
    codesep_pos = 0xFFFFFFFF

    operations = {
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
        "OP_ADD": bitcoin_script.op_add,
        "OP_NOT": bitcoin_script.op_not,
        "OP_CHECKSIGVERIFY": bitcoin_script.op_checksigverify,
        "OP_CHECKSIGADD": bitcoin_script.op_checksigadd,
        "OP_EQUALVERIFY": bitcoin_script.op_equalverify,
        "OP_RESERVED": bitcoin_script.op_reserved,
        "OP_VER": bitcoin_script.op_ver,
        "OP_RESERVED1": bitcoin_script.op_reserved1,
        "OP_RESERVED2": bitcoin_script.op_reserved2,
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
                    sighash_type = get_hashtype(signature)
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
