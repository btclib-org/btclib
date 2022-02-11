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

from typing import Callable, List, MutableMapping

try:
    from btclib_libsecp256k1.dsa import verify as dsa_verify
except ImportError:
    from btclib.ecc.dsa import verify_ as dsa_verify  # type: ignore

from btclib.alias import Command
from btclib.ecc.der import Sig
from btclib.exceptions import BTClibValueError
from btclib.script import sig_hash
from btclib.script.engine import script_op_codes
from btclib.script.engine.script_op_codes import _from_num, _to_num
from btclib.script.script import parse
from btclib.script.script import serialize as serialize_script
from btclib.tx.tx import Tx
from btclib.utils import bytes_from_command


def fix_signature(signature: bytes, flags: List[str]) -> bytes:
    signature_suffix = signature[-1:]
    signature = signature[:-1]
    if "STRICTENC" not in flags and "DERSIG" not in flags:
        signature = Sig.parse(signature, strict=False).serialize()
    if "LOW_S" not in flags:
        sig = Sig.parse(signature)
        if sig.s > sig.ec.n // 2:
            signature = Sig(sig.r, sig.ec.n - sig.s).serialize()
        sig = Sig.parse(signature)
    return signature + signature_suffix


def check_pub_key(pub_key: bytes) -> bool:
    if pub_key[0] == 4:
        return len(pub_key) == 65
    if pub_key[0] == 2 or pub_key[0] == 3:
        return len(pub_key) == 33
    return False


def calculate_script_code(
    script_bytes: bytes,
    separator_index: int,
    signatures: List[bytes],
    const_scriptcode: bool,
    segwit: bool,
) -> bytes:

    script_code = parse(script_bytes)

    # We only take the bytes from the last executed OP_CODESEPARATOR
    # we can't serialize the script_pub_key from the last executed
    # OP_CODESEPARATOR because this will hide away the pushdata prefix, and this
    # will cause failure in some tests because FindAndDelete takes in account
    # this prefix too
    redeem_script = script_code[: separator_index + 1]
    redeem_script_len = len(serialize_script(redeem_script))
    script_bytes = script_bytes[redeem_script_len:]

    if not segwit:
        for signature in signatures:  # find and delete
            ser_signature = serialize_script([signature])
            while ser_signature in script_bytes:
                if const_scriptcode:
                    raise BTClibValueError()
                script_bytes = script_bytes.replace(ser_signature, b"")

    if const_scriptcode or segwit:
        return script_bytes

    script_code = parse(script_bytes)
    while "OP_CODESEPARATOR" in script_code:
        script_code.remove("OP_CODESEPARATOR")
    return serialize_script(script_code)


def op_checksig(
    signature: bytes,
    signatures: List[bytes],
    pub_key: bytes,
    script_bytes: bytes,
    codesep_index: int,
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: List[str],
    segwit: bool,
) -> bool:
    if not signature or not pub_key:
        return False
    script_code = calculate_script_code(
        script_bytes, codesep_index, signatures, "CONST_SCRIPTCODE" in flags, segwit
    )
    signature = fix_signature(signature, flags)
    if segwit:
        msg_hash = sig_hash.segwit_v0(script_code, tx, i, signature[-1], prevout_value)
    else:
        msg_hash = sig_hash.legacy(script_code, tx, i, signature[-1])
    if not check_pub_key(pub_key):
        return False
    if not dsa_verify(msg_hash, pub_key, signature[:-1]):  # type: ignore
        return False
    return True


def verify_script(
    script_bytes: bytes,
    redeem_script: List[Command],
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: List[str],
    segwit: bool,
) -> None:

    script_pub_key = parse(script_bytes)
    script = redeem_script + script_pub_key

    if "OP_CODESEPARATOR" in script and "CONST_SCRIPTCODE" in flags and not segwit:
        raise BTClibValueError()

    for x, op_code in enumerate(script):
        if x <= len(redeem_script):
            continue
        if op_code == "OP_CODESEPARATOR":
            script[x] = f"OP_CODESEPARATOR{x-len(redeem_script)}"
    codesep_index = -1

    operations: MutableMapping[str, Callable] = {
        "OP_NOP": script_op_codes.op_nop,
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
        "OP_CHECKMULTISIGVERIFY": script_op_codes.op_checkmultisigverify,
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

    if "CHECKLOCKTIMEVERIFY" not in flags:
        operations["OP_CHECKLOCKTIMEVERIFY"] = script_op_codes.op_nop
    if "CHECKSEQUENCEVERIFY" not in flags:
        operations["OP_CHECKSEQUENCEVERIFY"] = script_op_codes.op_nop

    stack: List[bytes] = []
    altstack: List[bytes] = []

    script_index = 0

    script.reverse()
    while script:

        if len(stack) + len(altstack) > 1000:
            raise BTClibValueError()

        op = script.pop()
        script_index += 1

        if isinstance(op, str) and op[:3] == "OP_":

            if op in operations:
                operations[op](script, stack, altstack)

            elif op == "OP_CHECKSIG":
                if script_index < len(redeem_script) and "CONST_SCRIPTCODE" in flags:
                    raise BTClibValueError()
                pub_key = stack.pop()
                signature = stack.pop()
                result = op_checksig(
                    signature,
                    [signature],
                    pub_key,
                    script_bytes,
                    codesep_index,
                    prevout_value,
                    tx,
                    i,
                    flags,
                    segwit,
                )
                stack.append(_from_num(int(result)))

            elif op == "OP_CHECKMULTISIG":
                if script_index < len(redeem_script) and "CONST_SCRIPTCODE" in flags:
                    raise BTClibValueError()
                pub_key_num = _to_num(stack.pop())
                pub_keys = [stack.pop() for x in range(pub_key_num)]
                signature_num = _to_num(stack.pop())

                signatures = [stack.pop() for x in range(signature_num)]
                if stack.pop() != b"" and "NULLDUMMY" in flags:  # dummy value
                    raise BTClibValueError()
                signature_index = 0
                for pub_key in pub_keys:
                    signature = signatures[signature_index]
                    signature_index += op_checksig(
                        signature,
                        signatures,
                        pub_key,
                        script_bytes,
                        codesep_index,
                        prevout_value,
                        tx,
                        i,
                        flags,
                        segwit,
                    )
                    if signature_index == signature_num:
                        break

                stack.append(_from_num(int(signature_index == signature_num)))

            elif op == "OP_CHECKLOCKTIMEVERIFY":
                script_op_codes.op_checklocktimeverify(stack, tx, i)
            elif op == "OP_CHECKSEQUENCEVERIFY":
                script_op_codes.op_checksequenceverify(stack, tx, i)

            elif op[3:].isdigit():
                stack.append(_from_num(int(op[3:])))
            elif op[:16] == "OP_CODESEPARATOR":
                if len(op) > 16:
                    codesep_index = int(op[16:])
            else:
                raise BTClibValueError("unknown op code")

        else:
            stack.append(bytes_from_command(op))

    script_op_codes.op_verify([], stack, [])

    if stack and ("CLEANSTACK" in flags or segwit):
        raise BTClibValueError()
