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
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.script import sig_hash
from btclib.script.engine import script_op_codes
from btclib.script.engine.script_op_codes import _from_num, _to_num
from btclib.script.script import OP_CODE_NAME_FROM_INT, parse
from btclib.script.script import serialize as serialize_script
from btclib.script.sig_hash import SIG_HASH_TYPES
from btclib.tx.tx import Tx
from btclib.utils import bytesio_from_binarydata


def fix_signature(signature: bytes, flags: List[str]) -> bytes:
    signature_suffix = signature[-1:]
    if "STRICTENC" in flags and signature_suffix[0] not in SIG_HASH_TYPES:
        raise BTClibValueError()
    signature = signature[:-1]
    if "DERSIG" not in flags or "STRICTENC" in flags:
        signature = Sig.parse(signature, strict=False).serialize()
    if "LOW_S" not in flags:
        sig = Sig.parse(signature)
        if sig.s > sig.ec.n // 2:
            signature = Sig(sig.r, sig.ec.n - sig.s).serialize()
        # Sig.parse(signature)
    return signature + signature_suffix


def check_pub_key(pub_key: bytes, segwit: bool, flags: List[str]) -> bool:
    if not pub_key:
        return False
    if pub_key[0] in [4, 6, 7]:
        if pub_key[0] in [6, 7] and "STRICTENC" in flags:
            raise BTClibValueError()
        if segwit and "WITNESS_PUBKEYTYPE" in flags:
            raise BTClibValueError()  # uncompressed pubkeys are not possible with segwit
        return len(pub_key) == 65
    if pub_key[0] in [2, 3]:
        return len(pub_key) == 33
    return False


def calculate_script_code(
    script_bytes: bytes,
    separator_index: int,
    signatures: List[bytes],
    const_scriptcode: bool,
    segwit: bool,
) -> bytes:

    script_code = parse(script_bytes, accept_unknown=True)
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

    script_code = parse(script_bytes, accept_unknown=True)
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

    if not signature:
        return False
    try:
        signature = fix_signature(signature, flags)
    except (BTClibValueError, BTClibRuntimeError) as e:
        if "DERSIG" in flags or "STRICTENC" in flags:
            raise e
        return False

    if not check_pub_key(pub_key, segwit, flags):
        if "STRICTENC" in flags:
            raise BTClibValueError()
        return False

    script_code = calculate_script_code(
        script_bytes, codesep_index, signatures, "CONST_SCRIPTCODE" in flags, segwit
    )
    if segwit:
        msg_hash = sig_hash.segwit_v0(script_code, tx, i, signature[-1], prevout_value)
    else:
        msg_hash = sig_hash.legacy(script_code, tx, i, signature[-1])
    return dsa_verify(msg_hash, pub_key, signature[:-1])  # type: ignore


def check_script_op_code_limit(script: List[Command], segwit: bool) -> None:
    count = 0
    for i, op in enumerate(script):
        if not isinstance(op, str):
            continue
        serialized_op = serialize_script([op])
        if not (len(serialized_op) == 1 and serialized_op[0] > 0x60):
            continue
        if "OP_CHECKMULTISIG" in op:
            pub_key_count = script[i - 1] # if i else 'OP_0' # FIXME: fails on strange scripts
            if isinstance(pub_key_count, str):
                if "OP_" in pub_key_count:
                    count += int(pub_key_count[3:])
                else:
                    count += int(pub_key_count, 16)
            elif isinstance(pub_key_count, int):
                count += pub_key_count
        if "OP_CHECKSIG" in op:
            count += 1
        count += 1
    if count > 201:
        raise BTClibValueError()


def prepare_script(script: List[Command], flags: List[str], segwit: bool) -> None:
    if "OP_CODESEPARATOR" in script and "CONST_SCRIPTCODE" in flags and not segwit:
        raise BTClibValueError()

    if "OP_VERIF" in script or "OP_VERNOTIF" in script:
        raise BTClibValueError()


def check_balanced_if(script: List[Command]) -> None:
    if script.count("OP_IF") + script.count("OP_NOTIF") - script.count("OP_ENDIF"):
        raise BTClibValueError()


def verify_script(
    script_bytes: bytes,
    stack: List[bytes],
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: List[str],
    segwit: bool,
    final: bool = False,
) -> None:

    if len(script_bytes) > 10000:
        raise BTClibValueError()

    script = parse(script_bytes, accept_unknown=True)
    check_script_op_code_limit(script, segwit)
    check_balanced_if(script)
    prepare_script(script, flags, segwit)

    segwit_version = 0 if segwit else -1

    codesep_index = -1

    script_index = -1

    operations: MutableMapping[str, Callable] = {
        "OP_DUP": script_op_codes.op_dup,
        "OP_2DUP": script_op_codes.op_2dup,
        "OP_DROP": script_op_codes.op_drop,
        "OP_2DROP": script_op_codes.op_2drop,
        "OP_SWAP": script_op_codes.op_swap,
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

    altstack: List[bytes] = []
    condition_stack: List[bool] = [True]

    op_conditions = [99, 100, 103, 104]  # ["OP_IF", "OP_NOTIF", "OP_ELSE", "OP_ENDIF"]

    s = bytesio_from_binarydata(script_bytes)
    while True:

        script_index += 1

        if len(stack) + len(altstack) > 1000:
            raise BTClibValueError()

        skip_execution = not all(condition_stack)

        b = s.read(1)
        if not b:
            break
        t = b[0]
        if 0 < t <= 78:  # pushdata
            if t < 76:
                data_length = t
            else:
                data_length = int.from_bytes(s.read(2 ** (t - 76)), byteorder="little")
            a = s.read(data_length)
            if skip_execution:
                continue
            if "MINIMALDATA" in flags:
                if len(a) == 1 and (a[0] == 129 or 0 < a[0] <= 16) or len(a) == 0:
                    raise BTClibValueError()
                if serialize_script([a])[0] != t:
                    raise BTClibValueError()
            stack.append(a)
            continue
        if skip_execution and t not in op_conditions:
            continue
        op = OP_CODE_NAME_FROM_INT[t]

        if op == "OP_CHECKSIG":

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
            if "NULLFAIL" in flags and not result and signature != b"":
                raise BTClibValueError()
            stack.append(_from_num(int(result)))

        elif op == "OP_CHECKMULTISIG":
            pub_key_num = _to_num(stack.pop(), flags)
            pub_keys = [stack.pop() for x in range(pub_key_num)]
            signature_num = _to_num(stack.pop(), flags)
            signatures = [stack.pop() for x in range(signature_num)]

            if pub_key_num > 20:
                raise BTClibValueError()
            if signature_num > pub_key_num:
                raise BTClibValueError()

            if stack.pop() != b"" and "NULLDUMMY" in flags:  # dummy value
                raise BTClibValueError()
            signature_index = 0
            for pub_key_index in range(pub_key_num):
                if signature_index == signature_num:
                    break
                if pub_key_num - pub_key_index < signature_num - signature_index:
                    break
                pub_key = pub_keys[pub_key_index]
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
                stack.append(b"\x01")
            else:
                if "NULLFAIL" in flags and signatures != [b""] * signature_num:
                    raise BTClibValueError()
                stack.append(b"")

        elif op == "OP_CHECKLOCKTIMEVERIFY":
            script_op_codes.op_checklocktimeverify(stack, tx, i, flags)
        elif op == "OP_CHECKSEQUENCEVERIFY":
            script_op_codes.op_checksequenceverify(stack, tx, i, flags)
        elif op[3:].isdigit():
            stack.append(_from_num(int(op[3:])))
        elif op == "OP_CODESEPARATOR":
            codesep_index = script_index
        elif op == "OP_IF":
            script_op_codes.op_if(stack, condition_stack, flags, segwit_version)
        elif op == "OP_NOTIF":
            script_op_codes.op_notif(stack, condition_stack, flags, segwit_version)
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
                script_index -= len(r)
                s = bytesio_from_binarydata(serialize_script(r) + s.read())
        else:
            raise BTClibValueError("unknown op code")

    if len(stack) + len(altstack) > 1000:
        raise BTClibValueError()

    if final:
        script_op_codes.op_verify(stack, [], flags)
