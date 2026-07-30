#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Bitcoin Script engine."""

from __future__ import annotations

from collections.abc import MutableMapping

from btclib_libsecp256k1.dsa import verify as _libsecp256k1_dsa_verify

from btclib.alias import ScriptList
from btclib.ecc.dsa import Sig
from btclib.exceptions import BTClibRuntimeError, BTClibValueError, ScriptError
from btclib.script import sig_hash
from btclib.script.engine import script_op_codes
from btclib.script.engine.flags import ScriptFlag
from btclib.script.engine.script_op_codes import ScriptOp, _from_num, _to_num
from btclib.script.script import OP_CODE_NAME_FROM_INT, parse
from btclib.script.script import serialize as serialize_script
from btclib.script.sig_hash import SIG_HASH_TYPES, PrecomputedTxData
from btclib.tx.tx import Tx
from btclib.utils import bytesio_from_binarydata


def dsa_verify(msg_hash: bytes, pub_key: bytes, sig: bytes) -> bool:
    """Verify an ECDSA signature, returning False if it is malformed.

    The bindings raise a ValueError on a signature or public key that
    libsecp256k1 refuses to parse, while the engine treats it as a failed
    verification: DER strictness is enforced upstream, by fix_signature,
    according to the DERSIG and STRICTENC flags.
    """
    try:
        return bool(_libsecp256k1_dsa_verify(msg_hash, pub_key, sig))
    except ValueError:
        return False


def fix_signature(signature: bytes, flags: ScriptFlag) -> bytes:
    signature_suffix = signature[-1:]
    if ScriptFlag.STRICTENC in flags and signature_suffix[0] not in SIG_HASH_TYPES:
        raise BTClibValueError(f"invalid sig hash type: {hex(signature_suffix[0])}")
    signature = signature[:-1]
    if ScriptFlag.DERSIG not in flags or ScriptFlag.STRICTENC in flags:
        signature = Sig.parse(signature, strict=False).serialize()
    if ScriptFlag.LOW_S not in flags:
        sig = Sig.parse(signature)
        if sig.s > sig.ec.n // 2:
            signature = Sig(sig.r, sig.ec.n - sig.s).serialize()
        # Sig.parse(signature)
    return signature + signature_suffix


def check_pub_key(pub_key: bytes, segwit: bool, flags: ScriptFlag) -> bool:
    if not pub_key:
        return False
    if pub_key[0] in [4, 6, 7]:
        if pub_key[0] in [6, 7] and ScriptFlag.STRICTENC in flags:
            raise BTClibValueError(f"hybrid public key prefix: {hex(pub_key[0])}")
        if segwit and ScriptFlag.WITNESS_PUBKEYTYPE in flags:
            raise BTClibValueError("uncompressed public key in a segwit script")
        return len(pub_key) == 65
    return len(pub_key) == 33 if pub_key[0] in [2, 3] else False


def calculate_script_code(
    script_bytes: bytes,
    separator_index: int,
    signatures: list[bytes],
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
                    raise BTClibValueError("signature found in the script code")
                script_bytes = script_bytes.replace(ser_signature, b"")

    if const_scriptcode or segwit:
        return script_bytes

    script_code = parse(script_bytes, accept_unknown=True)
    while "OP_CODESEPARATOR" in script_code:
        script_code.remove("OP_CODESEPARATOR")
    return serialize_script(script_code)


def op_checksig(
    signature: bytes,
    signatures: list[bytes],
    pub_key: bytes,
    script_bytes: bytes,
    codesep_index: int,
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: ScriptFlag,
    segwit: bool,
    precomputed: PrecomputedTxData | None = None,
) -> bool:
    if not signature:
        return False
    try:
        signature = fix_signature(signature, flags)
    except (BTClibValueError, BTClibRuntimeError):
        if ScriptFlag.DERSIG in flags or ScriptFlag.STRICTENC in flags:
            raise
        return False

    if not check_pub_key(pub_key, segwit, flags):
        if ScriptFlag.STRICTENC in flags:
            raise BTClibValueError(f"invalid public key: {pub_key.hex()}")
        return False

    script_code = calculate_script_code(
        script_bytes,
        codesep_index,
        signatures,
        ScriptFlag.CONST_SCRIPTCODE in flags,
        segwit,
    )
    if segwit:
        msg_hash = sig_hash.segwit_v0(
            script_code, tx, i, signature[-1], prevout_value, precomputed
        )
    else:
        # the legacy sig_hash preimage is the transaction itself, blanked
        # and re-serialized per input: there is no transaction-wide part of
        # it to share, here or in Bitcoin Core
        msg_hash = sig_hash.legacy(script_code, tx, i, signature[-1])
    return bool(dsa_verify(msg_hash, pub_key, signature[:-1]))


def op_code_name(op_code: int) -> str:
    """Name an op code, rather than answer a missing key with a KeyError."""
    if op_code not in OP_CODE_NAME_FROM_INT:
        raise BTClibValueError(f"unknown op code: {hex(op_code)}")
    return OP_CODE_NAME_FROM_INT[op_code]


def check_nullfail(
    flags: ScriptFlag, verified: bool, signatures: list[bytes], op: str
) -> None:
    """Reject a signature that failed to verify and was not empty."""
    if ScriptFlag.NULLFAIL in flags and not verified and any(signatures):
        raise BTClibValueError(f"non-empty signature for a failed {op}")


def check_nulldummy(dummy: bytes, flags: ScriptFlag) -> None:
    """Reject a non-empty dummy, the element OP_CHECKMULTISIG pops too many."""
    if dummy != b"" and ScriptFlag.NULLDUMMY in flags:
        raise BTClibValueError("non-empty OP_CHECKMULTISIG dummy element")


def check_multisig_counts(pub_key_num: int, signature_num: int) -> None:
    if pub_key_num > 20:
        raise BTClibValueError(f"more than 20 public keys: {pub_key_num}")
    if signature_num > pub_key_num:
        raise BTClibValueError(
            f"{signature_num} signatures for {pub_key_num} public keys"
        )


def script_op_count(count: int, increment: int) -> int:
    count += increment
    if count > 201:
        raise BTClibValueError(f"more than 201 op codes: {count}")
    return count


def prepare_script(script: ScriptList, flags: ScriptFlag, segwit: bool) -> None:
    if (
        "OP_CODESEPARATOR" in script
        and ScriptFlag.CONST_SCRIPTCODE in flags
        and not segwit
    ):
        raise BTClibValueError("OP_CODESEPARATOR in a non-segwit script")

    if "OP_VERIF" in script or "OP_VERNOTIF" in script:
        raise BTClibValueError("disabled op code: OP_VERIF or OP_VERNOTIF")


def check_balanced_if(script: ScriptList) -> None:
    if script.count("OP_IF") + script.count("OP_NOTIF") - script.count("OP_ENDIF"):
        raise BTClibValueError(
            f"unbalanced conditional: {script.count('OP_IF')} OP_IF, "
            f"{script.count('OP_NOTIF')} OP_NOTIF, {script.count('OP_ENDIF')} OP_ENDIF"
        )


def verify_script(
    script_bytes: bytes,
    stack: list[bytes],
    prevout_value: int,
    tx: Tx,
    i: int,
    flags: ScriptFlag,
    segwit: bool,
    final: bool = False,
    precomputed: PrecomputedTxData | None = None,
) -> None:
    if len(script_bytes) > 10000:
        raise BTClibValueError(f"script longer than 10000 bytes: {len(script_bytes)}")

    script = parse(script_bytes, accept_unknown=True)
    check_balanced_if(script)
    prepare_script(script, flags, segwit)

    segwit_version = 0 if segwit else -1

    codesep_index = -1

    script_index = -1

    operations: MutableMapping[str, ScriptOp] = {
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

    altstack: list[bytes] = []
    condition_stack: list[bool] = [True]

    op_code_num = 0

    op_conditions = [99, 100, 103, 104]  # ["OP_IF", "OP_NOTIF", "OP_ELSE", "OP_ENDIF"]

    s = bytesio_from_binarydata(script_bytes)
    try:
        while True:
            script_index += 1

            script_op_codes.check_stack_size(stack, altstack)

            skip_execution = not all(condition_stack)

            b = s.read(1)
            if not b:
                break
            t = b[0]
            if 0 < t <= 78:  # pushdata
                if t < 76:
                    data_length = t
                else:
                    data_length = int.from_bytes(
                        s.read(2 ** (t - 76)), byteorder="little"
                    )
                a = s.read(data_length)
                if skip_execution:
                    continue
                script_op_codes.check_minimal_push(a, t, flags, serialize_script)
                stack.append(a)
                continue

            if t > 96:  # OP_16
                op_code_num = script_op_count(op_code_num, 1)

            if skip_execution and t not in op_conditions:
                continue
            op = op_code_name(t)

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
                    precomputed,
                )
                check_nullfail(flags, result, [signature], "OP_CHECKSIG")
                stack.append(_from_num(int(result)))

            elif op == "OP_CHECKMULTISIG":
                pub_key_num = _to_num(stack.pop(), flags)
                pub_keys = [stack.pop() for _ in range(pub_key_num)]
                signature_num = _to_num(stack.pop(), flags)
                signatures = [stack.pop() for _ in range(signature_num)]

                op_code_num = script_op_count(op_code_num, pub_key_num)

                check_multisig_counts(pub_key_num, signature_num)
                check_nulldummy(stack.pop(), flags)  # dummy value
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
                        precomputed,
                    )

                if signature_index == signature_num:
                    stack.append(b"\x01")
                else:
                    check_nullfail(flags, False, signatures, "OP_CHECKMULTISIG")
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
                    op_code_num -= len(r)
                    s = bytesio_from_binarydata(serialize_script(r) + s.read())
            else:
                script_op_codes.unknown_op_code(op)
    except BTClibValueError as e:
        raise ScriptError(str(e), script_index, len(stack)) from e
    except IndexError as e:
        # what the loop indexes and pops is the stack and the altstack,
        # so an IndexError out of it is an underflow; the chained
        # exception is there for the cases in which it is not
        raise ScriptError("stack underflow", script_index, len(stack)) from e

    script_op_codes.check_stack_size(stack, altstack)

    if final:
        if not stack:
            raise BTClibValueError("empty stack at the end of the script")
        script_op_codes.op_verify(stack, [], flags)
