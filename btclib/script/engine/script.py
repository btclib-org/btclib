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
from btclib.script.script import (
    BYTE_FROM_OP_CODE_NAME,
    OP_CODE_NAME_FROM_INT,
    op_code_spans,
    parse,
    read_op_code,
)
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


def find_and_delete(script: bytes, target: bytes) -> tuple[bytes, int]:
    """Delete every occurrence of target from script: (result, how many).

    Core's `FindAndDelete`, matched op code boundary by op code boundary
    and in one left-to-right pass, both of which are load-bearing. A
    `bytes.replace` loop is neither: it deletes a match lying inside the
    data of a push, which Core's walk never reaches, and re-running it
    over the result deletes matches that only exist because an earlier
    deletion joined their halves. Either turns a script code Core leaves
    alone into one that is shorter, differently signed, or no longer a
    script at all.

    Once a match is taken the walk resumes from just past it, wherever
    that lands — Core resumes its GetOp there too, which is how a deletion
    can leave the rest of the script read as something else. Bug for bug:
    the script code is consensus, not taste.
    """
    if not target:  # Core returns early rather than delete forever
        return script, 0
    kept: list[bytes] = []
    found = 0
    pc = pc2 = 0
    while True:
        kept.append(script[pc2:pc])
        while script[pc : pc + len(target)] == target:
            pc += len(target)
            found += 1
        pc2 = pc
        span = read_op_code(script, pc)
        if span is None:
            break
        pc = span[1]
    if not found:
        return script, 0
    kept.append(script[pc2:])
    return b"".join(kept), found


def calculate_script_code(
    script_bytes: bytes,
    codesep_offset: int,
    signatures: list[bytes],
    const_scriptcode: bool,
    segwit: bool,
) -> bytes:
    """Return the script code the signature under check commits to.

    Core's two steps and in its order: `CScript
    scriptCode(pbegincodehash, pend)`, a slice of the script's own bytes
    from just past the last executed OP_CODESEPARATOR, and then — for a
    pre-segwit signature only — FindAndDelete of the signature itself,
    which BIP-143 dropped for segwit v0 and which is why `segwit` is a
    parameter rather than a fact about the script.

    The OP_CODESEPARATORs left in the slice stay in it. Eliding them is
    the legacy serializer's, `sig_hash.legacy` doing it there because
    that is where Core does it, and doing it here as well would elide
    them before FindAndDelete rather than after.
    """
    script_code = script_bytes[codesep_offset:]

    if not segwit:
        for signature in signatures:
            script_code, found = find_and_delete(
                script_code, serialize_script([signature])
            )
            # Core's SCRIPT_ERR_SIG_FINDANDDELETE, and it errors on having
            # found rather than refusing to look: a script code that
            # carries the signature checked against it is the case the
            # flag exists to make unspendable
            if found and const_scriptcode:
                raise BTClibValueError("signature found in the script code")

    return script_code


def op_checksig(
    signature: bytes,
    signatures: list[bytes],
    pub_key: bytes,
    script_bytes: bytes,
    codesep_offset: int,
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
        codesep_offset,
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


# The op codes Core reads even inside an unexecuted branch: `fExec ||
# (OP_IF <= opcode && opcode <= OP_ENDIF)` in interpreter.cpp. It is a
# range and not the four conditionals in it, and that is the whole of
# what makes OP_VERIF (0x65) and OP_VERNOTIF (0x66) invalid whether they
# execute or not -- Core gives them no case of their own, so they fall
# to `default: BAD_OPCODE` from inside a branch that is never taken.
# Enumerating the four skipped them instead, and both engines then
# accepted a script Core rejects.
#
# Rejecting them here rather than in a pass over the parsed script is
# also what keeps tapscript faithful: Core's OP_SUCCESS pre-scan returns
# success at the first OP_SUCCESS whatever precedes it, so `OP_VERIF
# OP_SUCCESS80` is valid and must stay so (issue #182).
EVALUATED_WHEN_UNEXECUTED = range(0x63, 0x69)  # OP_IF..OP_ENDIF

# The op codes Satoshi switched off for CVE-2010-5137, which Core refuses
# earlier still: `if (opcode == OP_CAT || ...) return DISABLED_OPCODE`
# sits above the fExec test, so one of these anywhere in a script -- in a
# branch never taken, after an OP_RETURN, wherever -- makes it unspendable
# and its error DISABLED_OPCODE rather than BAD_OPCODE. Read from the
# table by name, so that a name that stops existing fails at import rather
# than leaving a rule that quietly stops matching.
#
# Only this engine needs them: BIP342 turns every one of these bytes into
# an OP_SUCCESSx, so in tapscript they are the opposite of disabled and
# the pre-scan answers before the interpreter sees one.
DISABLED_OP_CODES = frozenset(
    BYTE_FROM_OP_CODE_NAME[name][0]
    for name in (
        "OP_CAT",
        "OP_SUBSTR",
        "OP_LEFT",
        "OP_RIGHT",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_2MUL",
        "OP_2DIV",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFT",
        "OP_RSHIFT",
    )
)


def check_not_disabled(op_code: int) -> None:
    """Reject an op code disabled by CVE-2010-5137, executed or not."""
    if op_code in DISABLED_OP_CODES:
        raise BTClibValueError(f"disabled op code: {op_code_name(op_code)}")


def prepare_script(script: ScriptList, flags: ScriptFlag, segwit: bool) -> None:
    if (
        "OP_CODESEPARATOR" in script
        and ScriptFlag.CONST_SCRIPTCODE in flags
        and not segwit
    ):
        raise BTClibValueError("OP_CODESEPARATOR in a non-segwit script")


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

    # Core's pbegincodehash, an offset into script_bytes and not an index
    # into the parse: a script code is a slice of the script's own bytes,
    # and measuring where to cut it by re-serializing the op codes before
    # the cut moved it by whatever a non-minimal push there lost in the
    # round trip (issue #176). s.tell() cannot answer either — a *VERIFY
    # op code below rebuilds the stream out of the two it stands for, so
    # after one of those the stream is no longer the script. The op code
    # index survives that rebuild, which winds it back by the two it
    # injects, and neither of those two is ever an OP_CODESEPARATOR, so
    # the index is the right one wherever it is read below. Hence this:
    # the byte one past each op code, walked once and only for a script
    # that has a separator to cut at
    codesep_offset = 0
    op_code_stops = (
        [stop for _, _, stop in op_code_spans(script_bytes)]
        if "OP_CODESEPARATOR" in script
        else []
    )

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

            check_not_disabled(t)

            if skip_execution and t not in EVALUATED_WHEN_UNEXECUTED:
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
                    codesep_offset,
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
                        codesep_offset,
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
                codesep_offset = op_code_stops[script_index]
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
