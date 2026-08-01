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

from btclib.alias import Command, ScriptList
from btclib.exceptions import BTClibValueError
from btclib.hashes import sha256
from btclib.script.engine import tapscript
from btclib.script.engine.flags import (
    ALL_FLAGS,
    NO_FLAGS,
    ScriptFlag,
    ScriptFlags,
    to_script_flags,
)
from btclib.script.engine.script import verify_script as verify_script_legacy
from btclib.script.engine.script_op_codes import _to_num
from btclib.script.script import parse, serialize
from btclib.script.script_pub_key import is_segwit, type_and_payload
from btclib.script.sig_hash import PrecomputedTxData
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut

# the flags live in flags.py, a module of their own because the three
# modules that check them are imported here and cannot import back; they
# are re-exported so that `from btclib.script.engine import ALL_FLAGS`
# keeps working, and that re-export is what this list is for -- mypy's
# strict mode treats an imported name as private unless __all__ names it.
# The functions defined below are named too -- saving the underscore
# helpers of verify_input, whose names already say it -- __all__ being
# the public surface of the module once it exists and not a second list
# beside it
__all__ = [
    "ALL_FLAGS",
    "NO_FLAGS",
    "ScriptFlag",
    "ScriptFlags",
    "taproot_get_annex",
    "taproot_unwrap_script",
    "to_script_flags",
    "validate_redeem_script",
    "verify_amounts",
    "verify_input",
    "verify_transaction",
]


def taproot_unwrap_script(
    script: bytes, stack: list[bytes]
) -> tuple[bytes, list[bytes], int]:
    pub_key = type_and_payload(script)[1]
    script_bytes = stack[-2]
    control = stack[-1]

    if not check_output_pubkey(pub_key, script_bytes, control):
        raise BTClibValueError("invalid taproot control block")

    leaf_version = stack[-1][0] & 0xFE

    return script_bytes, stack[:-2], leaf_version


def taproot_get_annex(witness: Witness) -> tuple[bytes, list[bytes]]:
    # the trimmed stack is returned, never written back: a get_ function must
    # not write, and verifying a transaction must not rewrite it. A list in
    # either branch, the stack being popped by the script interpreter.
    # A slice and not [-1][0], for the reason sig_hash.taproot_annex_and_ext
    # gives: an empty witness element has no first byte, and BIP-341 makes
    # the annex the element whose first byte is 0x50. Core's vectors carry
    # the case -- two `spendpath/truncshortcontrol`, whose control block is
    # truncated to nothing -- which indexing would answer with an IndexError
    if len(witness.stack) >= 2 and witness.stack[-1][:1] == b"\x50":
        return witness.stack[-1], list(witness.stack[:-1])
    return b"", list(witness.stack)


def validate_redeem_script(redeem_script: ScriptList) -> None:
    for c in redeem_script:
        if isinstance(c, str):
            if c == "OP_1NEGATE":
                continue
            if c[:2] == "OP" and not c[3:].isdigit():
                raise BTClibValueError(f"non-push command in the script_sig: {c}")


def _check_script_sig_policy(
    parsed_script_sig: ScriptList, script_flags: ScriptFlag
) -> None:
    """Refuse the script_sig shapes SIGPUSHONLY and CONST_SCRIPTCODE ban."""
    if ScriptFlag.SIGPUSHONLY in script_flags:
        validate_redeem_script(parsed_script_sig)
    if ScriptFlag.CONST_SCRIPTCODE in script_flags:
        # the four op codes Core's CONST_SCRIPTCODE watches through
        # FindAndDelete: a signature check carried in the script_sig
        # takes the script_sig as its own script code, which is exactly
        # where its signatures sit. Refused up front and as a class,
        # wherever it sits and whether or not it executes, which is
        # stricter than Core in one direction and short in another.
        # Stricter: Core's error is inside the executed branch. Short:
        # the in-loop rule closes nothing else, `op_checksig` returning
        # early on an empty signature, on a lax encoding under no
        # strict-DER flag and on a bad public key under no STRICTENC,
        # all before it builds a script code to delete from -- where
        # Core deletes and errors before reading the signature at all.
        # So a script_pub_key of that shape keeps the gap this closes
        # for the script_sig
        op_checks = (
            "OP_CHECKSIG",
            "OP_CHECKSIGVERIFY",
            "OP_CHECKMULTISIG",
            "OP_CHECKMULTISIGVERIFY",
        )
        for x in parsed_script_sig:
            if x in op_checks:
                raise BTClibValueError(f"signature check in the script_sig: {x}")


def _verify_taproot(
    script: bytes,
    witness: Witness,
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    script_flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
) -> list[bytes]:
    """Verify a p2tr spend: the v1 arm of Core's VerifyWitnessProgram.

    One witness element is the key path, more are a script path, and
    what comes back is the stack the CLEANSTACK check is to see.
    """
    budget = 50 + len(witness.serialize())
    # the annex counts towards the budget, hence the order (bip 342)
    annex, stack = taproot_get_annex(witness)
    if len(stack) == 0:
        raise BTClibValueError("empty taproot witness stack")
    if len(stack) == 1:
        tapscript.verify_key_path(script, stack, prevouts, tx, i, annex, precomputed)
        return []
    script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
    if leaf_version != 0xC0:
        # an unknown leaf version passes validation: nothing runs, so
        # nothing may be left over to reject
        return []
    tapscript.verify_script_path_vc0(
        script_bytes, stack, prevouts, tx, i, annex, budget, script_flags, precomputed
    )
    # empty after a verified script path, vc0 enforcing its own
    # end-of-script rules -- but as it came after an OP_SUCCESS
    # short-circuit, and CLEANSTACK is owed that stack
    return stack


def _verify_witness_v0(
    script_type: str,
    payload: bytes,
    witness: Witness,
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    script_flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
) -> list[bytes]:
    """Verify a v0 spend: the v0 arm of Core's VerifyWitnessProgram.

    The script is rebuilt from the program -- p2wpkh names it, p2wsh
    carries it as the last witness element -- and runs against the rest
    of the witness stack, which is what comes back: v0 is the one
    version whose CLEANSTACK check is consensus.
    """
    # a list of its own: the interpreter pops what it consumes, and the
    # witness stack is an immutable tuple anyway
    stack = list(witness.stack)
    if script_type == "p2wpkh":
        # serialization of p2wpkh:
        # OP_DUP OP_HASH160 payload OP_EQUALVERIFY OP_CHECKSIG
        script = b"v\xa9\x14" + payload + b"\x88\xac"
    elif script_type == "p2wsh":
        # the witness script is the last element, and there is none:
        # Core's WITNESS_PROGRAM_WITNESS_EMPTY, and the guard the taproot
        # arm already has. Without it the empty stack is an IndexError
        # out of `stack[-1]`, i.e. malformed input leaving through
        # something other than BTClibValueError
        if not stack:
            raise BTClibValueError("empty p2wsh witness stack")
        if any(len(x) > 520 for x in stack[:-1]):
            raise BTClibValueError("witness stack element longer than 520 bytes")
        script = stack[-1]
        if payload != sha256(script):
            raise BTClibValueError("invalid witness script sha256")
        stack = stack[:-1]
    else:
        raise BTClibValueError(f"invalid segwit v0 script type: {script_type}")

    if "OP_CODESEPARATOR" in parse(script):
        # what this engine does not verify: a v0 script carrying
        # OP_CODESEPARATOR passes as it is, and the empty stack keeps
        # CLEANSTACK out of a verdict that was never computed
        return []

    verify_script_legacy(
        script, stack, prevouts[i].value, tx, i, script_flags, True, True, precomputed
    )
    return stack


def _verify_witness_program(
    script: bytes,
    script_type: str,
    payload: bytes,
    segwit_version: int,
    p2sh: bool,
    stack: list[bytes],
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    script_flags: ScriptFlag,
    precomputed: PrecomputedTxData | None,
) -> list[bytes]:
    """Dispatch a witness program: Core's VerifyWitnessProgram.

    BIP141 and BIP341 each brought an arm, and the return value is the
    stack the CLEANSTACK check is to see -- empty wherever validation
    ends here, since to `if stack` an empty stack and a skipped check
    are the same answer.
    """
    supported_segwit_version = -1
    if ScriptFlag.WITNESS in script_flags:
        supported_segwit_version = 0
    if ScriptFlag.TAPROOT in script_flags:
        supported_segwit_version = 1
    if segwit_version > supported_segwit_version:
        if ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in script_flags:
            raise BTClibValueError(f"unsupported segwit version: {segwit_version}")
        # a version this engine does not know passes validation outright
        return []

    if segwit_version == 1 and script_type == "p2tr":
        if p2sh:
            return []  # remains unencumbered
        return _verify_taproot(
            script, tx.vin[i].script_witness, prevouts, tx, i, script_flags, precomputed
        )
    if segwit_version == 0:
        return _verify_witness_v0(
            script_type,
            payload,
            tx.vin[i].script_witness,
            prevouts,
            tx,
            i,
            script_flags,
            precomputed,
        )
    # a v1 program that is not 32 bytes, within the supported versions:
    # nothing more executes, and what the legacy run left is what
    # CLEANSTACK is owed
    return stack


def verify_input(
    prevouts: list[TxOut],
    tx: Tx,
    i: int,
    flags: ScriptFlags | None = None,
    precomputed: PrecomputedTxData | None = None,
) -> None:
    """Verify one input of a transaction against the output it spends.

    `flags` are the rules to enforce, as a ScriptFlag or as the names of
    one: `None` is btclib's default set, ALL_FLAGS, and an unknown name is
    refused rather than ignored (issue #145). A default that says "the
    consensus rules" is what an outside caller wants, and it matches
    verify_transaction's.

    `precomputed` is the transaction-wide part of the segwit sig_hashes,
    which `verify_transaction` builds once for its whole loop; verifying a
    single input has nothing to share it with, so it defaults to None and
    each sig_hash computes what it needs (issue #164).

    The split is Core's: this function is VerifyScript -- the two legacy
    runs on one stack, the p2sh unwrap, the malleation checks, the
    CLEANSTACK check -- and the witness arms live behind
    ``_verify_witness_program``, as they live behind Core's
    VerifyWitnessProgram.
    """
    script_flags = to_script_flags(flags)
    script_sig = tx.vin[i].script_sig
    parsed_script_sig = parse(script_sig, accept_unknown=True)
    _check_script_sig_policy(parsed_script_sig, script_flags)

    stack: list[bytes] = []
    verify_script_legacy(
        script_sig, stack, prevouts[i].value, tx, i, script_flags, False, False
    )
    p2sh_script = stack[-1] if stack else b"\x00"

    script = prevouts[i].script_pub_key.script
    verify_script_legacy(
        script, stack, prevouts[i].value, tx, i, script_flags, False, True
    )

    script_type, payload = type_and_payload(script)

    p2sh = False
    if script_type == "p2sh" and ScriptFlag.P2SH in script_flags:
        p2sh = True
        validate_redeem_script(parsed_script_sig)  # similar to SIGPUSHONLY
        script = p2sh_script
        verify_script_legacy(
            script, stack, prevouts[i].value, tx, i, script_flags, False, True
        )
        script_type, payload = type_and_payload(script)

    # NO_FLAGS: this reads the version out of a witness program, it does
    # not execute a script, and MINIMALDATA is the only flag _to_num looks
    # at
    segwit_version = _to_num(stack[-1], NO_FLAGS) if is_segwit(script) else -1
    if segwit_version + 1 and tx.vin[i].script_sig and not p2sh:
        raise BTClibValueError("non-empty script_sig for a native segwit input")
    if not (segwit_version + 1) and tx.vin[i].script_witness:
        raise BTClibValueError("witness for a non-segwit input")

    if segwit_version + 1:
        stack = _verify_witness_program(
            script,
            script_type,
            payload,
            segwit_version,
            p2sh,
            stack,
            prevouts,
            tx,
            i,
            script_flags,
            precomputed,
        )

    if stack and (ScriptFlag.CLEANSTACK in script_flags or segwit_version == 0):
        raise BTClibValueError(f"{len(stack)} elements left on the stack")


def verify_amounts(prevouts: list[TxOut], tx: Tx) -> None:
    if sum(x.value for x in tx.vout) > sum(x.value for x in prevouts):
        raise BTClibValueError("Invalid transaction amounts")


def verify_transaction(
    prevouts: list[TxOut],
    tx: Tx,
    flags: ScriptFlags | None = None,
    check_amounts: bool = True,
) -> None:
    """Verify every input of a transaction against the outputs it spends.

    `flags` is what verify_input takes, converted once here rather than
    once per input.
    """
    script_flags = to_script_flags(flags)
    if len(prevouts) != len(tx.vin):
        raise BTClibValueError(
            f"{len(prevouts)} prevouts for {len(tx.vin)} transaction inputs"
        )
    if check_amounts:
        verify_amounts(prevouts, tx)
    # once for the whole loop, this function owning it and holding the
    # transaction still for its duration: it is what every input's segwit
    # sig_hash commits to, and rebuilding it per input makes verifying a
    # transaction Θ(N²) in the number of inputs (issue #164). Built
    # unconditionally, being O(N) against the Θ(N²) it removes: a predicate
    # for "has a segwit input" would have to repeat verify_input's own
    # dispatch, p2sh-wrapped cases and all, and would silently restore the
    # quadratic the day the two disagreed
    precomputed = PrecomputedTxData(tx, prevouts)
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i, script_flags, precomputed)
