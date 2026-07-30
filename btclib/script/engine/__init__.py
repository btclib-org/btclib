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
# The functions defined below are named too, __all__ being the public
# surface of the module once it exists and not a second list beside it
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
    # either branch, the stack being popped by the script interpreter
    if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
        return witness.stack[-1], list(witness.stack[:-1])
    return b"", list(witness.stack)


def validate_redeem_script(redeem_script: ScriptList) -> None:
    for c in redeem_script:
        if isinstance(c, str):
            if c == "OP_1NEGATE":
                continue
            if c[:2] == "OP" and not c[3:].isdigit():
                raise BTClibValueError(f"non-push command in the script_sig: {c}")


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
    refused rather than ignored (issue #145). It used to be a required
    argument, and every caller inside btclib passed something; a default
    that says "the consensus rules" is what an outside caller wants, and
    it is the default verify_transaction already had.

    `precomputed` is the transaction-wide part of the segwit sig_hashes,
    which `verify_transaction` builds once for its whole loop; verifying a
    single input has nothing to share it with, so it defaults to None and
    each sig_hash computes what it needs (issue #164).
    """
    script_flags = to_script_flags(flags)
    script_sig = tx.vin[i].script_sig
    parsed_script_sig = parse(script_sig, accept_unknown=True)
    if ScriptFlag.SIGPUSHONLY in script_flags:
        validate_redeem_script(parsed_script_sig)
    if ScriptFlag.CONST_SCRIPTCODE in script_flags:
        for x in parsed_script_sig:
            op_checks = [
                "OP_CHECKSIG",
                "OP_CHECKSIGVERIFY",
                "OP_CHECKMULTISIG",
                "OP_CHECKSIGVERIFY",
            ]
            if x in op_checks:
                raise BTClibValueError(f"signature check in the script_sig: {x}")
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
    # at. It was an empty list here for the same reason
    segwit_version = _to_num(stack[-1], NO_FLAGS) if is_segwit(script) else -1
    supported_segwit_version = -1
    if ScriptFlag.WITNESS in script_flags:
        supported_segwit_version = 0
    if ScriptFlag.TAPROOT in script_flags:
        supported_segwit_version = 1
    if segwit_version + 1 and tx.vin[i].script_sig and not p2sh:
        raise BTClibValueError("non-empty script_sig for a native segwit input")
    if not (segwit_version + 1) and tx.vin[i].script_witness:
        raise BTClibValueError("witness for a non-segwit input")
    if segwit_version > supported_segwit_version:
        if (
            segwit_version + 1
            and ScriptFlag.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM in script_flags
        ):
            raise BTClibValueError(f"unsupported segwit version: {segwit_version}")
        return

    if segwit_version == 1 and script_type == "p2tr":
        if p2sh:
            return  # remains unencumbered
        witness = tx.vin[i].script_witness
        budget = 50 + len(witness.serialize())
        # the annex counts towards the budget, hence the order (bip 342)
        annex, stack = taproot_get_annex(witness)
        if len(stack) == 0:
            raise BTClibValueError("empty taproot witness stack")
        if len(stack) == 1:
            tapscript.verify_key_path(
                script, stack, prevouts, tx, i, annex, precomputed
            )
            stack = []
        else:
            script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
            if leaf_version == 0xC0:
                tapscript.verify_script_path_vc0(
                    script_bytes,
                    stack,
                    prevouts,
                    tx,
                    i,
                    annex,
                    budget,
                    script_flags,
                    precomputed,
                )
            else:
                return  # unknown program, passes validation

    if segwit_version == 0:
        # a list of its own: the interpreter pops what it consumes, and the
        # witness stack is an immutable tuple anyway
        if script_type == "p2wpkh":
            stack = list(tx.vin[i].script_witness.stack)
            # serialization of ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
            script = b"v\xa9\x14" + payload + b"\x88\xac"
        elif script_type == "p2wsh":
            stack = list(tx.vin[i].script_witness.stack)
            if any(len(x) > 520 for x in stack[:-1]):
                raise BTClibValueError("witness stack element longer than 520 bytes")
            script = stack[-1]
            if payload != sha256(script):
                raise BTClibValueError("invalid witness script sha256")
            stack = stack[:-1]
        else:
            raise BTClibValueError(f"invalid segwit v0 script type: {script_type}")

        if "OP_CODESEPARATOR" in parse(script):
            return

        verify_script_legacy(
            script,
            stack,
            prevouts[i].value,
            tx,
            i,
            script_flags,
            True,
            True,
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
    once per input; it was defaulted with a copy of a mutable ALL_FLAGS,
    which a ScriptFlag makes unnecessary.
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
    # sig_hash commits to, and rebuilding it per input made verifying a
    # transaction Θ(N²) in the number of inputs (issue #164). Built
    # unconditionally, being O(N) against the Θ(N²) it removes: a predicate
    # for "has a segwit input" would have to repeat verify_input's own
    # dispatch, p2sh-wrapped cases and all, and would silently restore the
    # quadratic the day the two disagreed
    precomputed = PrecomputedTxData(tx, prevouts)
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i, script_flags, precomputed)
