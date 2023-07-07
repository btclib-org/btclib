#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Bitcoin Script engine."""

from __future__ import annotations

from typing import cast

from btclib.alias import Command, ScriptList
from btclib.exceptions import BTClibValueError
from btclib.hashes import sha256
from btclib.script.engine import tapscript
from btclib.script.engine.script import verify_script as verify_script_legacy
from btclib.script.engine.script_op_codes import _to_num
from btclib.script.script import parse, serialize
from btclib.script.script_pub_key import is_segwit, type_and_payload
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut


def taproot_unwrap_script(
    script: bytes, stack: list[bytes]
) -> tuple[bytes, list[bytes], int]:
    pub_key = type_and_payload(script)[1]
    script_bytes = stack[-2]
    control = stack[-1]

    if not check_output_pubkey(pub_key, script_bytes, control):
        raise BTClibValueError()

    leaf_version = stack[-1][0] & 0xFE

    return script_bytes, stack[:-2], leaf_version


def taproot_get_annex(witness: Witness) -> bytes:
    annex = b""
    if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
        annex = witness.stack[-1]
        witness.stack = witness.stack[:-1]
    return annex


def validate_redeem_script(redeem_script: ScriptList) -> None:
    for c in redeem_script:
        if isinstance(c, str):
            if c == "OP_1NEGATE":
                continue
            if c[:2] == "OP" and not c[3:].isdigit():
                raise BTClibValueError()


ALL_FLAGS = [
    "P2SH",
    # Bip 62, never finalized
    # "SIGPUSHONLY",
    # "LOW_S",
    # "STRICTENC",
    # "CONST_SCRIPTCODE",
    # "CLEANSTACK",
    # "MINIMALDATA",
    "DERSIG",
    # only standard, not consensus
    # "NULLFAIL",
    # "MINMALIF",
    # "DISCOURAGE_UPGRADABLE_NOPS",
    # "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "NULLDUMMY",
    # only standard, not strictly consensus
    # "WITNESS_PUBKEYTYPE",
    "TAPROOT",
]


def verify_input(prevouts: list[TxOut], tx: Tx, i: int, flags: list[str]) -> None:
    script_sig = tx.vin[i].script_sig
    parsed_script_sig = parse(script_sig, accept_unknown=True)
    if "SIGPUSHONLY" in flags:
        validate_redeem_script(parsed_script_sig)
    if "CONST_SCRIPTCODE" in flags:
        for x in parsed_script_sig:
            op_checks = [
                "OP_CHECKSIG",
                "OP_CHECKSIGVERIFY",
                "OP_CHECKMULTISIG",
                "OP_CHECKSIGVERIFY",
            ]
            if x in op_checks:
                raise BTClibValueError()
    stack: list[bytes] = []
    verify_script_legacy(
        script_sig, stack, prevouts[i].value, tx, i, flags, False, False
    )
    p2sh_script = stack[-1] if stack else b"\x00"

    script = prevouts[i].script_pub_key.script
    verify_script_legacy(script, stack, prevouts[i].value, tx, i, flags, False, True)

    script_type, payload = type_and_payload(script)

    p2sh = False
    if script_type == "p2sh" and "P2SH" in flags:
        p2sh = True
        validate_redeem_script(parsed_script_sig)  # similar to SIGPUSHONLY
        script = p2sh_script
        verify_script_legacy(
            script, stack, prevouts[i].value, tx, i, flags, False, True
        )
        script_type, payload = type_and_payload(script)

    segwit_version = _to_num(stack[-1], []) if is_segwit(script) else -1
    supported_segwit_version = -1
    if "WITNESS" in flags:
        supported_segwit_version = 0
    if "TAPROOT" in flags:
        supported_segwit_version = 1
    if segwit_version + 1 and tx.vin[i].script_sig and not p2sh:
        raise BTClibValueError()
    if not (segwit_version + 1) and tx.vin[i].script_witness:
        raise BTClibValueError()  # witness without witness script
    if segwit_version > supported_segwit_version:
        if segwit_version + 1 and "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" in flags:
            raise BTClibValueError()
        return

    if segwit_version == 1:
        if script_type == "p2tr":
            if p2sh:
                return  # remains unencumbered
            witness = tx.vin[i].script_witness
            budget = 50 + len(witness.serialize())
            annex = taproot_get_annex(witness)
            stack = witness.stack
            if len(stack) == 0:
                raise BTClibValueError()
            if len(stack) == 1:
                tapscript.verify_key_path(script, stack, prevouts, tx, i, annex)
                stack = []
            else:
                script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
                if leaf_version == 0xC0:
                    tapscript.verify_script_path_vc0(
                        script_bytes, stack, prevouts, tx, i, annex, budget, flags
                    )
                else:
                    return  # unknown program, passes validation

    if segwit_version == 0:
        if script_type == "p2wpkh":
            stack = tx.vin[i].script_witness.stack
            # serialization of ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
            script = b"v\xa9\x14" + payload + b"\x88\xac"
        elif script_type == "p2wsh":
            stack = tx.vin[i].script_witness.stack
            if any(len(x) > 520 for x in stack[:-1]):
                raise BTClibValueError()
            script = stack[-1]
            if payload != sha256(script):
                raise BTClibValueError()
            stack = stack[:-1]
        else:
            raise BTClibValueError()

        if "OP_CODESEPARATOR" in parse(script):
            return

        verify_script_legacy(script, stack, prevouts[i].value, tx, i, flags, True, True)

    if stack and ("CLEANSTACK" in flags or segwit_version == 0):
        raise BTClibValueError()


def verify_transaction(
    prevouts: list[TxOut], tx: Tx, flags: list | None = None
) -> None:
    if flags is None:
        flags = ALL_FLAGS[:]
    if len(prevouts) != len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i, flags)
