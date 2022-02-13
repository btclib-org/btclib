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

from typing import List, Optional, Tuple

from btclib.alias import Command
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.script.engine import tapscript
from btclib.script.engine.script import verify_script as verify_script_legacy
from btclib.script.engine.script_op_codes import op_verify
from btclib.script.script import parse
from btclib.script.script_pub_key import is_segwit, type_and_payload
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_command


def taproot_unwrap_script(
    script: bytes, stack: List[bytes]
) -> Tuple[bytes, List[bytes], int]:

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


def validate_redeem_script(redeem_script: List[Command]) -> None:
    print(redeem_script)
    for c in redeem_script:
        if isinstance(c, str):
            if c == "OP_1NEGATE":
                continue
            if c[:2] == "OP" and not c[3:].isdigit():
                raise BTClibValueError()


ALL_FLAGS = [
    "SIGPUSHONLY",
    "LOW_S",
    "STRICTENC",
    "DERSIG",
    "CONST_SCRIPTCODE",
    "NULLDUMMY",
    "CLEANSTACK",
    "MINIMALDATA",
    "P2SH",
    "CHECKLOCKTIMEVERIFY",
    "CHECKSEQUENCEVERIFY",
    "WITNESS",
    "TAPROOT",
]


def verify_input(prevouts: List[TxOut], tx: Tx, i: int, flags: List[str]) -> None:

    script = prevouts[i].script_pub_key.script
    script_type, payload = type_and_payload(script)

    redeem_script = parse(tx.vin[i].script_sig, accept_unknown=True)

    p2sh = False
    if script_type == "p2sh" and "P2SH" in flags:
        p2sh = True
        parsed_script = parse(tx.vin[i].script_sig, accept_unknown=True)
        script = bytes_from_command(parsed_script[-1])
        if payload != hash160(script):
            raise BTClibValueError()
        redeem_script = parsed_script[:-1]
        script_type, payload = type_and_payload(script)

    segwit_version = -1
    if is_segwit(script):
        if script[0] == 0:
            segwit_version = 0
        else:
            segwit_version = script[0] - 80
    supported_segwit_version = -1
    if "WITNESS" in flags:
        supported_segwit_version = 0
    if "TAPROOT" in flags:
        supported_segwit_version = 1
    if segwit_version + 1 and tx.vin[i].script_sig and not p2sh:
        raise BTClibValueError()
    if supported_segwit_version + 1 and segwit_version > supported_segwit_version:
        op_verify([script[1:]], [], flags)
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
            else:
                script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
                if leaf_version == 0xC0:
                    tapscript.verify_script_path_vc0(
                        script_bytes, stack, prevouts, tx, i, annex, budget, flags
                    )
            return  # unknown program, passes validation

    segwit = False
    if segwit_version == 0:
        segwit = True
        if script_type == "p2wpkh":
            redeem_script = tx.vin[i].script_witness.stack
            # serialization of ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
            script = b"v\xa9\x14" + payload + b"\x88\xac"
        elif script_type == "p2wsh":
            parsed_script = tx.vin[i].script_witness.stack
            if any(len(x) > 520 for x in parsed_script):
                raise BTClibValueError()
            script = bytes_from_command(parsed_script[-1])
            if payload != sha256(script):
                raise BTClibValueError()
            redeem_script = parsed_script[:-1]
        else:
            raise BTClibValueError()

    if "SIGPUSHONLY" in flags:
        validate_redeem_script(redeem_script)

    if len(script) > 10000:
        raise BTClibValueError()

    verify_script_legacy(script, redeem_script, prevouts[i].value, tx, i, flags, segwit)


def verify_transaction(
    prevouts: List[TxOut], tx: Tx, flags: Optional[List] = None
) -> None:
    if flags is None:
        flags = ALL_FLAGS
    if not len(prevouts) == len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i, flags)
