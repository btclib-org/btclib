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

from btclib.alias import Command
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.script import parse
from btclib.script.engine import tapscript
from btclib.script.engine.script import _from_num
from btclib.script.engine.script import verify_script as verify_script_legacy
from btclib.script.script_pub_key import (
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.script.taproot import check_output_pubkey
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut


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


def compute_stack(script: List[Command]) -> List[bytes]:
    stack = []
    for c in script:
        if isinstance(c, int):
            stack.append(_from_num(c))
        elif isinstance(c, str):
            if c == "OP_1NEGATE":
                stack.append(_from_num(-1))
            elif c[:2] == "OP":
                if not c[3:].isdigit():
                    raise BTClibValueError()
                stack.append(_from_num(int(c[3:])))
            else:
                stack.append(bytes.fromhex(c))
    return stack


ALL_FLAGS = ["P2SH", "NULLDUMMY", "CLEANSTACK", "WITNESS", "TAPROOT", "SIGPUSHONLY"]


def verify_input(
    prevouts: List[TxOut], tx: Tx, i: int, flags: List[str] = ALL_FLAGS
) -> None:

    script = prevouts[i].script_pub_key.script
    type, payload = type_and_payload(script)

    if type == "p2tr" and "TAPROOT" in flags:
        witness = tx.vin[i].script_witness
        annex = taproot_get_annex(witness)
        stack = witness.stack
        if len(stack) == 0:
            raise BTClibValueError()
        if len(stack) == 1:
            return tapscript.verify_key_path(script, stack, prevouts, tx, i, annex)
        script_bytes, stack, leaf_version = taproot_unwrap_script(script, stack)
        if leaf_version == 0xC0:
            return tapscript.verify_script_path_vc0(
                script_bytes, stack, prevouts, tx, i, annex
            )
        return  # unknown leaf version type

    stack = compute_stack(parse(tx.vin[i].script_sig))

    if type == "p2sh" and "P2SH" in flags:
        parsed_script = parse(tx.vin[i].script_sig)
        if isinstance(parsed_script[-1], int):
            script = _from_num(parsed_script[-1])
        else:
            script = bytes.fromhex(parsed_script[-1])
        if payload != hash160(script):
            raise BTClibValueError()
        stack = compute_stack(parsed_script[:-1])
        type, payload = type_and_payload(script)

    if type == "p2tr":
        return  # remain unencumbered

    if type == "p2wpkh":
        return

    if type == "p2wsh":
        return

    verify_script_legacy(script, stack, prevouts, tx, i, flags)


def verify_transaction(prevouts: List[TxOut], tx: Tx, flags: List = ALL_FLAGS) -> None:
    if not len(prevouts) == len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i, flags)
