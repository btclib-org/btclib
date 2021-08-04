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

from btclib.exceptions import BTClibValueError
from btclib.script.script import Command, parse
from btclib.script.script_pub_key import (
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.script.witness import Witness
from btclib.script import sig_hash
from btclib.ecc import ssa
from btclib.script.taproot import check_output_pubkey


def __unwrap_taproot_script(
    script: List[Command], stack: List[bytes]
) -> Tuple[bytes, List[bytes], int]:

    pub_key = script[1]
    script_bytes = stack[-2]
    control = stack[-1]

    if not check_output_pubkey(pub_key, script_bytes, control):
        raise BTClibValueError()

    leaf_version = stack[-1][0] & 0xFE

    return script_bytes, stack[:-2], leaf_version


def __taproot_get_hashtype(signature: bytes) -> int:
    sighash_type = 0  # all
    if len(signature) == 65:
        sighash_type = signature[-1]
        if sighash_type == 0:
            raise BTClibValueError()
    return sighash_type


def __taproot_get_annex(witness: Witness) -> bytes:
    annex = b""
    if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
        annex = witness.stack[-1]
        witness.stack = witness.stack[:-1]
    return annex


def _verify_taproot_key_path(
    script_pub_key: List[Command],
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    sighash_type = __taproot_get_hashtype(stack[0])
    signature = stack[0][:64]
    pub_key = bytes.fromhex(script_pub_key[1])
    msg_hash = sig_hash.taproot(tx, i, prevouts, sighash_type, 0, annex, b"")

    ssa.assert_as_valid_(msg_hash, pub_key, signature)


def __verify_taproot_script_path_leaf_vc0(
    script: List[Command],
    stack: List[bytes],
    prevouts: List[TxOut],
    tx: Tx,
    i: int,
    annex: bytes,
) -> None:

    if script == ["OP_SUCCESS"]:
        return
    script.reverse()
    while script:
        command = script.pop()
        if command[:6] == "OP_NOP":
            continue

    if len(stack) != 1:
        raise BTClibValueError()
    if stack[0] not in ["OP_0", 0]:
        raise BTClibValueError()


def verify_input(prevouts: List[TxOut], tx: Tx, i: int) -> None:

    script = prevouts[i].script_pub_key.script

    if is_p2tr(script):
        parsed_script = parse(prevouts[i].script_pub_key.script)
        witness = tx.vin[i].script_witness
        annex = __taproot_get_annex(witness)
        stack = witness.stack
        if len(stack) == 0:
            raise BTClibValueError()
        elif len(stack) == 1:
            _verify_taproot_key_path(parsed_script, stack, prevouts, tx, i, annex)
        else:
            script_bytes, stack, leaf_version = __unwrap_taproot_script(
                parsed_script, stack
            )
            if leaf_version == 0xC0:
                __verify_taproot_script_path_leaf_vc0(
                    parse(script_bytes, True), stack, prevouts, tx, i, annex
                )
            else:
                pass  # unknown leaf version type
        return

    pass


def verify_transaction(prevouts: List[TxOut], tx: Tx) -> None:
    if not len(prevouts) == len(tx.vin):
        raise BTClibValueError()
    for i in range(len(prevouts)):
        verify_input(prevouts, tx, i)
