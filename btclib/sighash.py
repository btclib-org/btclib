#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from copy import deepcopy
from typing import List, Union

from . import script, tx, tx_out, varbytes
from .alias import ScriptToken
from .exceptions import BTClibValueError
from .scriptpubkey import payload_from_script_pubkey
from .utils import hash256


# workaround to handle CTransactions
def _get_bytes(a: Union[int, bytes]) -> bytes:
    return int.to_bytes(a, 32, "big") if isinstance(a, int) else a


def legacy(
    scriptCode: bytes, transaction: tx.Tx, input_index: int, hashtype: int
) -> bytes:
    new_tx = deepcopy(transaction)
    for txin in new_tx.vin:
        txin.script_sig = b""
    # TODO: delete sig from scriptCode (even if non standard)
    new_tx.vin[input_index].script_sig = scriptCode
    if hashtype & 31 == 0x02:
        new_tx.vout = []
        for i, txin in enumerate(new_tx.vin):
            if i != input_index:
                txin.sequence = 0

    if hashtype & 31 == 0x03:
        # sighash single bug
        if input_index >= len(new_tx.vout):
            return (256 ** 31).to_bytes(32, "big")
        new_tx.vout = new_tx.vout[: input_index + 1]
        for txout in new_tx.vout[:-1]:
            txout.script_pubkey = b""
            txout.value = 256 ** 8 - 1
        for i, txin in enumerate(new_tx.vin):
            if i != input_index:
                txin.sequence = 0

    if hashtype & 0x80:
        new_tx.vin = [new_tx.vin[input_index]]

    preimage = new_tx.serialize(assert_valid=False)
    preimage += hashtype.to_bytes(4, "little")

    return hash256(preimage)


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def segwit_v0(
    scriptCode: bytes, transaction: tx.Tx, input_index: int, hashtype: int, amount: int
) -> bytes:

    hashtype_hex: str = hashtype.to_bytes(4, "little").hex()
    if hashtype_hex[0] != "8":
        hashPrevouts = b""
        for vin in transaction.vin:
            hashPrevouts += _get_bytes(vin.prevout.txid)[::-1]
            hashPrevouts += vin.prevout.vout.to_bytes(4, "little")
        hashPrevouts = hash256(hashPrevouts)
    else:
        hashPrevouts = b"\x00" * 32

    if hashtype_hex[1] == "1" and hashtype_hex[0] != "8":
        hashSequence = b""
        for vin in transaction.vin:
            hashSequence += vin.sequence.to_bytes(4, "little")
        hashSequence = hash256(hashSequence)
    else:
        hashSequence = b"\x00" * 32

    if hashtype_hex[1] not in ("2", "3"):
        hashOutputs = b""
        for vout in transaction.vout:
            hashOutputs += vout.serialize()
        hashOutputs = hash256(hashOutputs)
    elif hashtype_hex[1] == "3" and input_index < len(transaction.vout):
        hashOutputs = hash256(transaction.vout[input_index].serialize())
    else:
        hashOutputs = b"\x00" * 32

    outpoint = _get_bytes(transaction.vin[input_index].prevout.txid)[::-1]
    outpoint += transaction.vin[input_index].prevout.vout.to_bytes(4, "little")

    preimage = transaction.version.to_bytes(4, "little")
    preimage += hashPrevouts
    preimage += hashSequence
    preimage += outpoint
    preimage += varbytes.encode(scriptCode)
    preimage += amount.to_bytes(8, "little")  # value
    preimage += transaction.vin[input_index].sequence.to_bytes(4, "little")
    preimage += hashOutputs
    preimage += transaction.locktime.to_bytes(4, "little")
    preimage += bytes.fromhex(hashtype_hex)

    return hash256(preimage)


def _get_legacy_scriptCodes(script_pubkey: bytes) -> List[bytes]:
    scriptCodes: List[bytes] = []
    current_script: List[ScriptToken] = []
    for token in script.deserialize(script_pubkey)[::-1]:
        if token == "OP_CODESEPARATOR":
            scriptCodes.append(script.serialize(current_script[::-1]))
        else:
            current_script.append(token)
    scriptCodes.append(script.serialize(current_script[::-1]))
    return scriptCodes[::-1]


# FIXME: remove OP_CODESEPARATOR only if executed
def _get_witness_v0_scriptCodes(script_pubkey: bytes) -> List[bytes]:
    try:
        script_type = payload_from_script_pubkey(script.deserialize(script_pubkey))[0]
    except BTClibValueError:
        script_type = "unknown"
    if script_type == "p2wpkh":  # simple p2wpkh
        pubkeyhash = script.deserialize(script_pubkey)[1]
        if not isinstance(pubkeyhash, str):
            raise BTClibValueError("not a string")
        return [bytes.fromhex(f"76a914{pubkeyhash}88ac")]
    scriptCodes: List[bytes] = []
    current_script: List[ScriptToken] = []
    for token in script.deserialize(script_pubkey)[::-1]:
        if token == "OP_CODESEPARATOR":
            scriptCodes.append(script.serialize(current_script[::-1]))
        current_script.append(token)
    scriptCodes.append(script.serialize(current_script[::-1]))
    return scriptCodes[::-1]


def get_sighash(
    transaction: tx.Tx,
    previous_output: tx_out.TxOut,
    input_index: int,
    sighash_type: int,
) -> bytes:

    value = previous_output.value

    script_pubkey = previous_output.script_pubkey
    try:
        script_type = payload_from_script_pubkey(script_pubkey)[0]
        if script_type == "p2sh":
            script_pubkey = transaction.vin[input_index].script_sig
    except BTClibValueError:
        script_type = "unknown"

    list_script = script.deserialize(script_pubkey)
    if len(list_script) == 2 and list_script[0] == 0:  # is segwit
        script_type = payload_from_script_pubkey(script_pubkey)[0]
        if script_type == "p2wpkh":
            scriptCode = _get_witness_v0_scriptCodes(script_pubkey)[0]
        elif script_type == "p2wsh":
            # the real script is contained in the witness
            scriptCode = _get_witness_v0_scriptCodes(
                transaction.vin[input_index].txinwitness[-1]
            )[0]
        return segwit_v0(scriptCode, transaction, input_index, sighash_type, value)
    scriptCode = _get_legacy_scriptCodes(script_pubkey)[0]
    return legacy(scriptCode, transaction, input_index, sighash_type)
