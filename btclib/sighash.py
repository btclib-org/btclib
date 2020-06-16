#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List

from . import tx, tx_out, script
from .utils import hash256
from .alias import Script

# from .scriptpubkey import payload_from_scriptPubKey


def _get_witness_sighash(
    transaction: tx.Tx,
    input_index: int,
    scriptCode: str,
    value: float,
    sighash_type: int,
) -> bytes:
    nVersion = transaction.version.to_bytes(4, "little")

    sighash_type: str = sighash_type.to_bytes(4, "little").hex()
    if sighash_type[0] != "8":
        hashPrevouts = b""
        for vin in transaction.vin:
            hashPrevouts += bytes.fromhex(vin.txid)[::-1]
            hashPrevouts += vin.vout.to_bytes(4, "little")
        hashPrevouts = hash256(hashPrevouts)
    else:
        hashPrevouts = b"\x00" * 32

    if sighash_type[1] == "1" and sighash_type[0] != "8":
        hashSequence = b""
        for vin in transaction.vin:
            hashSequence += vin.sequence.to_bytes(4, "little")
        hashSequence = hash256(hashSequence)
    else:
        hashSequence = b"\x00" * 32

    if not sighash_type[1] == "2" and not sighash_type[1] == "3":
        hashOutputs = b""
        for vout in transaction.vout:
            hashOutputs += vout.serialize()
        hashOutputs = hash256(hashOutputs)
    elif sighash_type[1] == "3" and input_index < len(transaction.vout):
        hashOutputs = hash256(transaction.vout[input_index].serialize())
    else:
        hashOutputs = b"\x00" * 32

    outpoint = bytes.fromhex(transaction.vin[input_index].txid)[::-1]
    outpoint += transaction.vin[input_index].vout.to_bytes(4, "little")

    scriptCode = bytes.fromhex(scriptCode)

    value_spent = (int(value * 10 ** 8)).to_bytes(8, "little")
    nSequence = transaction.vin[input_index].sequence.to_bytes(4, "little")

    nLocktime = transaction.locktime.to_bytes(4, "little")
    sighash_type = bytes.fromhex(sighash_type)

    preimage = (
        nVersion
        + hashPrevouts
        + hashSequence
        + outpoint
        + scriptCode
        + value_spent
        + nSequence
        + hashOutputs
        + nLocktime
        + sighash_type
    )
    sig_hash = hash256(preimage)
    return sig_hash


# FIXME: remove OP_CODESEPARATOR only if exectued
def _get_witness_scriptCodes(scriptPubKey: Script):
    if scriptPubKey[0] == 0 and len(scriptPubKey) == 2:  # simple p2wpkh #FIXME
        pubkeyhash = scriptPubKey[1]
        scriptCodes = [f"1976a914{pubkeyhash}88ac"]
    else:
        scriptCodes = []
        current_script = []
        for token in scriptPubKey[::-1]:
            if token == "OP_CODESEPARATOR":
                scriptCodes.append(script.serialize(current_script[::-1]).hex())
            current_script.append(token)
        scriptCodes.append(script.serialize(current_script[::-1]).hex())
        scriptCodes = scriptCodes[::-1]
    return scriptCodes


def _get_sighash():
    pass


def get_sighash(
    transaction: tx.Tx,
    previous_output: tx_out.TxOut,
    input_index: int,
    sighash_type: int,
) -> List[bytes]:

    value = previous_output.value

    scriptPubKey = previous_output.scriptPubKey
    if len(scriptPubKey) == 3:
        if scriptPubKey[0] == "OP_HASH160" and scriptPubKey[2] == "OP_EQUAL":
            if len(scriptPubKey[1]) != 20 * 2:
                raise ValueError("Invalid script hash len")
            else:
                scriptPubKey = transaction.vin[input_index].scriptSig

    if len(scriptPubKey) == 2 and scriptPubKey[0] == 0:  # is segwit
        if len(scriptPubKey[1]) == 20 * 2:  # p2wpkh
            scriptCodes = _get_witness_scriptCodes(scriptPubKey)
        elif len(scriptPubKey[1]) == 32 * 2:  # p2wsh
            # the real script is contained in the witness
            scriptCodes = _get_witness_scriptCodes(
                script.decode(transaction.vin[input_index].txinwitness[-1])
            )
        else:
            raise ValueError("Invalid witness program")
        sighash: List[bytes] = []
        for scriptCode in scriptCodes:
            sighash.append(
                _get_witness_sighash(
                    transaction, input_index, scriptCode, value, sighash_type
                )
            )
        return sighash

    # else:
    #     scriptCode = _get_witness_scriptCode(scriptPubKey)
    #     sighash = _get_witness_sighash(transaction, input_index, scriptCode, value)


# def sign(
#     transaction: tx.Tx,
#     previous_output: tx.TxOut,
#     input_index: int,
#     prvkey: int,
#     sighash_type: int,
# ) -> str:
#     sighash = get_sighash(transaction, previous_output, input_index, sighash_type)
#     signature = dsa.serialize(*dsa._sign(sighash, prvkey))
#     signature += sighash_type.to_bytes(1, "little")
#     return signature.hex()
