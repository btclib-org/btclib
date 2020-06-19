#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List

from . import tx, tx_out, script, varint
from .utils import hash256, bytes_from_octets
from .alias import Script, Octets


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def SegwitV0SignatureHash(
    scriptCode: Octets, transaction: tx.Tx, input_index: int, hashtype: int, amount: int
) -> bytes:
    nVersion = transaction.nVersion.to_bytes(4, "little")

    hashtype_hex: str = hashtype.to_bytes(4, "little").hex()
    if hashtype_hex[0] != "8":
        hashPrevouts = b""
        for vin in transaction.vin:
            hashPrevouts += bytes.fromhex(vin.prevout.hash)[::-1]
            hashPrevouts += vin.prevout.n.to_bytes(4, "little")
        hashPrevouts = hash256(hashPrevouts)
    else:
        hashPrevouts = b"\x00" * 32

    if hashtype_hex[1] == "1" and hashtype_hex[0] != "8":
        hashSequence = b""
        for vin in transaction.vin:
            hashSequence += vin.nSequence.to_bytes(4, "little")
        hashSequence = hash256(hashSequence)
    else:
        hashSequence = b"\x00" * 32

    if not hashtype_hex[1] == "2" and not hashtype_hex[1] == "3":
        hashOutputs = b""
        for vout in transaction.vout:
            hashOutputs += vout.serialize()
        hashOutputs = hash256(hashOutputs)
    elif hashtype_hex[1] == "3" and input_index < len(transaction.vout):
        hashOutputs = hash256(transaction.vout[input_index].serialize())
    else:
        hashOutputs = b"\x00" * 32

    outpoint = bytes.fromhex(transaction.vin[input_index].prevout.hash)[::-1]
    outpoint += transaction.vin[input_index].prevout.n.to_bytes(4, "little")

    scriptCode = bytes_from_octets(scriptCode)
    scriptCode = varint.encode(len(scriptCode)) + scriptCode

    value_spent = (amount).to_bytes(8, "little")
    nSequence = transaction.vin[input_index].nSequence.to_bytes(4, "little")

    nLocktime = transaction.nLockTime.to_bytes(4, "little")
    hashtype_b = bytes.fromhex(hashtype_hex)

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
        + hashtype_b
    )
    sig_hash = hash256(preimage)
    return sig_hash


# FIXME: remove OP_CODESEPARATOR only if exectued
def _get_witness_scriptCodes(scriptPubKey: Script) -> List[str]:
    scriptCodes: List[str] = []
    if scriptPubKey[0] == 0 and len(scriptPubKey) == 2:  # simple p2wpkh #FIXME
        pubkeyhash = scriptPubKey[1]
        scriptCodes.append(f"76a914{pubkeyhash}88ac")
    else:
        current_script: Script = []
        for token in scriptPubKey[::-1]:
            if token == "OP_CODESEPARATOR":
                scriptCodes.append(script.encode(current_script[::-1]).hex())
            current_script.append(token)
        scriptCodes.append(script.encode(current_script[::-1]).hex())
        scriptCodes = scriptCodes[::-1]
    return scriptCodes


# def _get_sighash():
#     pass


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
                SegwitV0SignatureHash(
                    bytes.fromhex(scriptCode),
                    transaction,
                    input_index,
                    sighash_type,
                    value,
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
