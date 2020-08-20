#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, Union

from . import script, tx, tx_out, varint
from .alias import Octets, Script, Token
from .scriptpubkey import payload_from_scriptPubKey
from .utils import bytes_from_octets, hash256


# workaround to handle CTransactions
def _get_bytes(a: Union[int, str]) -> bytes:
    return int.to_bytes(a, 32, "big") if isinstance(a, int) else bytes.fromhex(a)


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def segwit_v0_sighash(
    scriptCode: Octets, transaction: tx.Tx, input_index: int, hashtype: int, amount: int
) -> bytes:

    hashtype_hex: str = hashtype.to_bytes(4, "little").hex()
    if hashtype_hex[0] != "8":
        hashPrevouts = b""
        for vin in transaction.vin:
            hashPrevouts += _get_bytes(vin.prevout.hash)[::-1]
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

    if hashtype_hex[1] != "2" and hashtype_hex[1] != "3":
        hashOutputs = b""
        for vout in transaction.vout:
            hashOutputs += vout.serialize()
        hashOutputs = hash256(hashOutputs)
    elif hashtype_hex[1] == "3" and input_index < len(transaction.vout):
        hashOutputs = hash256(transaction.vout[input_index].serialize())
    else:
        hashOutputs = b"\x00" * 32

    scriptCode = bytes_from_octets(scriptCode)

    outpoint = _get_bytes(transaction.vin[input_index].prevout.hash)[::-1]
    outpoint += transaction.vin[input_index].prevout.n.to_bytes(4, "little")

    preimage = transaction.nVersion.to_bytes(4, "little")
    preimage += hashPrevouts
    preimage += hashSequence
    preimage += outpoint
    preimage += varint.encode(len(scriptCode)) + scriptCode
    preimage += amount.to_bytes(8, "little")  # value
    preimage += transaction.vin[input_index].nSequence.to_bytes(4, "little")
    preimage += hashOutputs
    preimage += transaction.nLockTime.to_bytes(4, "little")
    preimage += bytes.fromhex(hashtype_hex)

    return hash256(preimage)


# FIXME: remove OP_CODESEPARATOR only if executed
def _get_witness_v0_scriptCodes(scriptPubKey: Script) -> List[str]:
    scriptCodes: List[str] = []
    try:
        script_type = payload_from_scriptPubKey(scriptPubKey)[0]
    except ValueError:
        script_type = "unknown"
    if script_type == "p2wpkh":  # simple p2wpkh
        pubkeyhash = scriptPubKey[1]
        assert isinstance(pubkeyhash, str)
        scriptCodes.append(f"76a914{pubkeyhash}88ac")
    else:
        current_script: List[Token] = []
        for token in scriptPubKey[::-1]:
            if token == "OP_CODESEPARATOR":
                scriptCodes.append(script.encode(current_script[::-1]).hex())
            current_script.append(token)
        scriptCodes.append(script.encode(current_script[::-1]).hex())
        scriptCodes = scriptCodes[::-1]
    return scriptCodes


def get_sighash(
    transaction: tx.Tx,
    previous_output: tx_out.TxOut,
    input_index: int,
    sighash_type: int,
) -> bytes:

    value = previous_output.nValue

    scriptPubKey = previous_output.scriptPubKey
    script_type = payload_from_scriptPubKey(scriptPubKey)[0]
    if script_type == "p2sh":
        scriptPubKey = transaction.vin[input_index].scriptSig

    if len(scriptPubKey) == 2 and scriptPubKey[0] == 0:  # is segwit
        script_type = payload_from_scriptPubKey(scriptPubKey)[0]
        if script_type == "p2wpkh":
            scriptCode = _get_witness_v0_scriptCodes(scriptPubKey)[0]
        elif script_type == "p2wsh":
            # the real script is contained in the witness
            scriptCode = _get_witness_v0_scriptCodes(
                script.decode(transaction.vin[input_index].txinwitness[-1])
            )[0]
        return segwit_v0_sighash(
            bytes.fromhex(scriptCode), transaction, input_index, sighash_type, value
        )
    raise RuntimeError("legacy transactions not supported yet")


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
