#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Signatures of transaction hashes (sighash) and sighash types.

https://medium.com/@bitaps.com/exploring-bitcoin-signature-hash-types-15427766f0a9
https://raghavsood.com/blog/2018/06/10/bitcoin-signature-types-sighash
https://wiki.bitcoinsv.io/index.php/SIGHASH_flags
"""

from copy import deepcopy
from typing import List, Union

from . import script, tx, tx_out, varbytes
from .alias import Octets, ScriptToken
from .exceptions import BTClibTypeError, BTClibValueError
from .scriptpubkey import payload_from_script_pubkey
from .utils import bytes_from_octets, hash256

_FIRST_FIVE_BITS = 0b11111

ALL = 1
NONE = 2
SINGLE = 3
ANYONECANPAY = 0b10000000

SIGHASH_TYPES = [
    ALL,
    NONE,
    SINGLE,
    ANYONECANPAY & ALL,
    ANYONECANPAY & NONE,
    ANYONECANPAY & SINGLE,
]


def assert_valid_sighash_type(sighash_type: int) -> None:
    if sighash_type not in SIGHASH_TYPES:
        raise BTClibValueError(f"invalid sighash type: {hex(sighash_type)}")


# workaround to handle CTransactions
def _get_bytes(a: Union[int, Octets]) -> bytes:
    if isinstance(a, int):
        return int.to_bytes(a, 32, "big")
    return bytes_from_octets(a, 32)


def legacy(
    script_code: bytes, transaction: tx.Tx, input_index: int, sighash_type: int
) -> bytes:
    new_tx = deepcopy(transaction)
    for txin in new_tx.vin:
        txin.script_sig = b""
    # TODO: delete sig from script_code (even if non standard)
    new_tx.vin[input_index].script_sig = script_code
    if sighash_type & _FIRST_FIVE_BITS == NONE:
        new_tx.vout = []
        for i, txin in enumerate(new_tx.vin):
            if i != input_index:
                txin.sequence = 0

    if sighash_type & _FIRST_FIVE_BITS == SINGLE:
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

    if sighash_type & 0x80:
        new_tx.vin = [new_tx.vin[input_index]]

    preimage = new_tx.serialize(include_witness=True, assert_valid=False)
    preimage += sighash_type.to_bytes(4, "little")

    return hash256(preimage)


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def segwit_v0(
    script_code: bytes,
    transaction: tx.Tx,
    input_index: int,
    sighash_type: int,
    amount: int,
) -> bytes:

    hashtype_hex: str = sighash_type.to_bytes(4, "little").hex()
    if hashtype_hex[0] != "8":
        hash_prev_outs = b""
        for vin in transaction.vin:
            hash_prev_outs += _get_bytes(vin.prev_out.txid)[::-1]
            hash_prev_outs += vin.prev_out.vout.to_bytes(4, "little")
        hash_prev_outs = hash256(hash_prev_outs)
    else:
        hash_prev_outs = b"\x00" * 32

    if hashtype_hex[1] == "1" and hashtype_hex[0] != "8":
        hash_seq = b""
        for vin in transaction.vin:
            hash_seq += vin.sequence.to_bytes(4, "little")
        hash_seq = hash256(hash_seq)
    else:
        hash_seq = b"\x00" * 32

    if hashtype_hex[1] not in ("2", "3"):
        hash_outputs = b""
        for vout in transaction.vout:
            hash_outputs += vout.serialize()
        hash_outputs = hash256(hash_outputs)
    elif hashtype_hex[1] == "3" and input_index < len(transaction.vout):
        hash_outputs = hash256(transaction.vout[input_index].serialize())
    else:
        hash_outputs = b"\x00" * 32

    outpoint = _get_bytes(transaction.vin[input_index].prev_out.txid)[::-1]
    outpoint += transaction.vin[input_index].prev_out.vout.to_bytes(4, "little")

    preimage = transaction.version.to_bytes(4, "little")
    preimage += hash_prev_outs
    preimage += hash_seq
    preimage += outpoint
    preimage += varbytes.serialize(script_code)
    preimage += amount.to_bytes(8, "little")  # value
    preimage += transaction.vin[input_index].sequence.to_bytes(4, "little")
    preimage += hash_outputs
    preimage += transaction.lock_time.to_bytes(4, "little")
    preimage += bytes.fromhex(hashtype_hex)

    return hash256(preimage)


def _get_legacy_script_codes(script_pubkey: Octets) -> List[bytes]:
    script_codes: List[bytes] = []
    current_script: List[ScriptToken] = []
    for token in script.deserialize(script_pubkey)[::-1]:
        if token == "OP_CODESEPARATOR":  # nosec required for python < 3.8
            script_codes.append(script.serialize(current_script[::-1]))
        else:
            current_script.append(token)
    script_codes.append(script.serialize(current_script[::-1]))
    return script_codes[::-1]


# FIXME: remove OP_CODESEPARATOR only if executed
def _get_witness_v0_script_codes(script_pubkey: Octets) -> List[bytes]:
    try:
        script_type = payload_from_script_pubkey(script_pubkey)[0]
    except BTClibValueError:
        script_type = "unknown"
    if script_type == "p2wpkh":  # simple p2wpkh
        pubkeyhash = script.deserialize(script_pubkey)[1]
        if not isinstance(pubkeyhash, str):
            raise BTClibTypeError("not a string")
        return [bytes.fromhex(f"76a914{pubkeyhash}88ac")]
    script_codes: List[bytes] = []
    current_script: List[ScriptToken] = []
    for token in script.deserialize(script_pubkey)[::-1]:
        if token == "OP_CODESEPARATOR":  # nosec required for python < 3.8
            script_codes.append(script.serialize(current_script[::-1]))
        current_script.append(token)
    script_codes.append(script.serialize(current_script[::-1]))
    return script_codes[::-1]


def sighash_from_prev_out(
    previous_output: tx_out.TxOut,
    transaction: tx.Tx,
    input_index: int,
    sighash_type: int,
) -> bytes:

    script_pubkey = previous_output.script_pubkey
    try:
        script_type = payload_from_script_pubkey(script_pubkey)[0]
        if script_type == "p2sh":
            script_pubkey = transaction.vin[input_index].script_sig
            script_type = payload_from_script_pubkey(script_pubkey)[0]
    except BTClibValueError:
        script_type = "unknown"

    list_script = script.deserialize(script_pubkey)
    if len(list_script) == 2 and list_script[0] == 0:  # is segwit
        if script_type == "p2wpkh":
            script_code = _get_witness_v0_script_codes(script_pubkey)[0]
        elif script_type == "p2wsh":
            # the real script is contained in the witness
            script_code = _get_witness_v0_script_codes(
                transaction.vin[input_index].witness.stack[-1]
            )[0]

        value = previous_output.value
        return segwit_v0(script_code, transaction, input_index, sighash_type, value)

    script_code = _get_legacy_script_codes(script_pubkey)[0]
    return legacy(script_code, transaction, input_index, sighash_type)
