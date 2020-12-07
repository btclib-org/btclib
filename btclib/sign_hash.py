#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Transaction hashes to be signed and their hash types.

https://medium.com/@bitaps.com/exploring-bitcoin-signature-hash-types-15427766f0a9
https://raghavsood.com/blog/2018/06/10/bitcoin-signature-types-sign_hash
https://wiki.bitcoinsv.io/index.php/SIG_HASH_flags
"""

from copy import deepcopy
from typing import List

from . import script, var_bytes
from .alias import Octets, ScriptToken
from .exceptions import BTClibValueError
from .script_pub_key import (
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    payload_from_script_pub_key,
    script_pub_key_from_payload,
)
from .tx import Tx
from .tx_out import TxOut
from .utils import hash256

_FIRST_FIVE_BITS = 0b11111

ALL = 1
NONE = 2
SINGLE = 3
ANYONECANPAY = 0b10000000

SIG_HASH_TYPES = [
    ALL,
    NONE,
    SINGLE,
    ANYONECANPAY & ALL,
    ANYONECANPAY & NONE,
    ANYONECANPAY & SINGLE,
]


def assert_valid_hash_type(hash_type: int) -> None:
    if hash_type not in SIG_HASH_TYPES:
        raise BTClibValueError(f"invalid sign_hash type: {hex(hash_type)}")


def _legacy_script(script_pub_key: Octets) -> List[bytes]:
    script_s: List[bytes] = []
    current_script: List[ScriptToken] = []
    for token in script.deserialize(script_pub_key)[::-1]:
        if token == "OP_CODESEPARATOR":  # nosec required for python < 3.8
            script_s.append(script.serialize(current_script[::-1]))
        else:
            current_script.append(token)
    script_s.append(script.serialize(current_script[::-1]))
    return script_s[::-1]


def legacy(script_: bytes, tx: Tx, vin_i: int, hash_type: int) -> bytes:
    new_tx = deepcopy(tx)
    for txin in new_tx.vin:
        txin.script_sig = b""
    # TODO: delete sig from script_ (even if non standard)
    new_tx.vin[vin_i].script_sig = script_
    if hash_type & _FIRST_FIVE_BITS == NONE:
        new_tx.vout = []
        for i, txin in enumerate(new_tx.vin):
            if i != vin_i:
                txin.sequence = 0

    if hash_type & _FIRST_FIVE_BITS == SINGLE:
        # sign_hash single bug
        if vin_i >= len(new_tx.vout):
            return (256 ** 31).to_bytes(32, "big")
        new_tx.vout = new_tx.vout[: vin_i + 1]
        for txout in new_tx.vout[:-1]:
            txout.script_pub_key = b""
            txout.value = 256 ** 8 - 1
        for i, txin in enumerate(new_tx.vin):
            if i != vin_i:
                txin.sequence = 0

    if hash_type & 0x80:
        new_tx.vin = [new_tx.vin[vin_i]]

    preimage = new_tx.serialize(include_witness=False, assert_valid=False)
    preimage += hash_type.to_bytes(4, "little")

    return hash256(preimage)


# FIXME: remove OP_CODESEPARATOR only if executed
def _witness_v0_script(script_pub_key: Octets) -> List[bytes]:
    script_type, payload = payload_from_script_pub_key(script_pub_key)

    if script_type == "p2wpkh":
        return [script_pub_key_from_payload("p2pkh", payload)]

    script_s: List[bytes] = []
    current_script: List[ScriptToken] = []
    for token in script.deserialize(script_pub_key)[::-1]:
        if token == "OP_CODESEPARATOR":  # nosec required for python < 3.8
            script_s.append(script.serialize(current_script[::-1]))
        current_script.append(token)
    script_s.append(script.serialize(current_script[::-1]))
    return script_s[::-1]


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def segwit_v0(script_: bytes, tx: Tx, vin_i: int, hash_type: int, amount: int) -> bytes:

    hashtype_hex: str = hash_type.to_bytes(4, "little").hex()
    if hashtype_hex[0] != "8":
        hash_prev_outs = b"".join([vin.prev_out.serialize() for vin in tx.vin])
        hash_prev_outs = hash256(hash_prev_outs)
    else:
        hash_prev_outs = b"\x00" * 32

    if hashtype_hex[1] == "1" and hashtype_hex[0] != "8":
        hash_seq = b""
        for vin in tx.vin:
            hash_seq += vin.sequence.to_bytes(4, "little")
        hash_seq = hash256(hash_seq)
    else:
        hash_seq = b"\x00" * 32

    if hashtype_hex[1] not in ("2", "3"):
        hash_outputs = b""
        for vout in tx.vout:
            hash_outputs += vout.serialize()
        hash_outputs = hash256(hash_outputs)
    elif hashtype_hex[1] == "3" and vin_i < len(tx.vout):
        hash_outputs = hash256(tx.vout[vin_i].serialize())
    else:
        hash_outputs = b"\x00" * 32

    preimage = tx.version.to_bytes(4, "little")
    preimage += hash_prev_outs
    preimage += hash_seq
    preimage += tx.vin[vin_i].prev_out.serialize()
    preimage += var_bytes.serialize(script_)
    preimage += amount.to_bytes(8, "little")  # value
    preimage += tx.vin[vin_i].sequence.to_bytes(4, "little")
    preimage += hash_outputs
    preimage += tx.lock_time.to_bytes(4, "little")
    preimage += bytes.fromhex(hashtype_hex)

    return hash256(preimage)


def from_utxo(utxo: TxOut, tx: Tx, vin_i: int, hash_type: int) -> bytes:

    script_pub_key = utxo.script_pub_key

    # first off, handle all p2sh-wrapped scripts
    if is_p2sh(script_pub_key):
        script_pub_key = tx.vin[vin_i].script_sig

    if is_p2wpkh(script_pub_key):
        script_ = _witness_v0_script(script_pub_key)[0]
        return segwit_v0(script_, tx, vin_i, hash_type, utxo.value)

    if is_p2wsh(script_pub_key):
        # the real script is contained in the witness
        script_ = _witness_v0_script(tx.vin[vin_i].witness.stack[-1])[0]
        return segwit_v0(script_, tx, vin_i, hash_type, utxo.value)

    script_ = _legacy_script(script_pub_key)[0]
    return legacy(script_, tx, vin_i, hash_type)
