#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Transaction hashes to be signed and their hash types.

https://medium.com/@bitaps.com/exploring-bitcoin-signature-hash-types-15427766f0a9
https://raghavsood.com/blog/2018/06/10/bitcoin-signature-types-sighash
https://wiki.bitcoinsv.io/index.php/SIGHASH_flags
"""

from copy import deepcopy
from typing import List

from btclib import var_bytes
from btclib.alias import Octets
from btclib.exceptions import BTClibValueError
from btclib.script.script import Command, parse, serialize
from btclib.script.script_pub_key import (
    ScriptPubKey,
    is_p2sh,
    is_p2wpkh,
    is_p2wsh,
    type_and_payload,
)
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_octets, hash256

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


def legacy_script(script_pub_key: Octets) -> List[bytes]:
    script_s: List[bytes] = []
    current_script: List[Command] = []
    for token in parse(script_pub_key)[::-1]:
        if token == "OP_CODESEPARATOR":  # nosec required for python < 3.8
            script_s.append(serialize(current_script[::-1]))
        else:
            current_script.append(token)
    script_s.append(serialize(current_script[::-1]))
    return script_s[::-1]


# FIXME: remove OP_CODESEPARATOR only if executed
def witness_v0_script(script_pub_key: Octets) -> List[bytes]:
    script_type, payload = type_and_payload(script_pub_key)

    if script_type == "p2wpkh":
        script = serialize(
            ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
        return [script]

    script_s: List[bytes] = []
    current_script: List[Command] = []
    for token in parse(script_pub_key)[::-1]:
        if token == "OP_CODESEPARATOR":  # nosec required for python < 3.8
            script_s.append(serialize(current_script[::-1]))
        current_script.append(token)
    script_s.append(serialize(current_script[::-1]))
    return script_s[::-1]


def legacy(script_: Octets, tx: Tx, vin_i: int, hash_type: int) -> bytes:
    script_ = bytes_from_octets(script_)

    new_tx = deepcopy(tx)
    for txin in new_tx.vin:
        txin.script_sig = b""
    # TODO: delete sig from script_ (even if non standard)
    new_tx.vin[vin_i].script_sig = script_
    if hash_type & 0x1F == NONE:
        new_tx.vout = []
        for i, txin in enumerate(new_tx.vin):
            if i != vin_i:
                txin.sequence = 0

    if hash_type & 0x1F == SINGLE:
        # sign_hash single bug
        if vin_i >= len(new_tx.vout):
            return (256 ** 31).to_bytes(32, byteorder="big", signed=False)
        new_tx.vout = new_tx.vout[: vin_i + 1]
        for txout in new_tx.vout[:-1]:
            txout.script_pub_key = ScriptPubKey(b"")
            txout.value = 0xFFFFFFFFFFFFFFFF
        for i, txin in enumerate(new_tx.vin):
            if i != vin_i:
                txin.sequence = 0

    if hash_type & 0x80:
        new_tx.vin = [new_tx.vin[vin_i]]

    preimage = new_tx.serialize(include_witness=False, check_validity=False)
    preimage += hash_type.to_bytes(4, byteorder="little", signed=False)

    return hash256(preimage)


# https://github.com/bitcoin/bitcoin/blob/4b30c41b4ebf2eb70d8a3cd99cf4d05d405eec81/test/functional/test_framework/script.py#L673
def segwit_v0(
    script_: Octets, tx: Tx, vin_i: int, hash_type: int, amount: int
) -> bytes:
    script_ = bytes_from_octets(script_)

    hash_prev_outs = b"\x00" * 32
    if not hash_type & ANYONECANPAY:
        hash_prev_outs = b"".join([vin.prev_out.serialize() for vin in tx.vin])
        hash_prev_outs = hash256(hash_prev_outs)

    hash_seqs = b"\x00" * 32
    if (
        not (hash_type & ANYONECANPAY)
        and (hash_type & 0x1F) != SINGLE
        and (hash_type & 0x1F) != NONE
    ):
        hash_seqs = b"".join(
            [
                vin.sequence.to_bytes(4, byteorder="little", signed=False)
                for vin in tx.vin
            ]
        )
        hash_seqs = hash256(hash_seqs)

    hash_outputs = b"\x00" * 32
    if hash_type & 0x1F not in (SINGLE, NONE):
        hash_outputs = b"".join([vout.serialize() for vout in tx.vout])
        hash_outputs = hash256(hash_outputs)
    elif (hash_type & 0x1F) == SINGLE and vin_i < len(tx.vout):
        hash_outputs = hash256(tx.vout[vin_i].serialize())

    preimage = b"".join(
        [
            tx.version.to_bytes(4, byteorder="little", signed=False),
            hash_prev_outs,
            hash_seqs,
            tx.vin[vin_i].prev_out.serialize(),
            var_bytes.serialize(script_),
            amount.to_bytes(8, byteorder="little", signed=False),  # value
            tx.vin[vin_i].sequence.to_bytes(4, byteorder="little", signed=False),
            hash_outputs,
            tx.lock_time.to_bytes(4, byteorder="little", signed=False),
            hash_type.to_bytes(4, byteorder="little", signed=False),
        ]
    )
    return hash256(preimage)


def from_utxo(utxo: TxOut, tx: Tx, vin_i: int, hash_type: int) -> bytes:

    script = utxo.script_pub_key.script

    # first off, handle all p2sh-wrapped scripts
    if is_p2sh(script):
        script = tx.vin[vin_i].script_sig

    if is_p2wpkh(script):
        script_ = witness_v0_script(script)[0]
        return segwit_v0(script_, tx, vin_i, hash_type, utxo.value)

    if is_p2wsh(script):
        # the real script is contained in the witness
        script_ = witness_v0_script(tx.vin[vin_i].script_witness.stack[-1])[0]
        return segwit_v0(script_, tx, vin_i, hash_type, utxo.value)

    script_ = legacy_script(script)[0]
    return legacy(script_, tx, vin_i, hash_type)
