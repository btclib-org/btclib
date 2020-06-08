#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from . import varint, script
from typing import TypedDict, List
from hashlib import sha256


class TxIn(TypedDict):
    txid: bytes = b""
    vout: int = 4294967295
    scriptSig: bytes = 0
    sequence: int = 4294967295
    txinwitness: List[bytes] = []


def tx_in_deserialize(data: bytes):
    tx_in = TxIn()
    tx_in["txid"] = data[:32][::-1].hex()
    tx_in["vout"] = int.from_bytes(data[32:36], "little")

    script_length = varint.decode(data[36:])
    data = data[36 + len(varint.encode(script_length)) :]
    tx_in["scriptSig"] = script.decode(data[:script_length])
    tx_in["txinwitness"] = []
    tx_in["sequence"] = int.from_bytes(
        data[script_length : script_length + 4], "little"
    )
    return tx_in


def tx_in_serialize(tx_in: TxIn):
    out = bytes.fromhex(tx_in["txid"])[::-1]
    out += tx_in["vout"].to_bytes(4, "little")
    script_bytes = script.encode(tx_in["scriptSig"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    out += tx_in["sequence"].to_bytes(4, "little")
    return out


class TxOut(TypedDict):
    value: int = 0
    pk_script_length: int = 0
    scriptPubKey: bytes = b""


def tx_out_deserialize(data: bytes):
    tx_out = TxOut()
    tx_out["value"] = int.from_bytes(data[:8], "little")
    script_length = varint.decode(data[8:])
    data = data[8 + len(varint.encode(script_length)) :]
    tx_out["scriptPubKey"] = script.decode(data[:script_length])
    return tx_out


def tx_out_serialize(tx_out: TxOut):
    out = tx_out["value"].to_bytes(8, "little")
    script_bytes = script.encode(tx_out["scriptPubKey"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    return out


class Transaction(TypedDict):
    txid: str = ""
    version: int = 0
    locktime: int = 0
    vin: List[TxIn] = []
    vout: List[TxOut] = []
    witness_flag: bool = False


def transaction_deserialize(data: bytes):
    # if len(data) < 60:
    #     raise Exception
    tx = Transaction()
    tx["witness_flag"] = False
    tx["version"] = int.from_bytes(data[0:4], "little")
    if data[4:6] == b"\x00\x01":
        tx["witness_flag"] = True
        data = data[6:]
    else:
        data = data[4:]

    tx["vin"] = []
    tx["vout"] = []

    input_count = varint.decode(data)
    data = data[len(varint.encode(input_count)) :]
    for x in range(input_count):
        tx_input = tx_in_deserialize(data)
        tx["vin"].append(tx_input)
        data = data[len(tx_in_serialize(tx_input)) :]

    output_count = varint.decode(data)
    data = data[len(varint.encode(output_count)) :]
    for x in range(output_count):
        tx_output = tx_out_deserialize(data)
        tx["vout"].append(tx_output)
        data = data[len(tx_out_serialize(tx_output)) :]

    if tx["witness_flag"]:
        for x in range(input_count):
            witness_count = varint.decode(data)
            data = data[len(varint.encode(witness_count)) :]
            for i in range(witness_count):
                witness_len = varint.decode(data)
                data = data[len(varint.encode(witness_len)) :]
                tx["vin"][x]["txinwitness"].append(data[:witness_len].hex())
                data = data[witness_len:]

    tx["locktime"] = int.from_bytes(data[:4], "little")

    tx["txid"] = (
        sha256(sha256(transaction_serialize(tx, False)).digest()).digest()[::-1].hex()
    )
    tx["hash"] = sha256(sha256(transaction_serialize(tx)).digest()).digest()[::-1].hex()

    return tx


def transaction_serialize(tx: Transaction, include_witness=True):
    out = tx["version"].to_bytes(4, "little")
    if tx["witness_flag"] and include_witness:
        out += b"\x00\x01"
    out += varint.encode(len(tx["vin"]))
    for tx_in in tx["vin"]:
        out += tx_in_serialize(tx_in)

    out += varint.encode(len(tx["vout"]))
    for tx_out in tx["vout"]:
        out += tx_out_serialize(tx_out)
    if tx["witness_flag"] and include_witness:
        for x in range(len(tx["vin"])):
            witness_count = len(tx["vin"][x]["txinwitness"])
            out += varint.encode(witness_count)
            for i in range(witness_count):

                # we have to count bytes, not hex
                witness_len = len(tx["vin"][x]["txinwitness"][i]) // 2

                out += varint.encode(witness_len)
                out += bytes.fromhex(tx["vin"][x]["txinwitness"][i])
    out += tx["locktime"].to_bytes(4, "little")
    return out
