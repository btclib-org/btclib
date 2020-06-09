#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict, List
from hashlib import sha256

from . import varint, tx_in, tx_out
from .tx_in import TxIn
from .tx_out import TxOut


class Transaction(TypedDict):
    txid: str = ""
    hash: str = ""
    version: int = 0
    locktime: int = 0
    vin: List[TxIn] = []
    vout: List[TxOut] = []
    witness_flag: bool = False


def deserialize(data: bytes):
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
        tx_input = tx_in.deserialize(data)
        tx["vin"].append(tx_input)
        data = data[len(tx_in.serialize(tx_input)) :]

    output_count = varint.decode(data)
    data = data[len(varint.encode(output_count)) :]
    for x in range(output_count):
        tx_output = tx_out.deserialize(data)
        tx["vout"].append(tx_output)
        data = data[len(tx_out.serialize(tx_output)) :]

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

    tx["txid"] = sha256(sha256(serialize(tx, False)).digest()).digest()[::-1].hex()
    tx["hash"] = sha256(sha256(serialize(tx)).digest()).digest()[::-1].hex()

    return tx


def serialize(tx: Transaction, include_witness=True):
    out = tx["version"].to_bytes(4, "little")
    if tx["witness_flag"] and include_witness:
        out += b"\x00\x01"
    out += varint.encode(len(tx["vin"]))
    for tx_input in tx["vin"]:
        out += tx_in.serialize(tx_input)

    out += varint.encode(len(tx["vout"]))
    for tx_output in tx["vout"]:
        out += tx_out.serialize(tx_output)
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
