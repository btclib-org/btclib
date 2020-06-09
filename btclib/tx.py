#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict, List

from . import varint, tx_in, tx_out
from .tx_in import TxIn
from .tx_out import TxOut
from .utils import hash256


class Tx(TypedDict):
    version: int
    locktime: int
    vin: List[TxIn]
    vout: List[TxOut]
    witness_flag: bool


def deserialize(data: bytes):
    # if len(data) < 60:
    #     raise Exception

    version = int.from_bytes(data[:4], "little")
    data = data[4:]

    witness_flag = False
    if data[:2] == b"\x00\x01":
        witness_flag = True
        data = data[2:]

    input_count = varint.decode(data)
    data = data[len(varint.encode(input_count)) :]
    vin: List[TxIn] = []
    for x in range(input_count):
        tx_input = tx_in.deserialize(data)
        vin.append(tx_input)
        data = data[len(tx_in.serialize(tx_input)) :]

    output_count = varint.decode(data)
    data = data[len(varint.encode(output_count)) :]
    vout: List[TxOut] = []
    for x in range(output_count):
        tx_output = tx_out.deserialize(data)
        vout.append(tx_output)
        data = data[len(tx_out.serialize(tx_output)) :]

    if witness_flag:
        for x in range(input_count):
            witness_count = varint.decode(data)
            data = data[len(varint.encode(witness_count)) :]
            for _ in range(witness_count):
                witness_len = varint.decode(data)
                data = data[len(varint.encode(witness_len)) :]
                vin[x]["txinwitness"].append(data[:witness_len].hex())
                data = data[witness_len:]

    locktime = int.from_bytes(data[:4], "little")

    tx: Tx = {
        "version": version,
        "locktime": locktime,
        "vin": vin,
        "vout": vout,
        "witness_flag": witness_flag,
    }
    return tx


def serialize(tx: Tx, include_witness=True):
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


def txid(tx: Tx):
    return hash256(serialize(tx, False))[::-1].hex()


def hash_value(tx: Tx):
    return hash256(serialize(tx))[::-1].hex()
