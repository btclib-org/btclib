#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from . import varint
from typing import TypedDict, List


class TxIn(TypedDict):
    previous_output_hash: bytes = b""
    previous_output_index: int = 4294967295
    script_length: int = 0
    signature_script: bytes = 0
    sequence: int = 4294967295
    witnesses: List[bytes] = []


def tx_in_deserialize(data: bytes):
    tx_in = TxIn()
    tx_in["previous_output_hash"] = data[:32]
    tx_in["previous_output_index"] = int.from_bytes(data[32:36], "little")
    tx_in["script_length"] = varint.decode(data[36:])
    data = data[36 + len(varint.encode(tx_in["script_length"])) :]
    tx_in["signature_script"] = data[: tx_in["script_length"]]
    tx_in["sequence"] = int.from_bytes(
        data[tx_in["script_length"] : tx_in["script_length"] + 4], "little"
    )
    tx_in["witnesses"] = []
    return tx_in


def tx_in_serialize(tx_in: TxIn):
    out = tx_in["previous_output_hash"]
    out += tx_in["previous_output_index"].to_bytes(4, "little")
    out += varint.encode(tx_in["script_length"])
    out += tx_in["signature_script"]
    out += tx_in["sequence"].to_bytes(4, "little")
    return out


class TxOut(TypedDict):
    value: int = 0
    pk_script_length: int = 0
    pk_script: bytes = b""


def tx_out_deserialize(data: bytes):
    tx_out = TxOut()
    tx_out["value"] = int.from_bytes(data[:8], "little")
    tx_out["pk_script_length"] = varint.decode(data[8:])
    data = data[8 + len(varint.encode(tx_out["pk_script_length"])) :]
    tx_out["pk_script"] = data[: tx_out["pk_script_length"]]
    return tx_out


def tx_out_serialize(tx_out: TxOut):
    out = tx_out["value"].to_bytes(8, "little")
    out += varint.encode(tx_out["pk_script_length"])
    out += tx_out["pk_script"]
    return out


class Transaction(TypedDict):
    version: int = 0
    witness_flag: bool = False
    input_count: int = 0
    tx_inputs: List[TxIn] = []
    output_count: int = 0
    tx_outputs: List[TxOut] = []
    lock_time: int = 0


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

    tx["tx_inputs"] = []
    tx["tx_outputs"] = []

    tx["input_count"] = varint.decode(data)
    data = data[len(varint.encode(tx["input_count"])) :]
    for x in range(tx["input_count"]):
        tx_input = tx_in_deserialize(data)
        tx["tx_inputs"].append(tx_input)
        data = data[len(tx_in_serialize(tx_input)) :]

    tx["output_count"] = varint.decode(data)
    data = data[len(varint.encode(tx["output_count"])) :]
    for x in range(tx["output_count"]):
        tx_output = tx_out_deserialize(data)
        tx["tx_outputs"].append(tx_output)
        data = data[len(tx_out_serialize(tx_output)) :]

    if tx["witness_flag"]:
        for x in range(tx["input_count"]):
            witness_count = varint.decode(data)
            data = data[len(varint.encode(witness_count)) :]
            for i in range(witness_count):
                witness_len = varint.decode(data)
                data = data[len(varint.encode(witness_len)) :]
                tx["tx_inputs"][x]["witnesses"].append(data[:witness_len])
                data = data[witness_len:]

    tx["lock_time"] = int.from_bytes(data[:4], "little")
    return tx


def transaction_serialize(tx: Transaction):
    out = tx["version"].to_bytes(4, "little")
    if tx["witness_flag"]:
        out += b"\x00\x01"
    out += varint.encode(tx["input_count"])
    for tx_in in tx["tx_inputs"]:
        out += tx_in_serialize(tx_in)

    out += varint.encode(tx["output_count"])
    for tx_out in tx["tx_outputs"]:
        out += tx_out_serialize(tx_out)
    if tx["witness_flag"]:
        for x in range(tx["input_count"]):
            witness_count = len(tx["tx_inputs"][x]["witnesses"])
            out += varint.encode(witness_count)
            for i in range(witness_count):
                witness_len = len(tx["tx_inputs"][x]["witnesses"][i])
                out += varint.encode(witness_len)
                out += tx["tx_inputs"][x]["witnesses"][i]
    out += tx["lock_time"].to_bytes(4, "little")
    return out
