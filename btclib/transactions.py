#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from . import varint
from typing import TypedDict


class Transaction:
    def __init__(self):
        self.version = 0
        self.witness_flag = False
        self.input_count = 0
        self.tx_inputs = []
        self.output_count = 0
        self.tx_outputs = []
        self.witnesses = []
        self.lock_time = 0

    @classmethod
    def from_bytes(cls, data):
        # if len(data) < 60:
        #     raise Exception
        trans = cls()
        trans.version = int.from_bytes(data[0:4], "little")
        if False:  # data[4:6] == b"\x01\x00":
            trans.witness_flag = True
            data = data[6:]
        else:
            data = data[4:]

        trans.input_count = varint.decode(data)
        data = data[len(varint.encode(trans.input_count)) :]
        for x in range(trans.input_count):
            tx_input = tx_in_deserialize(data)
            trans.tx_inputs.append(tx_input)
            data = data[len(tx_in_serialize(tx_input)) :]

        trans.output_count = varint.decode(data)
        data = data[len(varint.encode(trans.output_count)) :]
        for x in range(trans.output_count):
            tx_output = tx_out_deserialize(data)
            trans.tx_outputs.append(tx_output)
            data = data[len(tx_out_serialize(tx_output)) :]

        # if trans.witness_flag:
        #     trans.witnesses = TxWitness.from_bytes(data)
        #     data = data[len(trans.witnesses.to_bytes()) :]

        trans.lock_time = int.from_bytes(data[:4], "little")
        return trans

    def to_bytes(self):
        out = self.version.to_bytes(4, "little")
        # if self.witness_flag:
        #     out += b"\x00\x01"
        out += varint.encode(self.input_count)
        for tx_in in self.tx_inputs:
            out += tx_in_serialize(tx_in)

        out += varint.encode(self.output_count)
        for tx_out in self.tx_outputs:
            out += tx_out_serialize(tx_out)
        # if self.witness_flag:
        #     out += self.witnesses.to_bytes()
        out += self.lock_time.to_bytes(4, "little")
        return out


class TxIn(TypedDict):
    previous_output_hash: bytes = b""
    previous_output_index: int = 4294967295
    script_length: int = 0
    signature_script: bytes = 0
    sequence: int = 4294967295


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


# class TxWitness:
#     def __init__(self):
#         self.count = 0
#         self.witnesses = []
#
#     @classmethod
#     def from_bytes(cls, data):
#         if len(data) < 41:
#             raise Exception
#         tx_witness = cls()
#         tx_witness.count = varint.decode(data[:4])
#         data = data[len(varint.encode(tx_witness.count)) :]
#
#         for x in range(tx_witness.count):
#             witness_len = varint.decode(data)
#             data = data[len(varint.encode(witness_len)) :]
#             tx_witness.witnesses.append(data[:witness_len])
#
#         return tx_witness
#
#     def to_bytes(self):
#         out = varint.encode(self.count)
#         for witness in self.witnesses:
#             out += varint.encode(len(witness)) + witness
#         return out
