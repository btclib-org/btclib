#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import varint

block_1_coinbase_bytes = b'\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x07\x04\xff\xff\x00\x1d\x01\x04\xff\xff\xff\xff\x01\x00\xf2\x05*\x01\x00\x00\x00CA\x04\x96\xb58\xe8SQ\x9crj,\x91\xe6\x1e\xc1\x16\x00\xae\x13\x90\x81:b|f\xfb\x8b\xe7\x94{\xe6<R\xdau\x897\x95\x15\xd4\xe0\xa6\x04\xf8\x14\x17\x81\xe6"\x94r\x11f\xbfb\x1es\xa8,\xbf#B\xc8X\xee\xac\x00\x00\x00\x00'

block_1_coinbase_input_bytes = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x07\x04\xff\xff\x00\x1d\x01\x04\xff\xff\xff\xff"

block_1_coinbase_output_bytes = b'\x00\xf2\x05*\x01\x00\x00\x00CA\x04\x96\xb58\xe8SQ\x9crj,\x91\xe6\x1e\xc1\x16\x00\xae\x13\x90\x81:b|f\xfb\x8b\xe7\x94{\xe6<R\xdau\x897\x95\x15\xd4\xe0\xa6\x04\xf8\x14\x17\x81\xe6"\x94r\x11f\xbfb\x1es\xa8,\xbf#B\xc8X\xee\xac'


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
        if len(data) < 60:
            raise Exception
        trans = cls()
        trans.version = int.from_bytes(data[0:4], "little")
        if False:  # data[4:6] == b"\x01\x00":
            trans.witness_flag = True
            data = data[6:]
        else:
            data = data[4:]

        trans.input_count = varint.decode(data)
        data = data[varint.byte_size(data) :]
        for x in range(trans.input_count):
            tx_input = TxIn.from_bytes(data)
            trans.tx_inputs.append(tx_input)
            data = data[len(tx_input.to_bytes()) :]

        trans.output_count = varint.decode(data)
        data = data[varint.byte_size(data) :]
        for x in range(trans.output_count):
            tx_output = TxOut.from_bytes(data)
            trans.tx_outputs.append(tx_output)
            data = data[len(tx_output.to_bytes()) :]

        if trans.witness_flag:
            trans.witnesses = TxWitness.from_bytes(data)
            data = data[len(trans.witnesses.to_bytes()) :]

        trans.lock_time = int.from_bytes(data[:4], "little")
        return trans

    def to_bytes(self):
        out = self.version.to_bytes(4, "little")
        if self.witness_flag:
            out += b"\x00\x01"
        out += varint.encode(self.input_count)
        for tx_in in self.tx_inputs:
            out += tx_in.to_bytes()

        out += varint.encode(self.output_count)
        for tx_out in self.tx_outputs:
            out += tx_out.to_bytes()
        if self.witness_flag:
            out += self.witnesses.to_bytes()
        out += self.lock_time.to_bytes(4, "little")
        return out


class TxIn:
    def __init__(self):
        self.previous_output_hash = b""
        self.previous_output_index = 4294967295
        self.script_length = 0
        self.signature_script = b""
        self.sequence = 4294967295

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 41:
            raise Exception
        tx_in = cls()
        tx_in.previous_output_hash = data[:32]
        tx_in.previous_output_index = int.from_bytes(data[32:36], "little")
        tx_in.script_length = varint.decode(data[36:])
        data = data[36 + varint.byte_size(data[36:]) :]
        tx_in.signature_script = data[: tx_in.script_length]
        tx_in.sequence = int.from_bytes(
            data[tx_in.script_length : tx_in.script_length + 4], "little"
        )
        return tx_in

    def to_bytes(self):
        out = self.previous_output_hash
        out += self.previous_output_index.to_bytes(4, "little")
        out += varint.encode(self.script_length)
        out += self.signature_script
        out += self.sequence.to_bytes(4, "little")
        return out


class TxOut:
    def __init__(self):
        self.value = 0
        self.pk_script_length = 0
        self.pk_script = b""

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 9:
            raise Exception
        tx_out = cls()
        tx_out.value = int.from_bytes(data[:8], "little")
        tx_out.pk_script_length = varint.decode(data[8:])
        data = data[8 + varint.byte_size(data[8:]) :]
        tx_out.pk_script = data[: tx_out.pk_script_length]
        return tx_out

    def to_bytes(self):
        out = self.value.to_bytes(8, "little")
        out += varint.encode(self.pk_script_length)
        out += self.pk_script
        return out


class TxWitness:
    def __init__(self):
        self.count = 0
        self.witnesses = []

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 41:
            raise Exception
        tx_witness = cls()
        tx_witness.count = varint.decode(data[:4])
        data = data[len(varint.encode(tx_witness.count)) :]

        for x in range(tx_witness.count):
            witness_len = varint.decode(data)
            data = data[len(varint.encode(witness_len)) :]
            tx_witness.witnesses.append(data[:witness_len])

        return tx_witness

    def to_bytes(self):
        out = varint.encode(self.count)
        for witness in self.witnesses:
            out += varint.encode(len(witness)) + witness
        return out
