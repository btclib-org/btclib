#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, TypeVar, Type
from dataclasses import dataclass

from . import script, varint
from .alias import Octets, Token
from .utils import bytes_from_octets

_TxIn = TypeVar("_TxIn", bound="TxIn")


@dataclass
class TxIn:
    txid: str
    vout: int
    scriptSig: List[Token]
    scriptSigHex: str
    sequence: int
    txinwitness: List[str]

    @classmethod
    def deserialize(cls: Type[_TxIn], data: Octets) -> _TxIn:

        data = bytes_from_octets(data)

        txid = data[:32][::-1].hex()
        vout = int.from_bytes(data[32:36], "little")
        is_coinbase = False
        if txid == "00" * 32 and vout == 256 ** 4 - 1:
            is_coinbase = True

        script_length = varint.decode(data[36:])
        data = data[36 + len(varint.encode(script_length)) :]

        scriptSig: List[Token] = []
        scriptSigHex = ""
        if is_coinbase:
            scriptSigHex = data[:script_length].hex()
        else:
            scriptSig = script.decode(data[:script_length])

        sequence = int.from_bytes(data[script_length : script_length + 4], "little")
        txinwitness: List[str] = []

        tx_in = cls(
            txid=txid,
            vout=vout,
            scriptSig=scriptSig,
            scriptSigHex=scriptSigHex,
            sequence=sequence,
            txinwitness=txinwitness,
        )

        tx_in.assert_valid()
        return tx_in

    def serialize(self) -> bytes:
        out = bytes.fromhex(self.txid)[::-1]
        out += self.vout.to_bytes(4, "little")
        if self.txid == "00" * 32 and self.vout == 256 ** 4 - 1:
            script_bytes = bytes.fromhex(self.scriptSigHex)
        else:
            script_bytes = script.encode(self.scriptSig)
        out += varint.encode(len(script_bytes))
        out += script_bytes
        out += self.sequence.to_bytes(4, "little")
        return out

    def assert_valid(self) -> None:
        null_txid = "00" * 32
        null_vout = 256 ** 4 - 1
        if (self.txid == null_txid) ^ (self.vout == null_vout):
            raise ValueError("invalid tx_in")


def witness_deserialize(data: Octets) -> List[str]:

    data = bytes_from_octets(data)

    witness: List[str] = []

    witness_count = varint.decode(data)
    data = data[len(varint.encode(witness_count)) :]
    for _ in range(witness_count):
        witness_len = varint.decode(data)
        data = data[len(varint.encode(witness_len)) :]
        witness.append(data[:witness_len].hex())
        data = data[witness_len:]

    return witness


def witness_serialize(witness: List[str]) -> bytes:

    out = b""

    witness_count = len(witness)
    out += varint.encode(witness_count)
    for i in range(witness_count):
        witness_bytes = bytes.fromhex(witness[i])
        out += varint.encode(len(witness_bytes))
        out += witness_bytes

    return out
