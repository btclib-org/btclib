#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import List, TypedDict

from . import script, varint
from .alias import Token


class TxIn(TypedDict):
    txid: str
    vout: int
    scriptSig: List[Token]
    sequence: int
    txinwitness: List[str]


def deserialize(data: bytes) -> TxIn:

    txid = data[:32][::-1].hex()
    vout = int.from_bytes(data[32:36], "little")
    script_length = varint.decode(data[36:])
    data = data[36 + len(varint.encode(script_length)) :]
    scriptSig = script.decode(data[:script_length])
    sequence = int.from_bytes(data[script_length : script_length + 4], "little")
    txinwitness: List[str] = []

    tx_in: TxIn = {
        "txid": txid,
        "vout": vout,
        "scriptSig": scriptSig,
        "sequence": sequence,
        "txinwitness": txinwitness,
    }
    return tx_in


def serialize(tx_in: TxIn) -> bytes:
    out = bytes.fromhex(tx_in["txid"])[::-1]
    out += tx_in["vout"].to_bytes(4, "little")
    script_bytes = script.encode(tx_in["scriptSig"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    out += tx_in["sequence"].to_bytes(4, "little")
    return out
