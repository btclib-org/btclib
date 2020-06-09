#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict, List

from . import varint, script
from .alias import Script


class TxIn(TypedDict):
    txid: str = ""
    vout: int = 4294967295
    scriptSig: Script
    sequence: int = 4294967295
    txinwitness: List[bytes] = []


def deserialize(data: bytes):
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


def serialize(tx_in: TxIn):
    out = bytes.fromhex(tx_in["txid"])[::-1]
    out += tx_in["vout"].to_bytes(4, "little")
    script_bytes = script.encode(tx_in["scriptSig"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    out += tx_in["sequence"].to_bytes(4, "little")
    return out
