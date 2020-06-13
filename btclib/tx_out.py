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
from .alias import Octets, Token
from .utils import bytes_from_octets


class TxOut(TypedDict):
    value: int  # satoshis
    scriptPubKey: List[Token]


def deserialize(data: Octets) -> TxOut:

    data = bytes_from_octets(data)

    value = int.from_bytes(data[:8], "little")
    script_length = varint.decode(data[8:])
    data = data[8 + len(varint.encode(script_length)) :]
    scriptPubKey = script.decode(data[:script_length])

    tx_out: TxOut = {"value": value, "scriptPubKey": scriptPubKey}

    assert_valid(tx_out)
    return tx_out


def serialize(tx_out: TxOut) -> bytes:
    out = tx_out["value"].to_bytes(8, "little")
    script_bytes = script.encode(tx_out["scriptPubKey"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    return out


def assert_valid(tx_out: TxOut) -> None:
    if tx_out["value"] < 0:
        raise ValueError(f"negative value: {tx_out['value']}")

    if 2099999997690000 < tx_out["value"]:
        raise ValueError(f"value too high: {tx_out['value']}")

    if len(tx_out["scriptPubKey"]) == 0:
        raise ValueError(f"empty scriptPubKey: {tx_out['scriptPubKey']}")
