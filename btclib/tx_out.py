#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict

from . import varint, script
from .alias import Script


class TxOut(TypedDict):
    value: int = 0
    scriptPubKey: Script


def deserialize(data: bytes):
    tx_out = TxOut()
    tx_out["value"] = int.from_bytes(data[:8], "little")
    script_length = varint.decode(data[8:])
    data = data[8 + len(varint.encode(script_length)) :]
    tx_out["scriptPubKey"] = script.decode(data[:script_length])
    return tx_out


def serialize(tx_out: TxOut):
    out = tx_out["value"].to_bytes(8, "little")
    script_bytes = script.encode(tx_out["scriptPubKey"])
    out += varint.encode(len(script_bytes))
    out += script_bytes
    return out
