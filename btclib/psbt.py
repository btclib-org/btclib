#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass
from typing import List, Any, Dict, Tuple, Type, TypeVar
from base64 import b64decode, b64encode

from .tx import Tx
from .tx_out import TxOut
from . import varint, script


_PSbt = TypeVar("_PSbt", bound="Psbt")


@dataclass
class Psbt:
    global_map: Dict
    input_maps: List[Dict]
    output_maps: List[Dict]

    @classmethod
    def deserialize(cls: Type[_PSbt], data: str) -> _PSbt:
        data = b64decode(data)

        magic_bytes = data[:5]
        assert magic_bytes == bytes.fromhex(
            "70736274ff"
        ), "Malformed psbt: missing magic bytes"

        data = data[5:]

        global_map, data = deserialize_map(data)
        global_map = decode_global_map(global_map)

        assert "tx" in global_map.keys(), "Malformed psbt: missing unigned tx"

        input_len = len(global_map["tx"].vin)
        output_len = len(global_map["tx"].vout)

        input_maps = []
        for i in range(input_len):
            input_map, data = deserialize_map(data)
            input_map = decode_input_map(input_map)
            input_maps.append(input_map)

        output_maps = []
        for i in range(output_len):
            output_map, data = deserialize_map(data)
            output_map = decode_output_map(output_map)
            output_maps.append(output_map)

        psbt = cls(
            global_map=global_map, input_maps=input_maps, output_maps=output_maps
        )

        psbt.assert_valid()

        return psbt

    def assert_valid(self):
        pass


def deserialize_map(data: bytes) -> Tuple[Dict, bytes]:
    assert len(data) != 0, "Malformed psbt: at least a map is missing"
    partial_map = {}
    while True:
        if len(data) == 0:
            return partial_map, data
        if data[0] == 0:
            data = data[1:]
            return partial_map, data
        key_len = varint.decode(data)
        data = data[len(varint.encode(key_len)) :]
        key = data[:key_len]
        data = data[key_len:]
        value_len = varint.decode(data)
        data = data[len(varint.encode(value_len)) :]
        value = data[:value_len]
        data = data[value_len:]
        assert key not in partial_map.keys(), "Malformed psbt: duplicate keys"
        partial_map[key] = value


def decode_global_map(global_map: Dict) -> Dict:
    out_map = {}
    for key, value in global_map.items():
        if key == b"\x00":
            out_map["tx"] = Tx.deserialize(value)
        elif key[0] == 0x01:  # TODO
            assert len(key) == 33 + 1
            pass  # TODO
        elif key[0] == 0xFB:
            assert len(value) == 32
            out_map["version"] = int.from_bytes(value, "little")
        elif key[0] == 0xFC:
            pass  # proprietary use
        else:
            raise KeyError("Invalid key type")
    return out_map


def decode_input_map(input_map: Dict) -> Dict:
    out_map = {}
    for key, value in input_map.items():
        if key == b"\x00":
            out_map["non_witness_utxo"] = Tx.deserialize(value)
        elif key == b"\x01":
            out_map["witness_utxo"] = TxOut.deserialize(value)
        elif key[0] == 0x02:
            assert len(key) == 33 + 1
            out_map["partial_sig"] = value.hex()
        elif key == b"\x03":
            assert len(value) == 4
            out_map["sighash_type"] = int.from_bytes(value, "little")
        elif key == b"\x04":
            out_map["redeem_script"] = script.decode(value)
        elif key == b"\x05":
            out_map["witness_script"] = script.decode(value)
        elif key[0] == 0x06:
            assert len(key) == 33 + 1
            pass  # TODO
        elif key == b"\x07":
            out_map["scriptSig"] = script.decode(value)
        elif key == b"\x08":
            out_map["scriptWitenss"] = script.decode(value)
        elif key == b"\x09":
            pass  # TODO
        elif key[0] == 0xFC:
            pass  # proprietary use
        else:
            raise KeyError("Invalid key type")
    return out_map


def decode_output_map(output_map: Dict) -> Dict:
    out_map = {}
    for key, value in output_map.items():
        if key == b"\x00":
            out_map["redeem_script"] = script.decode(value)
        elif key == b"\x01":
            out_map["witness_script"] = script.decode(value)
        elif key[0] == 0x02:
            assert len(key) == 33 + 1
            pass  # TODO
        elif key[0] == 0xFC:
            pass  # proprietary use
        else:
            raise KeyError("Invalid key type")
    return out_map
