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
from .alias import Octets
from .utils import bytes_from_octets
from . import varint

from .tx import Tx


_PSbt = TypeVar("_PSbt", bound="Psbt")


@dataclass
class Psbt:
    # global_maps: List[List[Pair]]
    # input_maps: List[List[Pair]]
    # output_maps: List[List[Pair]]
    global_map: Dict
    input_maps: List[Dict]
    output_maps: List[Dict]

    @classmethod
    def deserialize(cls: Type[_PSbt], data: Octets) -> _PSbt:
        data = bytes_from_octets(data)

        magic_bytes = data[:5]
        if magic_bytes != bytes.fromhex("70736274ff"):
            raise Exception()

        data = data[5:]

        global_map, data = deserialize_map(data)

        input_len = len(Tx.deserialize(global_map[b"\x00"]).vin)
        output_len = len(Tx.deserialize(global_map[b"\x00"]).vout)

        input_maps = []
        for i in range(input_len):
            input_map, data = deserialize_map(data)
            input_maps.append(input_map)

        output_maps = []
        for i in range(output_len):
            output_map, data = deserialize_map(data)
            output_maps.append(output_map)

        return cls(
            global_map=global_map, input_maps=input_maps, output_maps=output_maps
        )


def deserialize_map(data: bytes) -> Tuple[Dict, bytes]:
    partial_map = {}
    while True:
        key_len = varint.decode(data)
        data = data[len(varint.encode(key_len)) :]
        key = data[:key_len]
        data = data[key_len:]
        value_len = varint.decode(data)
        data = data[len(varint.encode(value_len)) :]
        value = data[:value_len]
        data = data[value_len:]
        partial_map[key] = value
        if data[0] == 0:
            data = data[1:]
            return partial_map, data
