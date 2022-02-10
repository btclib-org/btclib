#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction (Psbt) helper functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from io import BytesIO
from typing import Dict, Mapping, Optional, Tuple

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.tx.tx import Tx
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


def deserialize_map(data: BinaryData) -> Tuple[Dict[bytes, bytes], BytesIO]:
    stream = bytesio_from_binarydata(data)
    if (
        len(stream.getbuffer()) == stream.tell()
    ):  # we are at the end of the stream buffer
        raise BTClibValueError("malformed psbt: at least a map is missing")
    partial_map: Dict[bytes, bytes] = {}
    while True:
        if stream.read(1)[0] == 0:
            return partial_map, stream
        stream.seek(-1, 1)  # reset stream position
        key = stream.read(var_int.parse(stream))
        value = stream.read(var_int.parse(stream))
        if key in partial_map:
            raise BTClibValueError(f"duplicated key in psbt map: 0x{key.hex()}")
        partial_map[key] = value


def serialize_hd_key_paths(
    type_: bytes, hd_key_paths: Mapping[bytes, BIP32KeyOrigin]
) -> bytes:
    "Return the binary representation of the dataclass element."

    if len(type_) != 1:
        err_msg = f"invalid type marker lenght: {len(type_)}, instead of 1"
        raise BTClibValueError(err_msg)

    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v.serialize())
            for k, v in sorted(hd_key_paths.items())
        ]
    )


def deserialize_int(k: bytes, v: bytes, type_: str) -> int:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return int.from_bytes(v, byteorder="little", signed=False)


def encode_dict_bytes_bytes(dict_: Mapping[bytes, bytes]) -> Dict[str, str]:
    "Return the json representation of the dataclass element."
    # unknown could be sorted, partial_sigs cannot
    return {k.hex(): v.hex() for k, v in dict_.items()}


def decode_dict_bytes_bytes(
    map_: Optional[Mapping[Octets, Octets]]
) -> Dict[bytes, bytes]:
    "Return the dataclass element from its json representation."
    # unknown could be sorted, partial_sigs cannot
    if map_ is None:
        return {}
    return {bytes_from_octets(k): bytes_from_octets(v) for k, v in map_.items()}


def serialize_dict_bytes_bytes(
    type_: bytes, dictionary: Mapping[bytes, bytes]
) -> bytes:
    "Return the binary representation of the dataclass element."

    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v)
            for k, v in sorted(dictionary.items())
        ]
    )


def serialize_bytes(type_: bytes, value: bytes) -> bytes:
    "Return the binary representation of the dataclass element."
    return var_bytes.serialize(type_) + var_bytes.serialize(value)


def deserialize_bytes(k: bytes, v: bytes, type_: str) -> bytes:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return v


def assert_valid_redeem_script(redeem_script: bytes) -> None:
    "Raise an exception if the dataclass element is not valid."
    # should check for a valid script
    bytes(redeem_script)


def assert_valid_witness_script(witness_script: bytes) -> None:
    "Raise an exception if the dataclass element is not valid."
    # should check for a valid script
    bytes(witness_script)


def assert_valid_unknown(data: Mapping[bytes, bytes]) -> None:
    "Raise an exception if the dataclass element is not valid."

    for key, value in data.items():
        bytes(key)
        bytes(value)


def deserialize_tx(
    k: bytes, v: bytes, type_: str, include_witness: Optional[bool] = True
) -> Tx:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    tx = Tx.parse(v)
    if not include_witness and tx.serialize(include_witness=False) != v:
        raise BTClibValueError("wrong tx serialization format")
    return tx
