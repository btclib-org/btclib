#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction (Psbt) helper functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""
from __future__ import annotations

from io import BytesIO
from typing import Mapping

from btclib import var_bytes, var_int
from btclib.alias import BinaryData, Octets
from btclib.bip32 import BIP32KeyOrigin
from btclib.bip32.der_path import indexes_from_bip32_path, str_from_bip32_path
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.exceptions import BTClibValueError
from btclib.tx import Tx
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


def deserialize_map(data: BinaryData) -> tuple[dict[bytes, bytes], BytesIO]:
    stream = bytesio_from_binarydata(data)
    if (
        len(stream.getbuffer()) == stream.tell()
    ):  # we are at the end of the stream buffer
        raise BTClibValueError("malformed psbt: at least a map is missing")
    partial_map: dict[bytes, bytes] = {}
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
    """Return the binary representation of the dataclass element."""
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
    """Return the dataclass element from its binary representation."""
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return int.from_bytes(v, byteorder="little", signed=False)


def encode_dict_bytes_bytes(dict_: Mapping[bytes, bytes]) -> dict[str, str]:
    """Return the json representation of the dataclass element."""
    # unknown could be sorted, partial_sigs cannot
    return {k.hex(): v.hex() for k, v in dict_.items()}


def decode_dict_bytes_bytes(map_: Mapping[Octets, Octets] | None) -> dict[bytes, bytes]:
    """Return the dataclass element from its json representation."""
    # unknown could be sorted, partial_sigs cannot
    if map_ is None:
        return {}
    return {bytes_from_octets(k): bytes_from_octets(v) for k, v in map_.items()}


def serialize_dict_bytes_bytes(
    type_: bytes, dictionary: Mapping[bytes, bytes]
) -> bytes:
    """Return the binary representation of the dataclass element."""
    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v)
            for k, v in sorted(dictionary.items())
        ]
    )


def encode_leaf_scripts(
    dict_: Mapping[bytes, Tuple[bytes, int]]
) -> Dict[str, Tuple[str, int]]:
    return {k.hex(): (v[0].hex(), v[1]) for k, v in dict_.items()}


def decode_leaf_scripts(
    map_: Optional[Mapping[Octets, Tuple[Octets, int]]]
) -> Dict[bytes, Tuple[bytes, int]]:
    if map_ is None:
        return {}
    return {
        bytes_from_octets(k): (bytes_from_octets(v[0]), v[1]) for k, v in map_.items()
    }


def serialize_leaf_scripts(
    type_: bytes, dictionary: Dict[bytes, Tuple[bytes, int]]
) -> bytes:
    return b"".join(
        [
            var_bytes.serialize(type_ + k)
            + var_bytes.serialize(v[0] + v[1].to_bytes(1, "big"))
            for k, v in sorted(dictionary.items())
        ]
    )


def parse_leaf_script(v: bytes) -> Tuple[bytes, int]:
    return (v[:-1], v[-1])


def encode_taproot_tree(
    list_: List[Tuple[int, int, bytes]]
) -> List[Tuple[int, int, str]]:
    return [(v[0], v[1], v[2].hex()) for v in list_]


def decode_taproot_tree(
    list_: Optional[Sequence[Tuple[int, int, Octets]]]
) -> List[Tuple[int, int, bytes]]:
    if list_ is None:
        return []
    return [(v[0], v[1], bytes_from_octets(v[2])) for v in list_]


def serialize_taproot_tree(type_: bytes, list_: List[Tuple[int, int, bytes]]) -> bytes:
    return var_bytes.serialize(type_) + var_bytes.serialize(
        b"".join(
            [v[0].to_bytes(1, "big") + v[1].to_bytes(1, "big") + v[2] for v in list_]
        )
    )


def parse_taproot_tree(v: bytes) -> List[Tuple[int, int, bytes]]:
    out: List[Tuple[int, int, bytes]] = []

    stream = bytesio_from_binarydata(v)
    while True:
        v = stream.read(1)
        if not v:
            return out
        depth = int.from_bytes(v, "big")
        leaf_version = int.from_bytes(stream.read(1), "big")
        script = stream.read()
        out.append((depth, leaf_version, script))


def taproot_bip32_to_dict(
    taproot_hd_key_paths: Dict[bytes, Tuple[List[bytes], BIP32KeyOrigin]]
) -> List[Dict[str, str]]:
    return [
        {
            "pub_key": pub_key.hex(),
            "leaf_hashes": [x.hex() for x in leaf_hashes],
            "master_fingerprint": key_origin.master_fingerprint.hex(),
            "path": str_from_bip32_path(key_origin.der_path),
        }
        for pub_key, (leaf_hashes, key_origin) in sorted(taproot_hd_key_paths.items())
    ]


def taproot_bip32_from_dict(
    taproot_hd_key_paths: List[Dict[str, str]]
) -> Dict[bytes, Tuple[List[bytes], BIP32KeyOrigin]]:
    return {
        bytes_from_octets(bip32_deriv["pub_key"], 4): (
            [bytes_from_octets(x) for x in bip32_deriv["leaf_hashes"]],
            BIP32KeyOrigin(
                bytes_from_octets(bip32_deriv["master_fingerprint"], 4),
                indexes_from_bip32_path(bip32_deriv["path"]),
            ),
        )
        for bip32_deriv in taproot_hd_key_paths
    }


def decode_taproot_bip32(
    dict_: Optional[Mapping[Octets, Tuple[List[Octets], BIP32KeyOrigin]]]
) -> Dict[bytes, Tuple[List[bytes], BIP32KeyOrigin]]:
    if dict_ is None:
        return {}
    taproot_bip32 = {
        bytes_from_octets(k): ([bytes_from_octets(x) for x in v[0]], v[1])
        for k, v in dict_.items()
    }
    return dict(sorted(taproot_bip32.items()))


def serialize_taproot_bip32(
    type_: bytes, dict_: Dict[bytes, Tuple[List[bytes], BIP32KeyOrigin]]
) -> bytes:
    return b"".join(
        [
            var_bytes.serialize(type_ + k)
            + var_bytes.serialize(
                var_int.serialize(len(v[0])) + b"".join(v[0]) + v[1].serialize()
            )
            for k, v in sorted(dict_.items())
        ]
    )


def parse_taproot_bip32(v: bytes) -> Tuple[List[bytes], BIP32KeyOrigin]:
    stream = bytesio_from_binarydata(v)
    len_ = var_int.parse(stream)
    leafs = [stream.read(4) for x in range(len_)]
    bip32keyorigin = BIP32KeyOrigin.parse(stream.read())
    return (leafs, bip32keyorigin)


def serialize_bytes(type_: bytes, value: bytes) -> bytes:
    """Return the binary representation of the dataclass element."""
    return var_bytes.serialize(type_) + var_bytes.serialize(value)


def deserialize_bytes(k: bytes, v: bytes, type_: str) -> bytes:
    """Return the dataclass element from its binary representation."""
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return v


def assert_valid_redeem_script(redeem_script: bytes) -> None:
    """Raise an exception if the dataclass element is not valid."""
    # should check for a valid script
    bytes(redeem_script)


def assert_valid_witness_script(witness_script: bytes) -> None:
    """Raise an exception if the dataclass element is not valid."""
    # should check for a valid script
    bytes(witness_script)


def assert_valid_unknown(data: Mapping[bytes, bytes]) -> None:
    """Raise an exception if the dataclass element is not valid."""
    for key, value in data.items():
        bytes(key)
        bytes(value)


def deserialize_tx(
    k: bytes, v: bytes, type_: str, include_witness: bool | None = True
) -> Tx:
    """Return the dataclass element from its binary representation."""
    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    tx = Tx.parse(v)
    if not include_witness and tx.serialize(include_witness=False) != v:
        raise BTClibValueError("wrong tx serialization format")
    return tx
