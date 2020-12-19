#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BIP32 derivation path and key origin.

A BIP 32 derivation path can be represented as:

- "m/44h/0'/1H/0/10" or "44h/0'/1H/0/10" string
- sequence of integer indexes (even a single int)
- bytes (multiples of 4-bytes index)
"""

from dataclasses import InitVar, dataclass, field
from io import SEEK_CUR
from typing import (
    Any,
    Collection,
    Dict,
    List,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
)

from dataclasses_json import DataClassJsonMixin, config

from btclib.sec_point import point_from_octets

from . import var_bytes
from .alias import BinaryData
from .exceptions import BTClibValueError
from .utils import bytes_from_octets, bytesio_from_binarydata

# default hardening symbol among the possible ones: "h", "H", "'"
_HARDENING = "h"


def _int_from_index_str(s: str) -> int:

    s.strip().lower()
    hardened = False
    if s[-1] in ("'", "h"):
        s = s[:-1]
        hardened = True

    index = int(s)
    if not 0 <= index < 0x80000000:
        raise BTClibValueError(f"invalid index: {index}")
    return index + (0x80000000 if hardened else 0)


def _str_from_index_int(i: int, hardening: str = _HARDENING) -> str:

    if hardening not in ("'", "h", "H"):
        raise BTClibValueError(f"invalid hardening symbol: {hardening}")
    if not 0 <= i <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid index: {i}")
    if i < 0x80000000:
        return str(i)
    return str(i - 0x80000000) + hardening


def _indexes_from_bip32_path_str(der_path: str, skip_m: bool = True) -> List[int]:

    steps = [x.strip().lower() for x in der_path.split("/")]
    if skip_m and steps[0] == "m":
        steps = steps[1:]

    indexes = [_int_from_index_str(s) for s in steps if s != ""]

    if len(indexes) > 255:
        err_msg = f"depth greater than 255: {len(indexes)}"
        raise BTClibValueError(err_msg)
    return indexes


BIP32DerPath = Union[str, Sequence[int], int, bytes]


def indexes_from_bip32_path(der_path: BIP32DerPath) -> List[int]:

    if isinstance(der_path, str):
        return _indexes_from_bip32_path_str(der_path)

    if isinstance(der_path, int):
        return [der_path]

    if isinstance(der_path, bytes):
        if len(der_path) % 4 != 0:
            err_msg = f"index are not a multiple of 4-bytes: {len(der_path)}"
            raise BTClibValueError(err_msg)
        return [
            int.from_bytes(der_path[n : n + 4], byteorder="little", signed=False)
            for n in range(0, len(der_path), 4)
        ]

    # Iterable[int]
    return [int(i) for i in der_path]


def _str_from_bip32_path(der_path: BIP32DerPath, hardening: str = _HARDENING) -> str:
    indexes = indexes_from_bip32_path(der_path)
    return "/".join(_str_from_index_int(i, hardening) for i in indexes)


def str_from_bip32_path(der_path: BIP32DerPath, hardening: str = _HARDENING) -> str:
    result = _str_from_bip32_path(der_path, hardening)
    return "m/" + result if result else "m"


def bytes_from_bip32_path(der_path: BIP32DerPath) -> bytes:
    indexes = indexes_from_bip32_path(der_path)
    result = [i.to_bytes(4, byteorder="little", signed=False) for i in indexes]
    return b"".join(result)


_BIP32KeyOrigin = TypeVar("_BIP32KeyOrigin", bound="BIP32KeyOrigin")


@dataclass(frozen=True)
class BIP32KeyOrigin(DataClassJsonMixin):
    fingerprint: bytes = field(
        metadata=config(
            field_name="master_fingerprint",
            encoder=lambda v: v.hex(),
            decoder=bytes.fromhex,  # use bytes_from_octets(v, 4)
        ),
    )
    der_path: Sequence[int] = field(
        metadata=config(
            field_name="path",
            encoder=str_from_bip32_path,
            decoder=indexes_from_bip32_path,
        ),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def __len__(self):
        return len(self.der_path)

    @property
    def description(self) -> str:

        fingerprint = self.fingerprint.hex()
        der_path = _str_from_bip32_path(self.der_path, hardening=_HARDENING)
        return fingerprint + "/" + der_path if der_path else fingerprint

    def assert_valid(self) -> None:
        if len(self.fingerprint) != 4:
            err_msg = f"invalid master fingerprint length: {len(self.fingerprint)}"
            raise BTClibValueError(err_msg)
        if len(self) > 255:
            raise BTClibValueError(f"invalid der_path size: {len(self.der_path)}")
        if any(not 0 <= i <= 0xFFFFFFFF for i in self.der_path):
            raise BTClibValueError("invalid der_path element")

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        return self.fingerprint + bytes_from_bip32_path(self.der_path)

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyOrigin], data: bytes, check_validity: bool = True
    ) -> _BIP32KeyOrigin:
        "Return a BIP32KeyOrigin by parsing binary data."

        fingerprint = data[:4]
        der_path = indexes_from_bip32_path(data[4:])

        return cls(fingerprint, der_path, check_validity)

    @classmethod
    def from_description(
        cls: Type[_BIP32KeyOrigin], data: str, check_validity: bool = True
    ) -> _BIP32KeyOrigin:
        data = data.strip()
        fingerprint = bytes.fromhex(data[:8])
        der_path = _indexes_from_bip32_path_str(data[9:], skip_m=False)

        return cls(fingerprint, der_path, check_validity)


_BIP32KeyPath = TypeVar("_BIP32KeyPath", bound="BIP32KeyPath")


@dataclass(frozen=True)
class BIP32KeyPath(DataClassJsonMixin):
    pub_key: bytes = field(
        metadata=config(
            encoder=lambda v: v.hex(),
            decoder=bytes.fromhex,
        ),
    )
    key_origin: BIP32KeyOrigin
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def __len__(self):
        return len(self.key_origin)

    def assert_valid(self) -> None:
        # check that self.pub_key is a valid SEC key
        point_from_octets(self.pub_key)
        self.key_origin.assert_valid()

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        bytes_ = var_bytes.serialize(self.pub_key)
        temp = self.key_origin.serialize()
        bytes_ += var_bytes.serialize(temp)
        return var_bytes.serialize(bytes_)

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyPath], data: BinaryData, check_validity: bool = True
    ) -> _BIP32KeyPath:
        "Return a BIP32KeyPath by parsing binary data."

        bytes_ = var_bytes.deserialize(data)
        stream = bytesio_from_binarydata(bytes_)
        pub_key = var_bytes.deserialize(stream)
        der_path_bytes = var_bytes.deserialize(stream)
        key_origin = BIP32KeyOrigin.deserialize(der_path_bytes, check_validity)

        return cls(pub_key, key_origin, check_validity)


def _encode_hd_key_paths(
    dictionary: Dict[bytes, BIP32KeyOrigin]
) -> List[Dict[str, Union[str, BIP32KeyOrigin]]]:
    "Return the json representation of the dataclass element."

    return [
        {
            "pub_key": pub_key.hex(),
            "key_origin": key_origin,
        }
        for pub_key, key_origin in dictionary.items()
    ]


def _decode_hd_key_path(new_element: Dict[str, Any]) -> Tuple[bytes, BIP32KeyOrigin]:
    fingerprint = bytes_from_octets(new_element["key_origin"]["master_fingerprint"], 4)
    der_path = indexes_from_bip32_path(new_element["key_origin"]["path"])
    k = bytes_from_octets(new_element["pub_key"], [33, 65, 78])
    return k, BIP32KeyOrigin(fingerprint, der_path)


def _decode_hd_key_paths(
    list_of_dict: List[Dict[str, Collection[str]]]
) -> Dict[bytes, BIP32KeyOrigin]:
    "Return the dataclass element from its json representation."

    return dict([_decode_hd_key_path(item) for item in list_of_dict])


def _serialize_hd_key_paths(
    type_: bytes, dictionary: Dict[bytes, BIP32KeyOrigin]
) -> bytes:
    "Return the binary representation of the dataclass element."

    if len(type_) != 1:
        raise BTClibValueError("invalid type marker")

    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v.serialize())
            for k, v in sorted(dictionary.items())
        ]
    )


def _assert_valid_hd_key_paths(hd_key_paths: Dict[bytes, BIP32KeyOrigin]) -> None:
    "Raise an exception if the dataclass element is not valid."

    allowed_lengths = (78, 33, 65)
    for pub_key, key_origin in hd_key_paths.items():
        # test vector 6 contains an invalid pubkey
        # point_from_pub_key(pub_key)
        if len(pub_key) not in allowed_lengths:
            err_msg = f"invalid public key length: {len(pub_key)}"
            raise BTClibValueError(err_msg)
        key_origin.assert_valid()


_BIP32KeyPaths = TypeVar("_BIP32KeyPaths", bound="BIP32KeyPaths")


@dataclass
class BIP32KeyPaths(DataClassJsonMixin):
    hd_key_paths: Dict[bytes, BIP32KeyOrigin] = field(
        default_factory=dict,
        metadata=config(
            field_name="bip32_derivs",
            encoder=_encode_hd_key_paths,
            decoder=_decode_hd_key_paths,
        ),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        self.hd_key_paths = dict(sorted(self.hd_key_paths.items()))
        if check_validity:
            self.assert_valid()

    def __len__(self):
        return len(self.hd_key_paths)

    def assert_valid(self) -> None:
        _assert_valid_hd_key_paths(self.hd_key_paths)

    def serialize(self, type_: bytes, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        if len(type_) != 1:
            raise BTClibValueError("invalid type marker")

        return _serialize_hd_key_paths(type_, self.hd_key_paths)

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyPaths],
        data: BinaryData,
        type_: bytes,
        check_validity: bool = True,
    ) -> _BIP32KeyPaths:
        "Return a BIP32KeyPaths by parsing binary data."

        if len(type_) != 1:
            raise BTClibValueError("invalid type marker")

        stream = bytesio_from_binarydata(data)
        hd_key_paths: Dict[bytes, BIP32KeyOrigin] = {}
        while stream.read(1):
            stream.seek(-1, SEEK_CUR)
            prefixed_pubkey = var_bytes.deserialize(stream)
            if prefixed_pubkey and prefixed_pubkey[:1] == type_:
                pubkey = prefixed_pubkey[1:]
                if pubkey in hd_key_paths:
                    raise BTClibValueError("duplicate pubkey")
                key_origin_bytes = var_bytes.deserialize(stream)
                key_origin = BIP32KeyOrigin.deserialize(key_origin_bytes)
                hd_key_paths[pubkey] = key_origin

        return cls(hd_key_paths, check_validity)
