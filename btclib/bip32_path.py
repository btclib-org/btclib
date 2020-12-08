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
from typing import List, Sequence, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin, config

from . import var_bytes
from .alias import BinaryData
from .exceptions import BTClibValueError
from .sec_point import point_from_octets
from .utils import bytesio_from_binarydata

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
            decoder=bytes.fromhex,
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

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        return self.fingerprint + bytes_from_bip32_path(self.der_path)

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyOrigin], data: bytes, assert_valid: bool = True
    ) -> _BIP32KeyOrigin:
        "Return a BIP32KeyOrigin by parsing binary data."

        fingerprint = data[:4]
        der_path = indexes_from_bip32_path(data[4:])

        return cls(fingerprint, der_path, check_validity=assert_valid)

    @classmethod
    def from_description(
        cls: Type[_BIP32KeyOrigin], data: str, assert_valid: bool = True
    ) -> _BIP32KeyOrigin:
        data = data.strip()
        fingerprint = bytes.fromhex(data[:8])
        der_path = _indexes_from_bip32_path_str(data[9:], skip_m=False)

        return cls(fingerprint, der_path, assert_valid)


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

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        bytes_ = var_bytes.serialize(self.pub_key)
        temp = self.key_origin.serialize()
        bytes_ += var_bytes.serialize(temp)
        return var_bytes.serialize(bytes_)

    @classmethod
    def deserialize(
        cls: Type[_BIP32KeyPath], data: BinaryData, assert_valid: bool = True
    ) -> _BIP32KeyPath:
        "Return a BIP32KeyPath by parsing binary data."

        bytes_ = var_bytes.deserialize(data)
        stream = bytesio_from_binarydata(bytes_)
        pub_key = var_bytes.deserialize(stream)
        der_path_bytes = var_bytes.deserialize(stream)
        key_origin = BIP32KeyOrigin.deserialize(
            der_path_bytes, assert_valid=assert_valid
        )

        return cls(pub_key, key_origin, check_validity=assert_valid)