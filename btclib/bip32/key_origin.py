#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BIP32 key origin."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping, Sequence

from btclib.alias import Octets
from btclib.bip32.der_path import (
    BIP32DerPath,
    bytes_from_bip32_path,
    indexes_from_bip32_path,
    str_from_bip32_path,
)
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets


@dataclass(frozen=True)
class BIP32KeyOrigin:
    master_fingerprint: bytes
    der_path: Sequence[int]

    @property
    def description(self) -> str:
        return str_from_bip32_path(self.der_path, self.master_fingerprint)

    def __init__(
        self,
        master_fingerprint: Octets,
        der_path: BIP32DerPath,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(
            self, "master_fingerprint", bytes_from_octets(master_fingerprint)
        )
        object.__setattr__(self, "der_path", indexes_from_bip32_path(der_path))

        if check_validity:
            self.assert_valid()

    def __len__(self) -> int:
        return len(self.der_path)

    def assert_valid(self) -> None:
        if len(self.master_fingerprint) != 4:
            err_msg = "invalid master fingerprint length: "
            err_msg += f"{len(self.master_fingerprint)}"
            raise BTClibValueError(err_msg)
        if len(self) > 255:
            raise BTClibValueError(f"invalid der_path size: {len(self.der_path)}")
        if any(not 0 <= i <= 0xFFFFFFFF for i in self.der_path):
            raise BTClibValueError("invalid der_path element")

    def to_dict(self, check_validity: bool = True) -> dict[str, str]:
        if check_validity:
            self.assert_valid()

        return {
            "master_fingerprint": self.master_fingerprint.hex(),
            "path": str_from_bip32_path(self.der_path),
        }

    @classmethod
    def from_dict(
        cls: type[BIP32KeyOrigin],
        dict_: Mapping[str, str],
        check_validity: bool = True,
    ) -> BIP32KeyOrigin:
        return cls(
            dict_["master_fingerprint"],
            dict_["path"],
            check_validity,
        )

    def serialize(self, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        return self.master_fingerprint + bytes_from_bip32_path(self.der_path)

    @classmethod
    def parse(
        cls: type[BIP32KeyOrigin], data: Octets, check_validity: bool = True
    ) -> BIP32KeyOrigin:
        """Return a BIP32KeyOrigin by parsing binary data."""
        data = bytes_from_octets(data)
        master_fingerprint = data[:4]
        der_path = indexes_from_bip32_path(data[4:])

        return cls(master_fingerprint, der_path, check_validity)

    @classmethod
    def from_description(
        cls: type[BIP32KeyOrigin], data: str, check_validity: bool = True
    ) -> BIP32KeyOrigin:
        data = data.strip()
        return cls(data[:8], data[9:], check_validity)

    def __hash__(self: BIP32KeyOrigin) -> int:
        return hash(self.serialize())


# MutableMapping[pub_key, [fingerprint, derivation_path]]
HdKeyPaths = MutableMapping[bytes, BIP32KeyOrigin]


def assert_valid_hd_key_paths(hd_key_paths: Mapping[bytes, BIP32KeyOrigin]) -> None:
    """Raise an exception if the dataclass element is not valid."""
    if len(hd_key_paths.values()) > len(
        set(map(lambda der_path: der_path.serialize(), hd_key_paths.values()))
    ):
        raise BTClibValueError("Duplicated key origin values in hd_key_paths")
    for pub_key, key_origin in hd_key_paths.items():
        # test vector 6 contains an invalid pub_key
        # point_from_pub_key(pub_key)
        if len(pub_key) not in (78, 33, 65):
            err_msg = f"invalid public key length: {len(pub_key)}"
            raise BTClibValueError(err_msg)
        key_origin.assert_valid()


def decode_hd_key_paths(map_: Mapping[Octets, BIP32KeyOrigin] | None) -> HdKeyPaths:
    """Return the dataclass element from its json representation."""
    hd_key_paths = {bytes_from_octets(k): v for k, v in map_.items()} if map_ else {}
    return dict(sorted(hd_key_paths.items()))


_BIP32Deriv = Mapping[str, str]


def encode_to_bip32_derivs(
    hd_key_paths: Mapping[bytes, BIP32KeyOrigin]
) -> list[_BIP32Deriv]:
    """Return the json representation of the dataclass element."""
    return [
        {
            "pub_key": pub_key.hex(),
            "master_fingerprint": key_origin.master_fingerprint.hex(),
            "path": str_from_bip32_path(key_origin.der_path),
        }
        for pub_key, key_origin in sorted(hd_key_paths.items())
    ]


def _decode_from_bip32_deriv(
    bip32_deriv: Mapping[str, str]
) -> tuple[bytes, BIP32KeyOrigin]:
    # FIXME remove size checks to allow
    # the instantiation of invalid master_fingerprint and pub_key
    master_fingerprint = bytes_from_octets(bip32_deriv["master_fingerprint"], 4)
    der_path = indexes_from_bip32_path(bip32_deriv["path"])
    key_origin = BIP32KeyOrigin(master_fingerprint, der_path)
    return bytes_from_octets(bip32_deriv["pub_key"]), key_origin


def decode_from_bip32_derivs(
    bip32_derivs: Sequence[Mapping[str, str]],
) -> HdKeyPaths:
    """Return the dataclass element from its json representation."""
    return dict(sorted([_decode_from_bip32_deriv(item) for item in bip32_derivs]))
