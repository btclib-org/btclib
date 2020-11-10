#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Output.

https://en.bitcoin.it/wiki/BIP_0174
"""

from dataclasses import dataclass, field
from typing import Dict, Tuple, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import varint
from .alias import Octets, String
from .bip32 import (
    BIP32KeyData,
    BIP32Path,
    bytes_from_bip32_path,
    str_from_bip32_path,
)
from .secpoint import bytes_from_point
from .to_pubkey import PubKey
from .utils import bytes_from_octets, token_or_string_to_hex_string


def _pubkey_to_hex_string(pubkey: PubKey) -> str:
    if isinstance(pubkey, tuple):
        return bytes_from_point(pubkey).hex()
    elif isinstance(pubkey, BIP32KeyData):
        return (pubkey.key).hex()
    elif isinstance(pubkey, str):
        return pubkey

    return pubkey.hex()


@dataclass
class HdKeyPaths(DataClassJsonMixin):
    hd_keypaths: Dict[str, Dict[str, str]] = field(default_factory=dict)

    def add_hd_keypath(self, key: PubKey, fingerprint: Octets, path: BIP32Path) -> None:

        key_str = _pubkey_to_hex_string(key)
        # assert key_str == pubkeyinfo_from_key(key)[0].hex()

        fingerprint_str = bytes_from_octets(fingerprint, 4).hex()
        path_str = str_from_bip32_path(path, "little")

        self.hd_keypaths[key_str] = {
            "fingerprint": fingerprint_str,
            "derivation_path": path_str,
        }

    def get_hd_keypath(self, key: PubKey) -> Tuple[str, str]:

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        entry = self.hd_keypaths[key_str]
        return entry["fingerprint"], entry["derivation_path"]

    def assert_valid(self) -> None:
        pass


PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
PSBT_OUT_PROPRIETARY = b"\xfc"

_PsbtOut = TypeVar("_PsbtOut", bound="PsbtOut")


@dataclass
class PsbtOut(DataClassJsonMixin):
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    hd_keypaths: HdKeyPaths = field(default_factory=HdKeyPaths)
    proprietary: Dict[int, Dict[str, bytes]] = field(default_factory=dict)
    unknown: Dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def deserialize(
        cls: Type[_PsbtOut], output_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtOut:
        out = cls()
        for key, value in output_map.items():
            if key[0:1] == PSBT_OUT_REDEEM_SCRIPT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.redeem_script == b"", "duplicated redeem_script"
                out.redeem_script = value
            elif key[0:1] == PSBT_OUT_WITNESS_SCRIPT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.witness_script == b"", "duplicated witness_script"
                out.witness_script = value
            elif key[0:1] == PSBT_OUT_BIP32_DERIVATION:
                assert len(key) == 33 + 1, f"invalid key length: {len(key)}"
                # TODO: assert not duplicated?
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0:1] == PSBT_OUT_PROPRIETARY:
                # TODO: assert not duplicated?
                prefix = varint.decode(key[1:])
                if prefix not in out.proprietary.keys():
                    out.proprietary[prefix] = {}
                key = key[1 + len(varint.encode(prefix)) :]
                out.proprietary[prefix][key.hex()] = value
            else:  # unknown keys
                # TODO: assert not duplicated?
                out.unknown[key.hex()] = value

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""

        if self.redeem_script:
            out += b"\x01" + PSBT_OUT_REDEEM_SCRIPT
            out += varint.encode(len(self.redeem_script)) + self.redeem_script
        if self.witness_script:
            out += b"\x01" + PSBT_OUT_WITNESS_SCRIPT
            out += varint.encode(len(self.witness_script)) + self.witness_script
        if self.hd_keypaths:
            for pubkey, hd_keypath in self.hd_keypaths.hd_keypaths.items():
                pubkey_bytes = PSBT_OUT_BIP32_DERIVATION + bytes.fromhex(pubkey)
                out += varint.encode(len(pubkey_bytes)) + pubkey_bytes
                keypath = bytes.fromhex(hd_keypath["fingerprint"])
                keypath += bytes_from_bip32_path(
                    hd_keypath["derivation_path"], "little"
                )
                out += varint.encode(len(keypath)) + keypath
        if self.proprietary:
            for (owner, dictionary) in self.proprietary.items():
                for key, value in dictionary.items():
                    key_bytes = (
                        PSBT_OUT_PROPRIETARY + varint.encode(owner) + bytes.fromhex(key)
                    )
                    out += varint.encode(len(key_bytes)) + key_bytes
                    out += varint.encode(len(value)) + value
        if self.unknown:
            for key2, value2 in self.unknown.items():
                out += varint.encode(len(key2) // 2) + bytes.fromhex(key2)
                out += varint.encode(len(value2)) + value2

        return out

    def assert_valid(self) -> None:
        pass

    def add_unknown(self, key: String, val: Octets):

        key_str = token_or_string_to_hex_string(key)

        self.unknown[key_str] = bytes_from_octets(val)

    def get_unknown(self, key: String) -> bytes:

        key_str = token_or_string_to_hex_string(key)

        return self.unknown[key_str]
