#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Output.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from dataclasses import dataclass, field
from typing import Dict, List, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import varbytes, varint
from .bip32 import (
    bytes_from_bip32_path,
    indexes_from_bip32_path,
    str_from_bip32_path,
)
from .exceptions import BTClibValueError


def encode_dict_bytes_bytes(d: Dict[bytes, bytes]) -> Dict[str, str]:
    return {k.hex(): v.hex() for k, v in d.items()}


def decode_dict_bytes_bytes(d: Dict[str, str]) -> Dict[bytes, bytes]:
    return {bytes.fromhex(k): bytes.fromhex(v) for k, v in d.items()}


def encode_bip32_derivs(d: Dict[bytes, bytes]) -> List[Dict[str, str]]:

    result: List[Dict[str, str]] = []
    for k, v in d.items():
        d_str_str: Dict[str, str] = {
            "pubkey": k.hex(),
            "master_fingerprint": v[:4].hex(),
            "path": str_from_bip32_path(v[4:], "little"),
        }
        result.append(d_str_str)
    return result


def decode_bip32_derivs(list_of_dict: List[Dict[str, str]]) -> Dict[bytes, bytes]:

    d2: Dict[bytes, bytes] = {}
    for d in list_of_dict:
        v = bytes.fromhex(d["master_fingerprint"])
        v += bytes_from_bip32_path(d["path"], "little")
        d2[bytes.fromhex(d["pubkey"])] = v
    return d2


def _assert_valid_bip32_derivs(bip32_derivs: Dict[bytes, bytes]) -> None:

    for _, v in bip32_derivs.items():
        # FIXME
        # point_from_pubkey(k)
        indexes_from_bip32_path(v, "little")


def _deserialize_proprietary(key: bytes, value: bytes) -> Dict[int, Dict[str, str]]:

    out: Dict[int, Dict[str, str]] = {}
    prefix = varint.decode(key[1:])
    if prefix not in out:
        out[prefix] = {}
    key = key[1 + len(varint.encode(prefix)) :]
    out[prefix][key.hex()] = value.hex()
    return out


def _serialize_proprietary(
    proprietary: Dict[int, Dict[str, str]], marker: bytes
) -> bytes:

    out = b""
    for (owner, dictionary) in proprietary.items():
        for key_p, value_p in dictionary.items():
            out += varbytes.encode(marker + varint.encode(owner) + bytes.fromhex(key_p))
            out += varbytes.encode(value_p)
    return out


def _assert_valid_proprietary(proprietary: Dict[int, Dict[str, str]]) -> None:

    for key, value in proprietary.items():
        if not isinstance(key, int):
            raise BTClibValueError("invalid key in proprietary")
        for inner_key, inner_value in value.items():
            if not bytes.fromhex(inner_key):
                raise BTClibValueError("invalid inner key in proprietary")
            if not bytes.fromhex(inner_value):
                raise BTClibValueError("invalid inner value in proprietary")


def _serialize_dict_bytes_bytes(d: Dict[bytes, bytes], m=bytes) -> bytes:

    return b"".join([varbytes.encode(m + k) + varbytes.encode(v) for k, v in d.items()])


def _assert_valid_unknown(data: Dict[bytes, bytes]) -> None:

    for key, value in data.items():
        if not isinstance(key, bytes):
            raise BTClibValueError("invalid key in unknown")
        if not isinstance(value, bytes):
            raise BTClibValueError("invalid value in unknown")


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
    bip32_derivs: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(encoder=encode_bip32_derivs, decoder=decode_bip32_derivs),
    )
    proprietary: Dict[int, Dict[str, str]] = field(default_factory=dict)
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=encode_dict_bytes_bytes, decoder=decode_dict_bytes_bytes
        ),
    )

    @classmethod
    def deserialize(
        cls: Type[_PsbtOut], output_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtOut:
        out = cls()
        for key, value in output_map.items():
            if key[0:1] == PSBT_OUT_REDEEM_SCRIPT:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_OUT_REDEEM_SCRIPT key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.redeem_script = value
            elif key[0:1] == PSBT_OUT_WITNESS_SCRIPT:
                if len(key) != 1:
                    err_msg = f"invalid PSBT_OUT_WITNESS_SCRIPT key length: {len(key)}"
                    raise BTClibValueError(err_msg)
                out.witness_script = value
            elif key[0:1] == PSBT_OUT_BIP32_DERIVATION:
                if len(key) not in (34, 66):
                    err_msg = "invalid PSBT_OUT_BIP32_DERIVATION pubkey length"
                    err_msg += f": {len(key)-1} instead of (33, 65)"
                    raise BTClibValueError(err_msg)
                out.bip32_derivs[key[1:]] = value
            elif key[0:1] == PSBT_OUT_PROPRIETARY:
                out.proprietary = _deserialize_proprietary(key, value)
            else:  # unknown
                out.unknown[key] = value

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""

        if self.redeem_script:
            out += b"\x01" + PSBT_OUT_REDEEM_SCRIPT
            out += varbytes.encode(self.redeem_script)
        if self.witness_script:
            out += b"\x01" + PSBT_OUT_WITNESS_SCRIPT
            out += varbytes.encode(self.witness_script)
        if self.bip32_derivs:
            out += _serialize_dict_bytes_bytes(
                self.bip32_derivs, PSBT_OUT_BIP32_DERIVATION
            )
        if self.proprietary:
            out += _serialize_proprietary(self.proprietary, PSBT_OUT_PROPRIETARY)
        if self.unknown:
            out += _serialize_dict_bytes_bytes(self.unknown, b"")

        return out

    def assert_valid(self) -> None:
        _assert_valid_bip32_derivs(self.bip32_derivs)
        _assert_valid_proprietary(self.proprietary)
        _assert_valid_unknown(self.unknown)
