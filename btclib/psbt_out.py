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

from dataclasses import InitVar, dataclass, field
from typing import Dict, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import var_bytes
from .bip32_path import (
    BIP32KeyOrigin,
    _assert_valid_hd_key_paths,
    _decode_hd_key_paths,
    _encode_hd_key_paths,
    _serialize_hd_key_paths,
)
from .exceptions import BTClibTypeError, BTClibValueError

# from .to_pub_key import point_from_pub_key


def _encode_dict_bytes_bytes(dictionary: Dict[bytes, bytes]) -> Dict[str, str]:
    "Return the json representation of the dataclass element."
    return {k.hex(): v.hex() for k, v in dictionary.items()}


def _decode_dict_bytes_bytes(dictionary: Dict[str, str]) -> Dict[bytes, bytes]:
    "Return the dataclass element from its json representation."
    return {bytes.fromhex(k): bytes.fromhex(v) for k, v in dictionary.items()}


def _serialize_dict_bytes_bytes(type_: bytes, dictionary: Dict[bytes, bytes]) -> bytes:
    "Return the binary representation of the dataclass element."

    return b"".join(
        [
            var_bytes.serialize(type_ + k) + var_bytes.serialize(v)
            for k, v in sorted(dictionary.items())
        ]
    )


def _serialize_bytes(type_: bytes, value: bytes) -> bytes:
    "Return the binary representation of the dataclass element."
    return var_bytes.serialize(type_) + var_bytes.serialize(value)


def _deserialize_bytes(k: bytes, v: bytes, type_: str) -> bytes:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return v


def _assert_valid_redeem_script(redeem_script: bytes) -> None:
    "Raise an exception if the dataclass element is not valid."
    if not isinstance(redeem_script, bytes):
        raise BTClibTypeError("invalid redeem script")


def _assert_valid_witness_script(witness_script: bytes) -> None:
    "Raise an exception if the dataclass element is not valid."
    if not isinstance(witness_script, bytes):
        raise BTClibTypeError("invalid witness script")


def _assert_valid_unknown(data: Dict[bytes, bytes]) -> None:
    "Raise an exception if the dataclass element is not valid."

    for key, value in data.items():
        if not isinstance(key, bytes):
            raise BTClibTypeError("invalid key in unknown")
        if not isinstance(value, bytes):
            raise BTClibTypeError("invalid value in unknown")


PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
# 0xfc is reserved for proprietary
# explicit code support for proprietary (and por) is unnecessary
# see https://github.com/bitcoin/bips/pull/1038
# PSBT_OUT_PROPRIETARY = b"\xfc"


_PsbtOut = TypeVar("_PsbtOut", bound="PsbtOut")


@dataclass
class PsbtOut(DataClassJsonMixin):
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    hd_key_paths: Dict[bytes, BIP32KeyOrigin] = field(
        default_factory=dict,
        metadata=config(
            field_name="bip32_derivs",
            encoder=_encode_hd_key_paths,
            decoder=_decode_hd_key_paths,
        ),
    )
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=_encode_dict_bytes_bytes, decoder=_decode_dict_bytes_bytes
        ),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        self.unknown = dict(sorted(self.unknown.items()))
        self.hd_key_paths = dict(sorted(self.hd_key_paths.items()))
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        "Assert logical self-consistency."
        _assert_valid_redeem_script(self.redeem_script)
        _assert_valid_witness_script(self.witness_script)
        _assert_valid_hd_key_paths(self.hd_key_paths)
        _assert_valid_unknown(self.unknown)

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        psbt_out_bin = b""

        if self.redeem_script:
            psbt_out_bin += _serialize_bytes(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)

        if self.witness_script:
            psbt_out_bin += _serialize_bytes(
                PSBT_OUT_WITNESS_SCRIPT, self.witness_script
            )

        if self.hd_key_paths:
            psbt_out_bin += _serialize_hd_key_paths(
                PSBT_OUT_BIP32_DERIVATION, self.hd_key_paths
            )

        if self.unknown:
            psbt_out_bin += _serialize_dict_bytes_bytes(b"", self.unknown)

        return psbt_out_bin

    @classmethod
    def deserialize(
        cls: Type[_PsbtOut], output_map: Dict[bytes, bytes], check_validity: bool = True
    ) -> _PsbtOut:
        "Return a PsbtOut by parsing binary data."

        # FIX deserialize must use BinaryData

        redeem_script = b""
        witness_script = b""
        hd_key_paths: Dict[bytes, BIP32KeyOrigin] = {}
        unknown: Dict[bytes, bytes] = {}

        for k, v in output_map.items():
            if k[:1] == PSBT_OUT_REDEEM_SCRIPT:
                if redeem_script:
                    raise BTClibValueError("duplicate PsbtOut redeem_script")
                redeem_script = _deserialize_bytes(k, v, "redeem script")
            elif k[:1] == PSBT_OUT_WITNESS_SCRIPT:
                if witness_script:
                    raise BTClibValueError("duplicate PsbtOut witness_script")
                witness_script = _deserialize_bytes(k, v, "witness script")
            elif k[:1] == PSBT_OUT_BIP32_DERIVATION:
                #  deserialize just one hd key path at time :-(
                if k[1:] in hd_key_paths:
                    raise BTClibValueError("duplicate pub_key in PsbtOut hd_key_path")
                hd_key_paths[k[1:]] = BIP32KeyOrigin.deserialize(v)
            else:  # unknown
                if k in unknown:
                    raise BTClibValueError("duplicate PsbtOut unknown")
                unknown[k] = v

        return cls(
            redeem_script,
            witness_script,
            hd_key_paths,
            unknown,
            check_validity,
        )
