#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Output (PsbtOut) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Type

from btclib.alias import Octets
from btclib.bip32.key_origin import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.psbt.psbt_utils import (
    assert_valid_redeem_script,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    deserialize_bytes,
    encode_dict_bytes_bytes,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
)
from btclib.utils import bytes_from_octets

PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
# 0xfc is reserved for proprietary
# explicit code support for proprietary (and por) is unnecessary
# see https://github.com/bitcoin/bips/pull/1038
# PSBT_OUT_PROPRIETARY = b"\xfc"


@dataclass
class PsbtOut:
    redeem_script: bytes
    witness_script: bytes
    hd_key_paths: HdKeyPaths
    unknown: Dict[bytes, bytes]

    def __init__(
        self,
        redeem_script: Octets = b"",
        witness_script: Octets = b"",
        hd_key_paths: Optional[Mapping[Octets, BIP32KeyOrigin]] = None,
        unknown: Optional[Mapping[Octets, Octets]] = None,
        check_validity: bool = True,
    ) -> None:

        self.redeem_script = bytes_from_octets(redeem_script)
        self.witness_script = bytes_from_octets(witness_script)
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        "Assert logical self-consistency."
        assert_valid_redeem_script(self.redeem_script)
        assert_valid_witness_script(self.witness_script)
        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_unknown(self.unknown)

    def to_dict(self, check_validity: bool = True) -> Dict[str, Any]:

        if check_validity:
            self.assert_valid()

        return {
            "redeem_script": self.redeem_script.hex(),  # TODO make it { "asm": "", "hex": "" }
            "witness_script": self.witness_script.hex(),  # TODO make it { "asm": "", "hex": "" }
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
        }

    @classmethod
    def from_dict(
        cls: Type["PsbtOut"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "PsbtOut":

        return cls(
            dict_["redeem_script"],
            dict_["witness_script"],
            # FIXME
            decode_from_bip32_derivs(dict_["bip32_derivs"]),  # type: ignore
            dict_["unknown"],
            check_validity,
        )

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        psbt_out_bin: List[bytes] = []

        if self.redeem_script:
            psbt_out_bin.append(
                serialize_bytes(PSBT_OUT_REDEEM_SCRIPT, self.redeem_script)
            )

        if self.witness_script:
            psbt_out_bin.append(
                serialize_bytes(PSBT_OUT_WITNESS_SCRIPT, self.witness_script)
            )

        if self.hd_key_paths:
            psbt_out_bin.append(
                serialize_hd_key_paths(PSBT_OUT_BIP32_DERIVATION, self.hd_key_paths)
            )

        if self.unknown:
            psbt_out_bin.append(serialize_dict_bytes_bytes(b"", self.unknown))

        return b"".join(psbt_out_bin)

    @classmethod
    def parse(
        cls: Type["PsbtOut"],
        output_map: Mapping[bytes, bytes],
        check_validity: bool = True,
    ) -> "PsbtOut":
        "Return a PsbtOut by parsing binary data."

        # FIX parse must use BinaryData

        redeem_script = b""
        witness_script = b""
        hd_key_paths: Dict[Octets, BIP32KeyOrigin] = {}
        unknown: Dict[Octets, Octets] = {}

        for k, v in output_map.items():
            if k[:1] == PSBT_OUT_REDEEM_SCRIPT:
                redeem_script = deserialize_bytes(k, v, "redeem script")
            elif k[:1] == PSBT_OUT_WITNESS_SCRIPT:
                witness_script = deserialize_bytes(k, v, "witness script")
            elif k[:1] == PSBT_OUT_BIP32_DERIVATION:
                #  parse just one hd key path at time :-(
                hd_key_paths[k[1:]] = BIP32KeyOrigin.parse(v)
            else:  # unknown
                unknown[k] = v

        return cls(
            redeem_script,
            witness_script,
            hd_key_paths,
            unknown,
            check_validity,
        )
