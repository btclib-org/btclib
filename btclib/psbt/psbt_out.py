#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Partially Signed Bitcoin Transaction Output (PsbtOut).

Dataclass and functions.
https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Mapping, Sequence, Tuple, cast

from btclib.alias import Octets
from btclib.bip32 import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.psbt.psbt_utils import (
    assert_valid_redeem_script,
    assert_valid_taproot_bip32_derivation,
    assert_valid_taproot_internal_key,
    assert_valid_taproot_tree,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    decode_taproot_bip32,
    decode_taproot_tree,
    deserialize_bytes,
    encode_dict_bytes_bytes,
    encode_taproot_tree,
    parse_taproot_bip32,
    parse_taproot_tree,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
    serialize_taproot_bip32,
    serialize_taproot_tree,
    taproot_bip32_from_dict,
    taproot_bip32_to_dict,
)
from btclib.utils import bytes_from_octets

PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
PSBT_OUT_TAP_INTERNAL_KEY = b"\x05"
PSBT_OUT_TAP_TREE = b"\x06"
PSBT_OUT_TAP_BIP32_DERIVATION = b"\x07"
# 0xfc is reserved for proprietary
# explicit code support for proprietary (and por) is unnecessary
# see https://github.com/bitcoin/bips/pull/1038
# PSBT_OUT_PROPRIETARY = b"\xfc"


@dataclass
class PsbtOut:
    redeem_script: bytes
    witness_script: bytes
    hd_key_paths: HdKeyPaths
    taproot_internal_key: bytes
    taproot_tree: list[tuple[int, int, bytes]]
    taproot_hd_key_paths: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]
    unknown: dict[bytes, bytes]

    def __init__(
        self,
        redeem_script: Octets = b"",
        witness_script: Octets = b"",
        hd_key_paths: Mapping[Octets, BIP32KeyOrigin] | None = None,
        taproot_internal_key: Octets = b"",
        taproot_tree: Sequence[tuple[int, int, Octets]] | None = None,
        taproot_hd_key_paths: Mapping[Octets, tuple[list[bytes], BIP32KeyOrigin]]
        | None = None,
        unknown: Mapping[Octets, Octets] | None = None,
        check_validity: bool = True,
    ) -> None:
        self.redeem_script = bytes_from_octets(redeem_script)
        self.witness_script = bytes_from_octets(witness_script)
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.taproot_internal_key = bytes_from_octets(taproot_internal_key)
        self.taproot_tree = decode_taproot_tree(taproot_tree)
        self.taproot_hd_key_paths = decode_taproot_bip32(taproot_hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency."""
        assert_valid_redeem_script(self.redeem_script)
        assert_valid_witness_script(self.witness_script)
        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_taproot_internal_key(self.taproot_internal_key)
        assert_valid_taproot_tree(self.taproot_tree)
        assert_valid_taproot_bip32_derivation(self.taproot_hd_key_paths)
        assert_valid_unknown(self.unknown)

    def to_dict(self, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        return {
            # TODO make it { "asm": "", "hex": "" }
            "redeem_script": self.redeem_script.hex(),
            # TODO make it { "asm": "", "hex": "" }
            "witness_script": self.witness_script.hex(),
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "taproot_internal_key": self.taproot_internal_key.hex(),
            "taproot_tree": encode_taproot_tree(self.taproot_tree),
            "taproot_hd_key_paths": taproot_bip32_to_dict(self.taproot_hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
        }

    @classmethod
    def from_dict(
        cls: type[PsbtOut], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> PsbtOut:
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            decode_from_bip32_derivs(dict_["bip32_derivs"]),
        )
        taproot_hd_key_paths = cast(
            Mapping[Octets, Tuple[List[bytes], BIP32KeyOrigin]],
            taproot_bip32_from_dict(dict_["taproot_hd_key_paths"]),
        )
        return cls(
            dict_["redeem_script"],
            dict_["witness_script"],
            hd_key_paths,
            dict_["taproot_internal_key"],
            dict_["taproot_tree"],
            taproot_hd_key_paths,
            dict_["unknown"],
            check_validity,
        )

    def serialize(self, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        psbt_out_bin: list[bytes] = []

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

        if self.taproot_internal_key:
            psbt_out_bin.append(
                serialize_bytes(PSBT_OUT_TAP_INTERNAL_KEY, self.taproot_internal_key)
            )

        if self.taproot_tree:
            psbt_out_bin.append(
                serialize_taproot_tree(PSBT_OUT_TAP_TREE, self.taproot_tree)
            )

        if self.taproot_hd_key_paths:
            psbt_out_bin.append(
                serialize_taproot_bip32(
                    PSBT_OUT_TAP_BIP32_DERIVATION, self.taproot_hd_key_paths
                )
            )

        if self.unknown:
            psbt_out_bin.append(serialize_dict_bytes_bytes(b"", self.unknown))

        return b"".join(psbt_out_bin)

    @classmethod
    def parse(
        cls: type[PsbtOut],
        output_map: Mapping[bytes, bytes],
        check_validity: bool = True,
    ) -> PsbtOut:
        """Return a PsbtOut by parsing binary data."""
        # FIX parse must use BinaryData
        redeem_script = b""
        witness_script = b""
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        taproot_internal_key = b""
        taproot_tree: list[tuple[int, int, bytes]] = []
        taproot_hd_key_paths: dict[Octets, tuple[list[bytes], BIP32KeyOrigin]] = {}
        unknown: dict[Octets, Octets] = {}

        for k, v in output_map.items():
            if k[:1] == PSBT_OUT_REDEEM_SCRIPT:
                redeem_script = deserialize_bytes(k, v, "redeem script")
            elif k[:1] == PSBT_OUT_WITNESS_SCRIPT:
                witness_script = deserialize_bytes(k, v, "witness script")
            elif k[:1] == PSBT_OUT_BIP32_DERIVATION:
                #  parse just one hd key path at time :-(
                hd_key_paths[k[1:]] = BIP32KeyOrigin.parse(v)
            elif k[:1] == PSBT_OUT_TAP_INTERNAL_KEY:
                taproot_internal_key = deserialize_bytes(k, v, "taproot internal key")
            elif k[:1] == PSBT_OUT_TAP_TREE:
                taproot_tree = parse_taproot_tree(v)
            elif k[:1] == PSBT_OUT_TAP_BIP32_DERIVATION:
                #  parse just one hd key path at time :-(
                taproot_hd_key_paths[k[1:]] = parse_taproot_bip32(v)
            else:  # unknown
                unknown[k] = v

        return cls(
            redeem_script,
            witness_script,
            hd_key_paths,
            taproot_internal_key,
            taproot_tree,
            taproot_hd_key_paths,
            unknown,
            check_validity,
        )
