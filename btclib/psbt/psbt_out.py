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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from btclib.alias import BinaryData, Octets
from btclib.amount import valid_sats_amount
from btclib.bip32 import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.psbt.psbt_utils import (
    PSBT_SEPARATOR,
    assert_not_a_v2_field,
    assert_valid_redeem_script,
    assert_valid_taproot_bip32_derivation,
    assert_valid_taproot_internal_key,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    decode_taproot_bip32,
    decode_taproot_tree,
    deserialize_bytes,
    deserialize_map,
    deserialize_sized_int,
    encode_dict_bytes_bytes,
    encode_taproot_tree,
    parse_taproot_bip32,
    parse_taproot_tree,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
    serialize_sized_int,
    serialize_taproot_bip32,
    serialize_taproot_tree,
    taproot_bip32_from_dict,
    taproot_bip32_to_dict,
)
from btclib.script import script_from_dict, script_to_dict
from btclib.utils import bytes_from_octets

PSBT_OUT_REDEEM_SCRIPT = b"\x00"
PSBT_OUT_WITNESS_SCRIPT = b"\x01"
PSBT_OUT_BIP32_DERIVATION = b"\x02"
PSBT_OUT_AMOUNT = b"\x03"
PSBT_OUT_SCRIPT = b"\x04"
PSBT_OUT_TAP_INTERNAL_KEY = b"\x05"
PSBT_OUT_TAP_TREE = b"\x06"
PSBT_OUT_TAP_BIP32_DERIVATION = b"\x07"

# the output fields BIP370 defines, which a version 0 output must not
# carry: the amount and the script_pub_key, which a v0 output reads from
# the unsigned transaction. See psbt_utils.assert_not_a_v2_field
_V2_FIELDS = {
    PSBT_OUT_AMOUNT: "PSBT_OUT_AMOUNT",
    PSBT_OUT_SCRIPT: "PSBT_OUT_SCRIPT",
}
# 0xfc is reserved for proprietary use, and needs no constant of its own:
# explicit support for proprietary (and por) is unnecessary,
# see https://github.com/bitcoin/bips/pull/1038


def _serialized_v2_fields(psbt_out: PsbtOut) -> list[bytes]:
    """Return the two BIP370 fields of an output map, in type-byte order.

    `is not None` for the amount, an output paying zero satoshi being an
    output; truthiness for the script, an empty one being what an output
    that does not carry the field has -- the two are indistinguishable
    here, and a psbt saying an output pays to no script at all is not
    one a Constructor writes.
    """
    serialized: list[bytes] = []
    if psbt_out.amount is not None:
        serialized.append(
            serialize_sized_int(PSBT_OUT_AMOUNT, psbt_out.amount, 8, signed=True)
        )
    if psbt_out.script_pub_key:
        serialized.append(serialize_bytes(PSBT_OUT_SCRIPT, psbt_out.script_pub_key))
    return serialized


@dataclass
class PsbtOut:
    redeem_script: bytes
    witness_script: bytes
    hd_key_paths: HdKeyPaths
    taproot_internal_key: bytes
    taproot_tree: list[tuple[int, int, bytes]]
    taproot_hd_key_paths: dict[bytes, tuple[list[bytes], BIP32KeyOrigin]]
    unknown: dict[bytes, bytes]
    amount: int | None
    script_pub_key: bytes

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
        amount: int | None = None,
        script_pub_key: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> None:
        self.redeem_script = bytes_from_octets(redeem_script)
        self.witness_script = bytes_from_octets(witness_script)
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.taproot_internal_key = bytes_from_octets(taproot_internal_key)
        self.taproot_tree = decode_taproot_tree(taproot_tree)
        self.taproot_hd_key_paths = decode_taproot_bip32(taproot_hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))
        self.amount = amount
        self.script_pub_key = bytes_from_octets(script_pub_key)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency.

        The two BIP370 fields are checked for what they hold and not for
        whether they are there: which of them an output must carry is the
        psbt's version, which an output on its own does not know, so
        Psbt.assert_valid asks that question (PsbtIn.assert_valid says
        the same of the five fields of an input).
        """
        if self.amount is not None:
            # BIP370 spells the amount as a signed 64-bit integer, as the
            # transaction does, and valid_sats_amount is the range every
            # other amount in btclib is held to: negative is not an
            # amount, and above MAX_MONEY is not one either
            valid_sats_amount(self.amount)

        assert_valid_redeem_script(self.redeem_script)
        assert_valid_witness_script(self.witness_script)
        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_taproot_internal_key(self.taproot_internal_key)
        assert_valid_taproot_bip32_derivation(self.taproot_hd_key_paths)
        assert_valid_unknown(self.unknown)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        return {
            "redeem_script": script_to_dict(self.redeem_script),
            "witness_script": script_to_dict(self.witness_script),
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "taproot_internal_key": self.taproot_internal_key.hex(),
            "taproot_tree": encode_taproot_tree(self.taproot_tree),
            "taproot_hd_key_paths": taproot_bip32_to_dict(self.taproot_hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
            "amount": self.amount,
            "script_pub_key": script_to_dict(self.script_pub_key),
        }

    @classmethod
    def from_dict(
        cls: type[PsbtOut], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> PsbtOut:
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            decode_from_bip32_derivs(dict_["bip32_derivs"]),
        )
        taproot_hd_key_paths = cast(
            Mapping[Octets, tuple[list[bytes], BIP32KeyOrigin]],
            taproot_bip32_from_dict(dict_["taproot_hd_key_paths"]),
        )
        return cls(
            script_from_dict(dict_["redeem_script"]),
            script_from_dict(dict_["witness_script"]),
            hd_key_paths,
            dict_["taproot_internal_key"],
            dict_["taproot_tree"],
            taproot_hd_key_paths,
            dict_["unknown"],
            dict_["amount"],
            script_from_dict(dict_["script_pub_key"]),
            check_validity=check_validity,
        )

    def serialize(self, *, psbt_version: int = 0, check_validity: bool = True) -> bytes:
        """Return the binary representation of the output map.

        psbt_version is the version of the psbt the map belongs to, and
        it decides whether the two BIP370 fields are written here or
        folded into the psbt's unsigned transaction; an output
        serialized on its own is written as version 0, the version
        BIP174 defines.
        """
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

        # between 0x02 and 0x05 because that is where their type bytes
        # belong: the order the fields are written in is what a psbt's
        # bytes are compared against, and BIP370's own psbts are in
        # ascending order of type byte
        if psbt_version == 2:
            psbt_out_bin.extend(_serialized_v2_fields(self))

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

        # the map ends itself, as it does in Bitcoin Core
        # (PSBTOutput::Serialize); PsbtIn.serialize says why
        psbt_out_bin.append(PSBT_SEPARATOR)
        return b"".join(psbt_out_bin)

    @classmethod
    def parse(
        cls: type[PsbtOut],
        data: BinaryData,
        *,
        psbt_version: int = 0,
        check_validity: bool = True,
    ) -> PsbtOut:
        """Return a PsbtOut by parsing binary data.

        One map is read, its terminator included, which leaves the stream
        on the output after this one.

        psbt_version is the version of the psbt the map belongs to, which
        decides whether a BIP370 type byte is a field of this output or
        one this version must not carry; an output read on its own is
        read as version 0, the version BIP174 defines.
        """
        output_map = deserialize_map(data)
        redeem_script = b""
        witness_script = b""
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        taproot_internal_key = b""
        taproot_tree: list[tuple[int, int, bytes]] = []
        taproot_hd_key_paths: dict[Octets, tuple[list[bytes], BIP32KeyOrigin]] = {}
        unknown: dict[Octets, Octets] = {}
        amount: int | None = None
        script_pub_key = b""

        for k, v in output_map.items():
            # before the dispatch and not in its `unknown` arm: 0x03 and
            # 0x04 are fields of this output now, so a version 0 psbt
            # carrying one would be read rather than refused
            assert_not_a_v2_field(k[:1], psbt_version, _V2_FIELDS)
            if k[:1] == PSBT_OUT_AMOUNT:
                amount = deserialize_sized_int(k, v, "amount", 8, signed=True)
            elif k[:1] == PSBT_OUT_SCRIPT:
                script_pub_key = deserialize_bytes(k, v, "script")
            elif k[:1] == PSBT_OUT_REDEEM_SCRIPT:
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
            amount,
            script_pub_key,
            check_validity=check_validity,
        )
