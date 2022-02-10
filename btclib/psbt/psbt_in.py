#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Input (PsbtIn) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Type

# Library imports
from btclib.alias import Octets

# Standard library imports
from btclib.bip32.key_origin import (
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.ecc import dsa, sec_point
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.psbt.psbt_out import BIP32KeyOrigin, HdKeyPaths
from btclib.psbt.psbt_utils import (
    assert_valid_redeem_script,
    assert_valid_unknown,
    assert_valid_witness_script,
    decode_dict_bytes_bytes,
    deserialize_bytes,
    deserialize_int,
    deserialize_tx,
    encode_dict_bytes_bytes,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
)
from btclib.script.sig_hash import assert_valid_hash_type
from btclib.script.witness import Witness
from btclib.tx.tx import Tx
from btclib.tx.tx_out import TxOut
from btclib.utils import bytes_from_octets

PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIG_HASH_TYPE = b"\x03"
PSBT_IN_REDEEM_SCRIPT = b"\x04"
PSBT_IN_WITNESS_SCRIPT = b"\x05"
PSBT_IN_BIP32_DERIVATION = b"\x06"
PSBT_IN_FINAL_SCRIPTSIG = b"\x07"
PSBT_IN_FINAL_SCRIPTWITNESS = b"\x08"
PSBT_IN_RIPEMD160 = b"\x0a"
PSBT_IN_SHA256 = b"\x0b"
PSBT_IN_HASH160 = b"\x0c"
PSBT_IN_HASH256 = b"\x0d"

# 0xfc is reserved for proprietary
# explicit code support for proprietary (and por) is unnecessary
# see https://github.com/bitcoin/bips/pull/1038
# PSBT_IN_PROPRIETARY = b"\xfc"


def _deserialize_witness_utxo(k: bytes, v: bytes) -> TxOut:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid witness-utxo key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return TxOut.parse(v)


def _assert_valid_partial_sigs(partial_sigs: Mapping[bytes, bytes]) -> None:
    "Raise an exception if the dataclass element is not valid."

    for pub_key, sig in partial_sigs.items():
        try:
            # pub_key must be a valid secp256k1 Point in SEC representation
            sec_point.point_from_octets(pub_key)
        except BTClibValueError as e:
            err_msg = "invalid partial signature pub_key: {pub_key!r}"
            raise BTClibValueError(err_msg) from e
        try:
            dsa.Sig.parse(sig)
        except BTClibValueError as e:
            err_msg = f"invalid partial signature: {sig!r}"
            raise BTClibValueError(err_msg) from e
        # TODO should we check that pub_key is recoverable from sig?


def _assert_valid_final_script_sig(final_script_sig: bytes) -> None:
    # should check for a valid script
    bytes(final_script_sig)


def _deserialize_final_script_witness(k: bytes, v: bytes) -> Witness:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid final script witness key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return Witness.parse(v)


def _assert_valid_ripemd160_preimages(
    ripemd160_preimages: Mapping[bytes, bytes]
) -> None:

    for h, preimage in ripemd160_preimages.items():
        if ripemd160(preimage) != h:
            raise BTClibValueError("Invalid RIPEMD160 preimage")


def _assert_valid_sha256_preimages(sha256_preimages: Mapping[bytes, bytes]) -> None:

    for h, preimage in sha256_preimages.items():
        if sha256(preimage) != h:
            raise BTClibValueError("Invalid SHA256 preimage")


def _assert_valid_hash160_preimages(hash160_preimages: Mapping[bytes, bytes]) -> None:

    for h, preimage in hash160_preimages.items():
        if hash160(preimage) != h:
            raise BTClibValueError("Invalid HASH160 preimage")


def _assert_valid_hash256_preimages(hash256_preimages: Mapping[bytes, bytes]) -> None:

    for h, preimage in hash256_preimages.items():
        if hash256(preimage) != h:
            raise BTClibValueError("Invalid HASH256 preimage")


@dataclass
class PsbtIn:
    non_witness_utxo: Optional[Tx]
    witness_utxo: Optional[TxOut]
    partial_sigs: Dict[bytes, bytes]
    sig_hash_type: Optional[int]
    redeem_script: bytes
    witness_script: bytes
    hd_key_paths: HdKeyPaths
    final_script_sig: bytes
    final_script_witness: Witness
    ripemd160_preimages: Dict[bytes, bytes]
    sha256_preimages: Dict[bytes, bytes]
    hash160_preimages: Dict[bytes, bytes]
    hash256_preimages: Dict[bytes, bytes]
    unknown: Dict[bytes, bytes]

    @property
    def sig_hash(self) -> int:
        "Return the sig_hash int for compatibility with PartiallySignedInput."
        return self.sig_hash_type or 0

    def __init__(
        self,
        non_witness_utxo: Optional[Tx] = None,
        witness_utxo: Optional[TxOut] = None,
        partial_sigs: Optional[Mapping[Octets, Octets]] = None,
        sig_hash_type: Optional[int] = None,
        redeem_script: Octets = b"",
        witness_script: Octets = b"",
        hd_key_paths: Optional[Mapping[Octets, BIP32KeyOrigin]] = None,
        final_script_sig: Octets = b"",
        final_script_witness: Witness = Witness(),
        ripemd160_preimages: Optional[Mapping[Octets, Octets]] = None,
        sha256_preimages: Optional[Mapping[Octets, Octets]] = None,
        hash160_preimages: Optional[Mapping[Octets, Octets]] = None,
        hash256_preimages: Optional[Mapping[Octets, Octets]] = None,
        unknown: Optional[Mapping[Octets, Octets]] = None,
        check_validity: bool = True,
    ) -> None:

        self.non_witness_utxo = non_witness_utxo
        self.witness_utxo = witness_utxo
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.partial_sigs = decode_dict_bytes_bytes(partial_sigs)
        self.sig_hash_type = sig_hash_type
        self.redeem_script = bytes_from_octets(redeem_script)
        self.witness_script = bytes_from_octets(witness_script)
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.final_script_sig = bytes_from_octets(final_script_sig)
        self.final_script_witness = final_script_witness
        self.ripemd160_preimages = decode_dict_bytes_bytes(ripemd160_preimages)
        self.sha256_preimages = decode_dict_bytes_bytes(sha256_preimages)
        self.hash160_preimages = decode_dict_bytes_bytes(hash160_preimages)
        self.hash256_preimages = decode_dict_bytes_bytes(hash256_preimages)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        "Assert logical self-consistency."

        if self.non_witness_utxo:
            self.non_witness_utxo.assert_valid()

        if self.witness_utxo:
            self.witness_utxo.assert_valid()

        _assert_valid_partial_sigs(self.partial_sigs)

        if self.sig_hash_type:
            assert_valid_hash_type(self.sig_hash_type)

        assert_valid_redeem_script(self.redeem_script)
        assert_valid_witness_script(self.witness_script)
        assert_valid_hd_key_paths(self.hd_key_paths)
        _assert_valid_final_script_sig(self.final_script_sig)
        self.final_script_witness.assert_valid()

        _assert_valid_ripemd160_preimages(self.ripemd160_preimages)
        _assert_valid_sha256_preimages(self.sha256_preimages)
        _assert_valid_hash160_preimages(self.hash160_preimages)
        _assert_valid_hash256_preimages(self.hash256_preimages)

        assert_valid_unknown(self.unknown)

    def to_dict(self, check_validity: bool = True) -> Dict[str, Any]:

        if check_validity:
            self.assert_valid()

        return {
            "non_witness_utxo": self.non_witness_utxo.to_dict(False)
            if self.non_witness_utxo
            else None,
            "witness_utxo": self.witness_utxo.to_dict(False)
            if self.witness_utxo
            else None,
            "partial_signatures": encode_dict_bytes_bytes(self.partial_sigs),
            "sig_hash": self.sig_hash_type,
            # TODO make it { "asm": "", "hex": "" }
            "redeem_script": self.redeem_script.hex(),
            # TODO make it { "asm": "", "hex": "" }
            "witness_script": self.witness_script.hex(),
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            # TODO make it { "asm": "", "hex": "" }
            "final_script_sig": self.final_script_sig.hex(),
            "final_script_witness": self.final_script_witness.to_dict(False),
            "ripemd160_preimages": encode_dict_bytes_bytes(self.ripemd160_preimages),
            "sha256_preimages": encode_dict_bytes_bytes(self.sha256_preimages),
            "hash160_preimages": encode_dict_bytes_bytes(self.hash160_preimages),
            "hash256_preimages": encode_dict_bytes_bytes(self.hash256_preimages),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
        }

    @classmethod
    def from_dict(
        cls: Type["PsbtIn"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "PsbtIn":

        return cls(
            Tx.from_dict(dict_["non_witness_utxo"], False)
            if dict_["non_witness_utxo"]
            else None,
            TxOut.from_dict(dict_["witness_utxo"], False)
            if dict_["witness_utxo"]
            else None,
            dict_["partial_signatures"],
            dict_["sig_hash"],
            dict_["redeem_script"],
            dict_["witness_script"],
            # FIXME
            decode_from_bip32_derivs(dict_["bip32_derivs"]),  # type: ignore
            dict_["final_script_sig"],
            Witness.from_dict(dict_["final_script_witness"], False),
            dict_["ripemd160_preimages"],
            dict_["sha256_preimages"],
            dict_["hash160_preimages"],
            dict_["hash256_preimages"],
            dict_["unknown"],
            check_validity,
        )

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        psbt_in_bin: List[bytes] = []

        if self.non_witness_utxo:
            temp = self.non_witness_utxo.serialize(include_witness=True)
            psbt_in_bin.append(serialize_bytes(PSBT_IN_NON_WITNESS_UTXO, temp))

        if self.witness_utxo:
            psbt_in_bin.append(
                serialize_bytes(PSBT_IN_WITNESS_UTXO, self.witness_utxo.serialize())
            )

        if not self.final_script_sig and not self.final_script_witness:

            if self.partial_sigs:
                psbt_in_bin.append(
                    serialize_dict_bytes_bytes(PSBT_IN_PARTIAL_SIG, self.partial_sigs)
                )

            if self.sig_hash_type:
                temp = self.sig_hash_type.to_bytes(4, byteorder="little", signed=False)
                psbt_in_bin.append(serialize_bytes(PSBT_IN_SIG_HASH_TYPE, temp))

            if self.redeem_script:
                psbt_in_bin.append(
                    serialize_bytes(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)
                )

            if self.witness_script:
                psbt_in_bin.append(
                    serialize_bytes(PSBT_IN_WITNESS_SCRIPT, self.witness_script)
                )

            if self.hd_key_paths:
                psbt_in_bin.append(
                    serialize_hd_key_paths(PSBT_IN_BIP32_DERIVATION, self.hd_key_paths)
                )

        if self.final_script_sig:
            psbt_in_bin.append(
                serialize_bytes(PSBT_IN_FINAL_SCRIPTSIG, self.final_script_sig)
            )

        if self.final_script_witness:
            temp = self.final_script_witness.serialize()
            psbt_in_bin.append(serialize_bytes(PSBT_IN_FINAL_SCRIPTWITNESS, temp))

        if self.unknown:
            psbt_in_bin.append(serialize_dict_bytes_bytes(b"", self.unknown))

        if self.ripemd160_preimages:
            print(
                serialize_dict_bytes_bytes(PSBT_IN_RIPEMD160, self.ripemd160_preimages)
            )
            print(self.ripemd160_preimages)
            psbt_in_bin.append(
                serialize_dict_bytes_bytes(PSBT_IN_RIPEMD160, self.ripemd160_preimages)
            )

        if self.sha256_preimages:
            psbt_in_bin.append(
                serialize_dict_bytes_bytes(PSBT_IN_SHA256, self.sha256_preimages)
            )

        if self.hash160_preimages:
            psbt_in_bin.append(
                serialize_dict_bytes_bytes(PSBT_IN_HASH160, self.hash160_preimages)
            )

        if self.hash256_preimages:
            psbt_in_bin.append(
                serialize_dict_bytes_bytes(PSBT_IN_HASH256, self.hash256_preimages)
            )

        return b"".join(psbt_in_bin)

    @classmethod
    def parse(
        cls: Type["PsbtIn"],
        input_map: Mapping[bytes, bytes],
        check_validity: bool = True,
    ) -> "PsbtIn":
        "Return a PsbtIn by parsing binary data."

        # FIX parse must use BinaryData

        non_witness_utxo = None
        witness_utxo = None
        partial_sigs: Dict[Octets, Octets] = {}
        sig_hash_type = None
        redeem_script = b""
        witness_script = b""
        hd_key_paths: Dict[Octets, BIP32KeyOrigin] = {}
        final_script_sig = b""
        final_script_witness = Witness()
        ripemd160_preimages: Dict[Octets, Octets] = {}
        sha256_preimages: Dict[Octets, Octets] = {}
        hash160_preimages: Dict[Octets, Octets] = {}
        hash256_preimages: Dict[Octets, Octets] = {}
        unknown: Dict[Octets, Octets] = {}

        for k, v in input_map.items():
            if k[:1] == PSBT_IN_NON_WITNESS_UTXO:
                non_witness_utxo = deserialize_tx(k, v, "non-witness utxo")
            elif k[:1] == PSBT_IN_WITNESS_UTXO:
                witness_utxo = _deserialize_witness_utxo(k, v)
            elif k[:1] == PSBT_IN_PARTIAL_SIG:
                partial_sigs[k[1:]] = v
            elif k[:1] == PSBT_IN_SIG_HASH_TYPE:
                sig_hash_type = deserialize_int(k, v, "sig_hash type")
            elif k[:1] == PSBT_IN_REDEEM_SCRIPT:
                redeem_script = deserialize_bytes(k, v, "redeem script")
            elif k[:1] == PSBT_IN_WITNESS_SCRIPT:
                witness_script = deserialize_bytes(k, v, "witness script")
            elif k[:1] == PSBT_IN_BIP32_DERIVATION:
                hd_key_paths[k[1:]] = BIP32KeyOrigin.parse(v)
            elif k[:1] == PSBT_IN_FINAL_SCRIPTSIG:
                final_script_sig = deserialize_bytes(k, v, "final script_sig")
            elif k[:1] == PSBT_IN_RIPEMD160:
                ripemd160_preimages[k[1:]] = v
            elif k[:1] == PSBT_IN_SHA256:
                sha256_preimages[k[1:]] = v
            elif k[:1] == PSBT_IN_HASH160:
                hash160_preimages[k[1:]] = v
            elif k[:1] == PSBT_IN_HASH256:
                hash256_preimages[k[1:]] = v
            elif k[:1] == PSBT_IN_FINAL_SCRIPTWITNESS:
                final_script_witness = _deserialize_final_script_witness(k, v)
            else:  # unknown
                unknown[k] = v

        return cls(
            non_witness_utxo,
            witness_utxo,
            partial_sigs,
            sig_hash_type,
            redeem_script,
            witness_script,
            hd_key_paths,
            final_script_sig,
            final_script_witness,
            ripemd160_preimages,
            sha256_preimages,
            hash160_preimages,
            hash256_preimages,
            unknown,
            check_validity,
        )
