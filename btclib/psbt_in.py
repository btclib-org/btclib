#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Input.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from dataclasses import InitVar, dataclass, field
from typing import Dict, Optional, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import dsa, sec_point
from .exceptions import BTClibTypeError, BTClibValueError
from .psbt_out import (
    _assert_valid_hd_key_paths,
    _assert_valid_redeem_script,
    _assert_valid_unknown,
    _assert_valid_witness_script,
    _decode_dict_bytes_bytes,
    _decode_hd_key_paths,
    _deserialize_bytes,
    _deserialize_hd_key_path,
    _encode_dict_bytes_bytes,
    _encode_hd_key_paths,
    _serialize_bytes,
    _serialize_dict_bytes_bytes,
)
from .sign_hash import assert_valid_hash_type
from .tx import Tx
from .tx_out import TxOut
from .witness import Witness

PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIG_HASH_TYPE = b"\x03"
PSBT_IN_REDEEM_SCRIPT = b"\x04"
PSBT_IN_WITNESS_SCRIPT = b"\x05"
PSBT_IN_BIP32_DERIVATION = b"\x06"
PSBT_IN_FINAL_SCRIPTSIG = b"\x07"
PSBT_IN_FINAL_SCRIPTWITNESS = b"\x08"
# TODO: add support for the following
# PSBT_IN_RIPEMD160 = b"\0x0a"
# PSBT_IN_SHA256 = b"\0x0b"
# PSBT_IN_HASH160 = b"\0x0c"
# PSBT_IN_HASH256 = b"\0x0d"

# 0xfc is reserved for proprietary
# explicit code support for proprietary (and por) is unnecessary
# see https://github.com/bitcoin/bips/pull/1038
# PSBT_IN_PROPRIETARY = b"\xfc"


def _deserialize_tx(k: bytes, v: bytes, type_: str) -> Tx:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return Tx.deserialize(v)


def _deserialize_witness_utxo(k: bytes, v: bytes) -> TxOut:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid witness-utxo key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return TxOut.deserialize(v)


def _deserialize_partial_sigs(k: bytes, v: bytes) -> Dict[bytes, bytes]:
    "Return the dataclass element from its binary representation."

    if len(k) - 1 not in (33, 65):
        err_msg = "invalid partial signature pub_key length"
        err_msg += f": {len(k)-1} instead of (33, 65)"
        raise BTClibValueError(err_msg)
    return {k[1:]: v}


def _assert_valid_partial_sigs(partial_sigs: Dict[bytes, bytes]) -> None:
    "Raise an exception if the dataclass element is not valid."

    for pub_key, sig in partial_sigs.items():
        try:
            # pub_key must be a valid secp256k1 Point in SEC representation
            sec_point.point_from_octets(pub_key)
        except BTClibValueError as e:
            err_msg = "invalid partial signature pub_key: {pub_key!r}"
            raise BTClibValueError(err_msg) from e
        try:
            dsa.Sig.deserialize(sig)
        except BTClibValueError as e:
            err_msg = f"invalid partial signature: {sig!r}"
            raise BTClibValueError(err_msg) from e
        # TODO should we check that pub_key is recoverable from sig?


def _deserialize_int(k: bytes, v: bytes, type_: str) -> int:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return int.from_bytes(v, byteorder="little", signed=False)


def _assert_valid_final_script_sig(final_script_sig: bytes) -> None:
    if not isinstance(final_script_sig, bytes):
        raise BTClibTypeError("invalid final script_sig")


def _deserialize_final_script_witness(k: bytes, v: bytes) -> Witness:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid final script witness key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return Witness.deserialize(v)


_PsbtIn = TypeVar("_PsbtIn", bound="PsbtIn")


@dataclass
class PsbtIn(DataClassJsonMixin):
    non_witness_utxo: Optional[Tx] = None
    witness_utxo: Optional[TxOut] = None
    partial_sigs: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            field_name="partial_signatures",
            encoder=_encode_dict_bytes_bytes,
            decoder=_decode_dict_bytes_bytes,
        ),
    )
    sig_hash_type: Optional[int] = field(
        default=None, metadata=config(field_name="sign_hash")
    )
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    hd_key_paths: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            field_name="bip32_derivs",
            encoder=_encode_hd_key_paths,
            decoder=_decode_hd_key_paths,
        ),
    )
    final_script_sig: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    final_script_witness: Witness = Witness()
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=_encode_dict_bytes_bytes, decoder=_decode_dict_bytes_bytes
        ),
    )
    check_validity: InitVar[bool] = True

    @property
    def sig_hash(self) -> int:
        "Return the sig_hash int for compatibility with PartiallySignedInput."
        return self.sig_hash_type or 0

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        "Assert logical self-consistency."

        if self.non_witness_utxo:
            self.non_witness_utxo.assert_valid()

        if self.witness_utxo:
            self.witness_utxo.assert_valid()

        if self.sig_hash_type:
            assert_valid_hash_type(self.sig_hash_type)

        _assert_valid_redeem_script(self.redeem_script)
        _assert_valid_witness_script(self.witness_script)
        _assert_valid_final_script_sig(self.final_script_sig)
        self.final_script_witness.assert_valid()
        _assert_valid_partial_sigs(self.partial_sigs)
        _assert_valid_hd_key_paths(self.hd_key_paths)
        _assert_valid_unknown(self.unknown)

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""

        if self.non_witness_utxo:
            temp = self.non_witness_utxo.serialize(include_witness=True)
            out += _serialize_bytes(PSBT_IN_NON_WITNESS_UTXO, temp)

        if self.witness_utxo:
            out += _serialize_bytes(PSBT_IN_WITNESS_UTXO, self.witness_utxo.serialize())

        if not self.final_script_sig and not self.final_script_witness:

            if self.partial_sigs:
                out += _serialize_dict_bytes_bytes(
                    PSBT_IN_PARTIAL_SIG, self.partial_sigs
                )

            if self.sig_hash_type:
                temp = self.sig_hash_type.to_bytes(4, byteorder="little", signed=False)
                out += _serialize_bytes(PSBT_IN_SIG_HASH_TYPE, temp)

            if self.redeem_script:
                out += _serialize_bytes(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)

            if self.witness_script:
                out += _serialize_bytes(PSBT_IN_WITNESS_SCRIPT, self.witness_script)

            if self.hd_key_paths:
                out += _serialize_dict_bytes_bytes(
                    PSBT_IN_BIP32_DERIVATION, self.hd_key_paths
                )

        if self.final_script_sig:
            out += _serialize_bytes(PSBT_IN_FINAL_SCRIPTSIG, self.final_script_sig)

        if self.final_script_witness:
            temp = self.final_script_witness.serialize()
            out += _serialize_bytes(PSBT_IN_FINAL_SCRIPTWITNESS, temp)

        if self.unknown:
            out += _serialize_dict_bytes_bytes(b"", self.unknown)

        return out

    @classmethod
    def deserialize(
        cls: Type[_PsbtIn], input_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtIn:
        "Return a PsbtIn by parsing binary data."

        # FIX deserialize must use BinaryData
        out = cls(check_validity=False)
        for k, v in input_map.items():
            if k[0:1] == PSBT_IN_NON_WITNESS_UTXO:
                out.non_witness_utxo = _deserialize_tx(k, v, "non-witness utxo")
            elif k[0:1] == PSBT_IN_WITNESS_UTXO:
                out.witness_utxo = _deserialize_witness_utxo(k, v)
            elif k[0:1] == PSBT_IN_PARTIAL_SIG:
                out.partial_sigs.update(_deserialize_partial_sigs(k, v))
            elif k[0:1] == PSBT_IN_SIG_HASH_TYPE:
                out.sig_hash_type = _deserialize_int(k, v, "sign_hash type")
            elif k[0:1] == PSBT_IN_REDEEM_SCRIPT:
                out.redeem_script = _deserialize_bytes(k, v, "redeem script")
            elif k[0:1] == PSBT_IN_WITNESS_SCRIPT:
                out.witness_script = _deserialize_bytes(k, v, "witness script")
            elif k[0:1] == PSBT_IN_BIP32_DERIVATION:
                out.hd_key_paths.update(
                    _deserialize_hd_key_path(k, v, "PsbtIn BIP32 pub_key")
                )
            elif k[0:1] == PSBT_IN_FINAL_SCRIPTSIG:
                out.final_script_sig = _deserialize_bytes(k, v, "final script_sig")
            elif k[0:1] == PSBT_IN_FINAL_SCRIPTWITNESS:
                out.final_script_witness = _deserialize_final_script_witness(k, v)
            else:  # unknown
                out.unknown[k] = v

        if assert_valid:
            out.assert_valid()
        return out
