#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Input.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import dsa, secpoint
from .exceptions import BTClibValueError
from .psbt_out import (
    _assert_valid_bip32_derivs,
    _assert_valid_redeem_script,
    _assert_valid_unknown,
    _assert_valid_witness_script,
    _decode_bip32_derivs,
    _decode_dict_bytes_bytes,
    _deserialize_bip32_derivs,
    _deserialize_bytes,
    _encode_bip32_derivs,
    _encode_dict_bytes_bytes,
    _serialize_bytes,
    _serialize_dict_bytes_bytes,
)
from .script import SIGHASHES
from .tx import Tx
from .tx_in import witness_deserialize, witness_serialize
from .tx_out import TxOut

PSBT_IN_NON_WITNESS_UTXO = b"\x00"
PSBT_IN_WITNESS_UTXO = b"\x01"
PSBT_IN_PARTIAL_SIG = b"\x02"
PSBT_IN_SIGHASH_TYPE = b"\x03"
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


def _assert_valid_tx(tx_: Optional[Tx]) -> None:
    if tx_ is not None:
        tx_.assert_valid()


def _deserialize_witness_utxo(k: bytes, v: bytes) -> TxOut:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid witness-utxo key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return TxOut.deserialize(v)


def _assert_valid_witness_utxo(witness_utxo: Optional[TxOut]) -> None:
    if witness_utxo is not None:
        witness_utxo.assert_valid()


def _deserialize_partial_signatures(k: bytes, v: bytes) -> Dict[bytes, bytes]:
    "Return the dataclass element from its binary representation."

    if len(k) - 1 not in (33, 65):
        err_msg = "invalid partial signature pubkey length"
        err_msg += f": {len(k)-1} instead of (33, 65)"
        raise BTClibValueError(err_msg)
    return {k[1:]: v}


def _deserialize_int(k: bytes, v: bytes, type_: str) -> int:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid {type_} key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return int.from_bytes(v, "little")


def _assert_valid_sighash(sighash: Optional[int]) -> None:
    if sighash is not None and sighash not in SIGHASHES:
        raise BTClibValueError(f"invalid sighash: {sighash}")


def _deserialize_final_script_witness(k: bytes, v: bytes) -> List[bytes]:
    "Return the dataclass element from its binary representation."

    if len(k) != 1:
        err_msg = f"invalid final script witness key length: {len(k)}"
        raise BTClibValueError(err_msg)
    return witness_deserialize(v)


def _assert_valid_final_script_sig(final_script_sig: bytes) -> None:
    if not isinstance(final_script_sig, bytes):
        raise BTClibValueError("invalid final script_sig")


def _assert_valid_final_script_witness(final_script_witness: List[bytes]) -> None:
    err_msg = "invalid final script witness"
    if not isinstance(final_script_witness, list):
        raise BTClibValueError(err_msg)
    for b in final_script_witness:
        if not isinstance(b, bytes):
            raise BTClibValueError(err_msg)


def _assert_valid_partial_signatures(partial_signatures: Dict[bytes, bytes]) -> None:
    "Raise an exception if the dataclass element is not valid."

    for pubkey, sig in partial_signatures.items():
        try:
            # pubkey must be a valid secp256k1 Point in SEC representation
            secpoint.point_from_octets(pubkey)
        except BTClibValueError as e:
            err_msg = "invalid partial signature pubkey: {pubkey!r}"
            raise BTClibValueError(err_msg) from e
        try:
            dsa.deserialize(sig)
        except BTClibValueError as e:
            err_msg = f"invalid partial signature: {sig!r}"
            raise BTClibValueError(err_msg) from e
        # TODO should we check that pubkey is recoverable from sig?


_PsbtIn = TypeVar("_PsbtIn", bound="PsbtIn")


@dataclass
class PsbtIn(DataClassJsonMixin):
    # FIXME remove Optional in favor of Tx()
    # to make it equivalent to Psbt.tx
    non_witness_utxo: Optional[Tx] = None
    witness_utxo: Optional[TxOut] = None
    partial_signatures: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=_encode_dict_bytes_bytes, decoder=_decode_dict_bytes_bytes
        ),
    )
    sighash: Optional[int] = None
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    bip32_derivs: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(encoder=_encode_bip32_derivs, decoder=_decode_bip32_derivs),
    )
    final_script_sig: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    final_script_witness: List[bytes] = field(
        default_factory=list,
        metadata=config(
            encoder=lambda val: [v.hex() for v in val],
            decoder=lambda val: [bytes.fromhex(v) for v in val],
        ),
    )
    unknown: Dict[bytes, bytes] = field(
        default_factory=dict,
        metadata=config(
            encoder=_encode_dict_bytes_bytes, decoder=_decode_dict_bytes_bytes
        ),
    )

    @classmethod
    def deserialize(
        cls: Type[_PsbtIn], input_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtIn:
        out = cls()
        for k, v in input_map.items():
            if k[0:1] == PSBT_IN_NON_WITNESS_UTXO:
                out.non_witness_utxo = _deserialize_tx(k, v, "non-witness utxo")
            elif k[0:1] == PSBT_IN_WITNESS_UTXO:
                out.witness_utxo = _deserialize_witness_utxo(k, v)
            elif k[0:1] == PSBT_IN_PARTIAL_SIG:
                out.partial_signatures.update(_deserialize_partial_signatures(k, v))
            elif k[0:1] == PSBT_IN_SIGHASH_TYPE:
                out.sighash = _deserialize_int(k, v, "sighash")
            elif k[0:1] == PSBT_IN_FINAL_SCRIPTSIG:
                out.final_script_sig = _deserialize_bytes(k, v, "final script_sig")
            elif k[0:1] == PSBT_IN_FINAL_SCRIPTWITNESS:
                out.final_script_witness = _deserialize_final_script_witness(k, v)
            elif k[0:1] == PSBT_IN_REDEEM_SCRIPT:
                out.redeem_script = _deserialize_bytes(k, v, "redeem script")
            elif k[0:1] == PSBT_IN_WITNESS_SCRIPT:
                out.witness_script = _deserialize_bytes(k, v, "witness script")
            elif k[0:1] == PSBT_IN_BIP32_DERIVATION:
                out.bip32_derivs.update(
                    _deserialize_bip32_derivs(k, v, "PsbtIn BIP32 pubkey")
                )
            else:  # unknown
                out.unknown[k] = v

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""

        if self.non_witness_utxo:
            temp = self.non_witness_utxo.serialize()
            out += _serialize_bytes(PSBT_IN_NON_WITNESS_UTXO, temp)
        if self.witness_utxo:
            out += _serialize_bytes(PSBT_IN_WITNESS_UTXO, self.witness_utxo.serialize())
        if self.partial_signatures:
            out += _serialize_dict_bytes_bytes(
                PSBT_IN_PARTIAL_SIG, self.partial_signatures
            )
        if self.sighash:
            temp = self.sighash.to_bytes(4, "little")
            out += _serialize_bytes(PSBT_IN_SIGHASH_TYPE, temp)
        if self.redeem_script:
            out += _serialize_bytes(PSBT_IN_REDEEM_SCRIPT, self.redeem_script)
        if self.witness_script:
            out += _serialize_bytes(PSBT_IN_WITNESS_SCRIPT, self.witness_script)
        if self.final_script_sig:
            out += _serialize_bytes(PSBT_IN_FINAL_SCRIPTSIG, self.final_script_sig)
        if self.final_script_witness:
            temp = witness_serialize(self.final_script_witness)
            out += _serialize_bytes(PSBT_IN_FINAL_SCRIPTWITNESS, temp)
        if self.bip32_derivs:
            out += _serialize_dict_bytes_bytes(
                PSBT_IN_BIP32_DERIVATION, self.bip32_derivs
            )
        if self.unknown:
            out += _serialize_dict_bytes_bytes(b"", self.unknown)

        return out

    def assert_valid(self) -> None:
        "Assert logical self-consistency."
        _assert_valid_tx(self.non_witness_utxo)
        _assert_valid_witness_utxo(self.witness_utxo)
        _assert_valid_sighash(self.sighash)
        _assert_valid_redeem_script(self.redeem_script)
        _assert_valid_witness_script(self.witness_script)
        _assert_valid_final_script_sig(self.final_script_sig)
        _assert_valid_final_script_witness(self.final_script_witness)
        _assert_valid_partial_signatures(self.partial_signatures)
        _assert_valid_bip32_derivs(self.bip32_derivs)
        _assert_valid_unknown(self.unknown)
