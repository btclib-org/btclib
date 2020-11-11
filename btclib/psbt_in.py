#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Partially Signed Bitcoin Transaction Input.

https://en.bitcoin.it/wiki/BIP_0174
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import dsa, varint
from .psbt_out import HdKeyPaths, ProprietaryData, UnknownData
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
PSBT_IN_POR_COMMITMENT = b"\x09"
# TODO: add support for the following
# PSBT_IN_RIPEMD160 = b"\0x0a"
# PSBT_IN_SHA256 = b"\0x0b"
# PSBT_IN_HASH160 = b"\0x0c"
# PSBT_IN_HASH256 = b"\0x0d"
PSBT_IN_PROPRIETARY = b"\xfc"


@dataclass
class PartialSigs(DataClassJsonMixin):
    sigs: Dict[str, str] = field(default_factory=dict)

    def assert_valid(self) -> None:
        for pubkey, sig in self.sigs.items():
            # TODO: verify that pubkey is a valid secp256k1 Point
            # in compressed SEC representation
            assert len(bytes.fromhex(pubkey)) == 33
            assert dsa.deserialize(sig)


_PsbtIn = TypeVar("_PsbtIn", bound="PsbtIn")


@dataclass
class PsbtIn(DataClassJsonMixin):
    non_witness_utxo: Optional[Tx] = None
    witness_utxo: Optional[TxOut] = None
    partial_sigs: PartialSigs = field(default_factory=PartialSigs)
    sighash: Optional[int] = None
    redeem_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    witness_script: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    hd_keypaths: HdKeyPaths = field(default_factory=HdKeyPaths)
    final_script_sig: bytes = field(
        default=b"", metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    final_script_witness: List[bytes] = field(
        default_factory=list,
        metadata=config(encoder=lambda val: [v.hex() for v in val]),
    )
    por_commitment: Optional[str] = None
    proprietary: ProprietaryData = field(default_factory=ProprietaryData)
    unknown: UnknownData = field(default_factory=UnknownData)

    @classmethod
    def deserialize(
        cls: Type[_PsbtIn], input_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtIn:
        out = cls()
        for key, value in input_map.items():
            if key[0:1] == PSBT_IN_NON_WITNESS_UTXO:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.non_witness_utxo = Tx.deserialize(value)
            elif key[0:1] == PSBT_IN_WITNESS_UTXO:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.witness_utxo = TxOut.deserialize(value)
            elif key[0:1] == PSBT_IN_PARTIAL_SIG:
                assert len(key) == 33 + 1, f"invalid key length: {len(key)}"
                out.partial_sigs.sigs[key[1:].hex()] = value.hex()
            elif key[0:1] == PSBT_IN_SIGHASH_TYPE:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert len(value) == 4
                out.sighash = int.from_bytes(value, "little")
            elif key[0:1] == PSBT_IN_FINAL_SCRIPTSIG:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.final_script_sig = value
            elif key[0:1] == PSBT_IN_FINAL_SCRIPTWITNESS:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.final_script_witness = witness_deserialize(value)
            elif key[0:1] == PSBT_IN_POR_COMMITMENT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.por_commitment = value.decode("utf-8")  # TODO: see bip127
            elif key[0:1] == PSBT_IN_REDEEM_SCRIPT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.redeem_script = value
            elif key[0:1] == PSBT_IN_WITNESS_SCRIPT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.witness_script = value
            elif key[0:1] == PSBT_IN_BIP32_DERIVATION:
                assert len(key) == 33 + 1, f"invalid key length: {len(key)}"
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0:1] == PSBT_IN_PROPRIETARY:
                out.proprietary = ProprietaryData.deserialize(key, value, False)
            else:  # unknown keys
                out.unknown.data[key.hex()] = value.hex()

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""

        if self.non_witness_utxo:
            out += b"\x01" + PSBT_IN_NON_WITNESS_UTXO
            utxo = self.non_witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.witness_utxo:
            out += b"\x01" + PSBT_IN_WITNESS_UTXO
            utxo = self.witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.partial_sigs:
            for key, value in self.partial_sigs.sigs.items():
                out += b"\x22" + PSBT_IN_PARTIAL_SIG + bytes.fromhex(key)
                t = bytes.fromhex(value)
                out += varint.encode(len(t)) + t
        if self.sighash:
            out += b"\x01" + PSBT_IN_SIGHASH_TYPE
            out += b"\x04" + self.sighash.to_bytes(4, "little")
        if self.redeem_script:
            out += b"\x01" + PSBT_IN_REDEEM_SCRIPT
            out += varint.encode(len(self.redeem_script)) + self.redeem_script
        if self.witness_script:
            out += b"\x01" + PSBT_IN_WITNESS_SCRIPT
            out += varint.encode(len(self.witness_script)) + self.witness_script
        if self.final_script_sig:
            out += b"\x01" + PSBT_IN_FINAL_SCRIPTSIG
            out += varint.encode(len(self.final_script_sig)) + self.final_script_sig
        if self.final_script_witness:
            out += b"\x01" + PSBT_IN_FINAL_SCRIPTWITNESS
            wit = witness_serialize(self.final_script_witness)
            out += varint.encode(len(wit)) + wit
        if self.por_commitment:
            out += b"\x01" + PSBT_IN_POR_COMMITMENT
            c = self.por_commitment.encode("utf-8")
            out += varint.encode(len(c)) + c
        if self.hd_keypaths.hd_keypaths:
            out += self.hd_keypaths.serialize(PSBT_IN_BIP32_DERIVATION, assert_valid)
        if self.proprietary.data:
            out += self.proprietary.serialize(PSBT_IN_PROPRIETARY, assert_valid)
        if self.unknown.data:
            out += self.unknown.serialize(assert_valid)

        return out

    def assert_valid(self) -> None:
        if self.non_witness_utxo is not None:
            self.non_witness_utxo.assert_valid()
        if self.witness_utxo is not None:
            self.witness_utxo.assert_valid()
        self.partial_sigs.assert_valid()
        if self.sighash is not None:
            assert self.sighash in SIGHASHES, f"invalid sighash: {self.sighash}"
        assert isinstance(self.redeem_script, bytes)
        assert isinstance(self.witness_script, bytes)
        self.hd_keypaths.assert_valid()
        assert isinstance(self.final_script_sig, bytes)
        assert isinstance(self.final_script_witness, list)
        if self.por_commitment is not None:
            assert self.por_commitment.encode("utf-8")

        self.proprietary.assert_valid()
        self.unknown.assert_valid()
