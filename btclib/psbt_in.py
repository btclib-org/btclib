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

from . import der, varint
from .alias import Octets, String
from .bip32 import bytes_from_bip32_path
from .psbt_out import HdKeyPaths, _pubkey_to_hex_string
from .script import SIGHASHES
from .to_pubkey import PubKey
from .tx import Tx
from .tx_in import witness_deserialize, witness_serialize
from .tx_out import TxOut
from .utils import bytes_from_octets, token_or_string_to_hex_string

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
    sigs: Dict[str, bytes] = field(default_factory=dict)

    def add_sig(self, key: PubKey, sig: der.DERSig):

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        r, s, sighash = der.deserialize(sig)
        sig_str = der.serialize(r, s, sighash)

        self.sigs[key_str] = sig_str

    def get_sig(self, key: PubKey) -> bytes:

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        return self.sigs[key_str]

    def assert_valid(self) -> None:
        pass


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
    proprietary: Dict[int, Dict[str, bytes]] = field(default_factory=dict)
    unknown: Dict[str, bytes] = field(default_factory=dict)

    @classmethod
    def deserialize(
        cls: Type[_PsbtIn], input_map: Dict[bytes, bytes], assert_valid: bool = True
    ) -> _PsbtIn:
        out = cls()
        for key, value in input_map.items():
            if key[0:1] == PSBT_IN_NON_WITNESS_UTXO:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.non_witness_utxo is None, "duplicated non_witness_utxo"
                out.non_witness_utxo = Tx.deserialize(value)
            elif key[0:1] == PSBT_IN_WITNESS_UTXO:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.witness_utxo is None, "duplicated witness_utxo"
                out.witness_utxo = TxOut.deserialize(value)
            elif key[0:1] == PSBT_IN_PARTIAL_SIG:
                assert len(key) == 33 + 1, f"invalid key length: {len(key)}"
                out.partial_sigs.add_sig(key[1:], value)
            elif key[0:1] == PSBT_IN_SIGHASH_TYPE:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.sighash is None, "duplicated sighash"
                assert len(value) == 4
                out.sighash = int.from_bytes(value, "little")
            elif key[0:1] == PSBT_IN_FINAL_SCRIPTSIG:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.final_script_sig == b"", "duplicated final_script_sig"
                out.final_script_sig = value
            elif key[0:1] == PSBT_IN_FINAL_SCRIPTWITNESS:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert not out.final_script_witness, "duplicated final_script_witness"
                out.final_script_witness = witness_deserialize(value)
            elif key[0:1] == PSBT_IN_POR_COMMITMENT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                out.por_commitment = value.decode("utf-8")  # TODO: see bip127
            elif key[0:1] == PSBT_IN_REDEEM_SCRIPT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.redeem_script == b"", "duplicated redeem_script"
                out.redeem_script = value
            elif key[0:1] == PSBT_IN_WITNESS_SCRIPT:
                assert len(key) == 1, f"invalid key length: {len(key)}"
                assert out.witness_script == b"", "duplicated witness_script"
                out.witness_script = value
            elif key[0:1] == PSBT_IN_BIP32_DERIVATION:
                assert len(key) == 33 + 1, f"invalid key length: {len(key)}"
                # TODO: assert not duplicated?
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0:1] == PSBT_IN_PROPRIETARY:
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

        if self.non_witness_utxo:
            out += b"\x01" + PSBT_IN_NON_WITNESS_UTXO
            utxo = self.non_witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        elif self.witness_utxo:
            out += b"\x01" + PSBT_IN_WITNESS_UTXO
            utxo = self.witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo

        if self.partial_sigs:
            for key, value in self.partial_sigs.sigs.items():
                out += b"\x22" + PSBT_IN_PARTIAL_SIG + bytes.fromhex(key)
                out += varint.encode(len(value)) + value
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
        if self.hd_keypaths:
            for pubkey, hd_keypath in self.hd_keypaths.hd_keypaths.items():
                pubkey_bytes = PSBT_IN_BIP32_DERIVATION + bytes.fromhex(pubkey)
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
                        PSBT_IN_PROPRIETARY + varint.encode(owner) + bytes.fromhex(key)
                    )
                    out += varint.encode(len(key_bytes)) + key_bytes
                    out += varint.encode(len(value)) + value
        if self.unknown:
            for key2, value2 in self.unknown.items():
                out += varint.encode(len(key2) // 2) + bytes.fromhex(key2)
                out += varint.encode(len(value2)) + value2

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
        assert isinstance(self.proprietary, dict)
        assert isinstance(self.unknown, dict)

    def add_unknown(self, key: String, val: Octets):

        key_str = token_or_string_to_hex_string(key)

        self.unknown[key_str] = bytes_from_octets(val)

    def get_unknown(self, key: String) -> bytes:

        key_str = token_or_string_to_hex_string(key)

        return self.unknown[key_str]
