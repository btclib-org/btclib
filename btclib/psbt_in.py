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


@dataclass
class PartialSigs(DataClassJsonMixin):
    sigs: Dict[str, bytes] = field(default_factory=dict)

    def add_sig(self, key: PubKey, sig: der.DERSig):

        # key_str = pubkeyinfo_from_key(key)[0].hex()
        key_str = _pubkey_to_hex_string(key)

        r, s, sighash = der._deserialize(sig)
        sig_str = der._serialize(r, s, sighash)

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
            if key[0] == 0x00:  # non_witness_utxo
                assert len(key) == 1
                out.non_witness_utxo = Tx.deserialize(value)
            elif key[0] == 0x01:  # witness_utxo
                assert len(key) == 1
                out.witness_utxo = TxOut.deserialize(value)
            elif key[0] == 0x02:  # partial_sigs
                assert len(key) == 33 + 1
                out.partial_sigs.add_sig(key[1:], value)
            elif key[0] == 0x03:  # sighash
                assert len(key) == 1
                assert len(value) == 4
                out.sighash = int.from_bytes(value, "little")
            elif key[0] == 0x04:  # redeem_script
                assert len(key) == 1
                out.redeem_script = value
            elif key[0] == 0x05:  # witness_script
                assert len(key) == 1
                out.witness_script = value
            elif key[0] == 0x06:  # hd_keypaths
                if len(key) != 33 + 1:
                    raise ValueError(f"invalid key lenght: {len(key)-1}")
                out.hd_keypaths.add_hd_keypath(key[1:], value[:4], value[4:])
            elif key[0] == 0x07:  # final_script_sig
                assert len(key) == 1
                out.final_script_sig = value
            elif key[0] == 0x08:  # final_script_witness
                assert len(key) == 1
                out.final_script_witness = witness_deserialize(value)
            elif key[0] == 0x09:  # por_commitment
                assert len(key) == 1
                out.por_commitment = value.hex()  # TODO: bip127
            elif key[0] == 0xFC:  # proprietary
                prefix = varint.decode(key[1:])
                if prefix not in out.proprietary.keys():
                    out.proprietary[prefix] = {}
                key = key[1 + len(varint.encode(prefix)) :]
                out.proprietary[prefix][key.hex()] = value
            else:  # unknown keys
                out.unknown[key.hex()] = value

        if assert_valid:
            out.assert_valid()
        return out

    def serialize(self, assert_valid: bool = True) -> bytes:

        if assert_valid:
            self.assert_valid()

        out = b""
        if self.non_witness_utxo:
            out += b"\x01\x00"
            utxo = self.non_witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.witness_utxo:
            out += b"\x01\x01"
            utxo = self.witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.partial_sigs:
            for key, value in self.partial_sigs.sigs.items():
                out += b"\x22\x02" + bytes.fromhex(key)
                out += varint.encode(len(value)) + value
        if self.sighash:
            out += b"\x01\x03"
            out += b"\x04" + self.sighash.to_bytes(4, "little")
        if self.redeem_script:
            out += b"\x01\x04"
            out += varint.encode(len(self.redeem_script)) + self.redeem_script
        if self.witness_script:
            out += b"\x01\x05"
            out += varint.encode(len(self.witness_script)) + self.witness_script
        if self.hd_keypaths:
            for xpub, hd_keypath in self.hd_keypaths.hd_keypaths.items():
                out += b"\x22\x06" + bytes.fromhex(xpub)
                keypath = bytes.fromhex(hd_keypath["fingerprint"])
                keypath += bytes_from_bip32_path(
                    hd_keypath["derivation_path"], "little"
                )
                out += varint.encode(len(keypath)) + keypath
        if self.final_script_sig:
            out += b"\x01\x07"
            out += varint.encode(len(self.final_script_sig)) + self.final_script_sig
        if self.final_script_witness:
            out += b"\x01\x08"
            wit = witness_serialize(self.final_script_witness)
            out += varint.encode(len(wit)) + wit
        if self.por_commitment:  # TODO
            out += b"\x01\x09"
            c = bytes.fromhex(self.por_commitment)
            out += varint.encode(len(c)) + c
        if self.proprietary:
            for (owner, dictionary) in self.proprietary.items():
                for key, value2 in dictionary.items():
                    key_bytes = b"\xfc" + varint.encode(owner) + bytes.fromhex(key)
                    out += varint.encode(len(key_bytes)) + key_bytes
                    out += varint.encode(len(value2)) + value2
        if self.unknown:
            for key, value2 in self.unknown.items():
                out += varint.encode(len(key) // 2) + bytes.fromhex(key)
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
            assert isinstance(self.por_commitment, str)
        assert isinstance(self.proprietary, dict)
        assert isinstance(self.unknown, dict)

    def add_unknown(self, key: String, val: Octets):

        key_str = token_or_string_to_hex_string(key)

        self.unknown[key_str] = bytes_from_octets(val)

    def get_unknown(self, key: String) -> bytes:

        key_str = token_or_string_to_hex_string(key)

        return self.unknown[key_str]
