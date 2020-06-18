#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import dataclass
from typing import List, Dict, Tuple, Type, TypeVar, Optional
from base64 import b64decode, b64encode

from .tx import Tx
from .tx_out import TxOut
from .alias import Script
from . import varint, script

_PsbtGlobalMap = TypeVar("_PsbtGlobalMap", bound="PsbtGlobalMap")


@dataclass
class PsbtGlobalMap:
    tx: Tx
    xpub: Optional[Dict[str, str]] = None
    version: int = 0

    @classmethod
    def decode(
        cls: Type[_PsbtGlobalMap], global_map: Dict[bytes, bytes]
    ) -> _PsbtGlobalMap:
        out_map = {}
        for key, value in global_map.items():
            if key == b"\x00":
                out_map["tx"] = Tx.deserialize(value)
            elif key[0] == 0x01:  # TODO
                assert len(key) == 78 + 1
                assert len(value) % 4 == 0
                out_map["xpub"] = {
                    "xpub": key[1:].hex(),
                    "fingerprint": value[4:].hex(),
                    "derivation_path": value[4:].hex(),
                }
            elif key[0] == 0xFB:
                assert len(value) == 32
                out_map["version"] = int.from_bytes(value, "little")
            elif key[0] == 0xFC:
                pass  # proprietary use
            else:
                raise KeyError("Invalid key type")

        out = cls(**out_map)

        out.assert_valid()

        return out

    def serialize(self) -> bytes:
        out = b"\x01\x00"
        tx = self.tx.serialize()
        out += varint.encode(len(tx)) + tx
        if self.xpub:
            pass
        if self.version:
            pass
        return out

    def assert_valid(self) -> None:
        for vin in self.tx.vin:
            assert vin.scriptSig == []


_PsbtInputMap = TypeVar("_PsbtInputMap", bound="PsbtInputMap")


@dataclass
class PsbtInputMap:
    non_witness_utxo: Optional[Tx] = None
    witness_utxo: Optional[TxOut] = None
    partial_sig: Optional[Dict[str, str]] = None
    sighash_type: Optional[int] = None
    redeem_script: Optional[Script] = None
    witness_script: Optional[Script] = None
    bip32_derivation: Optional[Dict[str, str]] = None
    scriptSig: Optional[Script] = None
    scriptWitenss: Optional[Script] = None
    por_commitment: Optional[str] = None

    @classmethod
    def decode(
        cls: Type[_PsbtInputMap], input_map: Dict[bytes, bytes]
    ) -> _PsbtInputMap:
        out_map = {}
        for key, value in input_map.items():
            if key == b"\x00":
                out_map["non_witness_utxo"] = Tx.deserialize(value)
            elif key == b"\x01":
                out_map["witness_utxo"] = TxOut.deserialize(value)
            elif key[0] == 0x02:
                assert len(key) == 33 + 1
                out_map["partial_sig"] = {"pubkey": key[1:], "signature": value.hex()}
            elif key == b"\x03":
                assert len(value) == 4
                out_map["sighash_type"] = int.from_bytes(value, "little")
            elif key == b"\x04":
                out_map["redeem_script"] = script.decode(value)
            elif key == b"\x05":
                out_map["witness_script"] = script.decode(value)
            elif key[0] == 0x06:
                assert len(key) == 33 + 1
                assert len(value) % 4 == 0
                out_map["bip32_derivation"] = {
                    "xpub": key[1:].hex(),
                    "fingerprint": value[4:].hex(),
                    "derivation_path": value[4:].hex(),
                }
            elif key == b"\x07":
                out_map["scriptSig"] = script.decode(value)
            elif key == b"\x08":
                out_map["scriptWitenss"] = script.decode(value)
            elif key == b"\x09":
                out_map["por_commitment"] = value.hex()  # TODO: bip127
            elif key[0] == 0xFC:
                pass  # proprietary use
            else:
                raise KeyError("Invalid key type")

        out = cls(**out_map)

        out.assert_valid()

        return out

    def serialize(self) -> bytes:
        out = b""
        if self.non_witness_utxo:
            out += b"\x01\x00"
            utxo = self.non_witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.witness_utxo:
            out += b"\x01\x01"
            utxo = self.witness_utxo.serialize()
            out += varint.encode(len(utxo)) + utxo
        if self.partial_sig:
            pass
        if self.sighash_type:
            out += b"\x01\x03\x04"
            out += self.sighash_type.to_bytes(4, "little")
        if self.redeem_script:
            out += b"\x01\x04"
            out += script.serialize(self.redeem_script)
        if self.witness_script:
            pass
        if self.bip32_derivation:
            pass
        if self.scriptSig:
            out += b"\x01\x07"
            out += script.serialize(self.scriptSig)
        if self.scriptWitenss:
            out += b"\x01\x08"
            out += script.deserialize(self.scriptWitenss)
        if self.por_commitment:
            out += b"\x01\x09"
            c = bytes.fromhex(self.por_commitment)
            out += varint.encode(len(c)) + c
        return out

    def assert_valid(self) -> None:
        pass


_PsbtOutputMap = TypeVar("_PsbtOutputMap", bound="PsbtOutputMap")


@dataclass
class PsbtOutputMap:
    redeem_script: Optional[Script] = None
    witness_script: Optional[Script] = None
    bip32_derivation: Optional[Dict[str, str]] = None

    @classmethod
    def decode(
        cls: Type[_PsbtOutputMap], output_map: Dict[bytes, bytes]
    ) -> _PsbtOutputMap:
        out_map = {}
        for key, value in output_map.items():
            if key == b"\x00":
                out_map["redeem_script"] = script.decode(value)
            elif key == b"\x01":
                out_map["witness_script"] = script.decode(value)
            elif key[0] == 0x02:
                assert len(key) == 33 + 1
                assert len(value) % 4 == 0
                out_map["bip32_derivation"] = {
                    "xpub": key[1:].hex(),
                    "fingerprint": value[4:].hex(),
                    "derivation_path": value[4:].hex(),
                }
            elif key[0] == 0xFC:
                pass  # proprietary use
            else:
                raise KeyError("Invalid key type")

        out = cls(**out_map)

        out.assert_valid()

        return out

    def serialize(self) -> bytes:
        return b""

    def assert_valid(self) -> None:
        pass


_PSbt = TypeVar("_PSbt", bound="Psbt")


@dataclass
class Psbt:
    global_map: PsbtGlobalMap
    input_maps: List[PsbtInputMap]
    output_maps: List[PsbtOutputMap]

    @classmethod
    def deserialize(cls: Type[_PSbt], data: str) -> _PSbt:
        data = b64decode(data)

        magic_bytes = data[:5]
        assert magic_bytes == bytes.fromhex(
            "70736274ff"
        ), "Malformed psbt: missing magic bytes"

        data = data[5:]

        global_map, data = deserialize_map(data)
        global_map = PsbtGlobalMap.decode(global_map)

        input_len = len(global_map.tx.vin)
        output_len = len(global_map.tx.vout)

        input_maps = []
        for i in range(input_len):
            input_map, data = deserialize_map(data)
            input_map = PsbtInputMap.decode(input_map)
            input_maps.append(input_map)

        output_maps = []
        for i in range(output_len):
            output_map, data = deserialize_map(data)
            output_map = PsbtOutputMap.decode(output_map)
            output_maps.append(output_map)

        psbt = cls(
            global_map=global_map, input_maps=input_maps, output_maps=output_maps
        )

        psbt.assert_valid()

        return psbt

    def serialize(self) -> bytes:
        out = bytes.fromhex("70736274ff")
        out += self.global_map.serialize() + b"\x00"
        for input_map in self.input_maps:
            out += input_map.serialize() + b"\x00"
        for output_map in self.output_maps:
            out += output_map.serialize() + b"\x00"
        return b64encode(out).decode()

    def assert_valid(self) -> None:
        self.global_map.assert_valid()
        for input_map in self.input_maps:
            input_map.assert_valid()
        for output_map in self.output_maps:
            output_map.assert_valid()


def deserialize_map(data: bytes) -> Tuple[Dict[bytes, bytes], bytes]:
    assert len(data) != 0, "Malformed psbt: at least a map is missing"
    partial_map: Dict[bytes, bytes] = {}
    while True:
        # if len(data) == 0:
        #     return partial_map, data
        if data[0] == 0:
            data = data[1:]
            return partial_map, data
        key_len = varint.decode(data)
        data = data[len(varint.encode(key_len)) :]
        key = data[:key_len]
        data = data[key_len:]
        value_len = varint.decode(data)
        data = data[len(varint.encode(value_len)) :]
        value = data[:value_len]
        data = data[value_len:]
        assert key not in partial_map.keys(), "Malformed psbt: duplicate keys"
        partial_map[key] = value
