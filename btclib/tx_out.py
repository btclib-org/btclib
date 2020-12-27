#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from dataclasses import InitVar, dataclass, field
from typing import Dict, Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config
from dataclasses_json.core import Json

from btclib import var_bytes
from btclib.alias import BinaryData, String
from btclib.exceptions import BTClibValueError
from btclib.script_pub_key import payload_from_script_pub_key
from btclib.script_pub_key_address import (
    address_from_script_pub_key,
    script_pub_key_from_address,
)
from btclib.utils import bytesio_from_binarydata
from btclib.amount import MAX_SATOSHI, btc_from_sats, sats_from_btc

_TxOut = TypeVar("_TxOut", bound="TxOut")


@dataclass
class TxOut(DataClassJsonMixin):
    # 8 bytes, unsigned little endian
    value: int = field(  # denominated in satoshi
        default=0,
        metadata=config(encoder=lambda v: str(btc_from_sats(v)), decoder=sats_from_btc),
    )
    # FIXME: make it
    # "script_pub_key": {
    #    "asm": "0 d85c2b71d0060b09c9886aeb815e50991dda124d",
    #    "hex": "0014d85c2b71d0060b09c9886aeb815e50991dda124d",
    #    "reqSigs": 1,
    #    "type": "witness_v0_keyhash",
    #    "addresses": [
    #        "bc1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdgwyw6k"
    #    ]
    # }
    script_pub_key: bytes = field(
        default=b"",
        metadata=config(
            field_name="scriptPubKey", encoder=lambda v: v.hex(), decoder=bytes.fromhex
        ),
    )
    _script_type: str = field(
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="type"),
    )
    network: str = "mainnet"
    _address: str = field(
        default="",
        init=False,
        repr=False,
        compare=False,
        metadata=config(field_name="address"),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def _set_properties(self) -> None:
        self._address = self.address
        self._script_type = self.script_type

    def to_dict(self, encode_json=False) -> Dict[str, Json]:
        self._set_properties()
        return super().to_dict(encode_json)

    @property
    def nValue(self) -> int:  # pylint: disable=invalid-name
        "Return the nValue int for compatibility with CTxOut."
        return self.value

    @property
    def scriptPubKey(self) -> bytes:  # pylint: disable=invalid-name
        "Return the scriptPubKey bytes for compatibility with CTxOut."
        return self.script_pub_key

    @property
    def address(self) -> str:
        "Return the address, if any."
        return address_from_script_pub_key(self.script_pub_key, self.network)

    @property
    def script_type(self) -> str:
        "Return the script_type, if any."
        return payload_from_script_pub_key(self.script_pub_key)[0]

    def assert_valid(self) -> None:
        if self.value < 0:
            raise BTClibValueError(f"negative value: {self.value}")
        if self.value > MAX_SATOSHI:
            raise BTClibValueError(f"too many satoshis: {hex(self.value)}")

        self._set_properties()

    # def is_witness(self) -> Tuple[bool, int, bytes]:
    #     return is_witness(self.script_pub_key)

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        out = self.value.to_bytes(8, byteorder="little", signed=False)
        out += var_bytes.serialize(self.script_pub_key)
        return out

    @classmethod
    def parse(
        cls: Type[_TxOut], data: BinaryData, check_validity: bool = True
    ) -> _TxOut:
        stream = bytesio_from_binarydata(data)
        value = int.from_bytes(stream.read(8), byteorder="little", signed=False)
        script_pub_key = var_bytes.parse(stream)
        return cls(value, script_pub_key, "mainnet", check_validity)

    @classmethod
    def from_address(cls: Type[_TxOut], value: int, address: String) -> _TxOut:
        script_pub_key, network = script_pub_key_from_address(address)
        return cls(value, script_pub_key, network)
