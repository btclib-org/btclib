#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Transaction Output (TxOut) dataclass.

Dataclass encapsulating value and script_pub_key
(and network to convert script_pub_key to and from address).
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Type, TypeVar

from btclib import var_bytes
from btclib.alias import BinaryData, Octets, String
from btclib.amount import btc_from_sats, sats_from_btc
from btclib.exceptions import BTClibValueError
from btclib.network import NETWORKS
from btclib.script.address import (
    address_from_script_pub_key,
    script_pub_key_from_address,
)
from btclib.script.script_pub_key import payload_from_script_pub_key
from btclib.utils import bytes_from_octets, bytesio_from_binarydata

_TxOut = TypeVar("_TxOut", bound="TxOut")


# FIXME make it frozen
@dataclass
class TxOut:
    # 8 bytes, unsigned little endian
    value: int  # denominated in satoshi
    script_pub_key: bytes
    network: str

    @property
    def nValue(self) -> int:  # pylint: disable=invalid-name
        "Return the nValue int for compatibility with CTxOut."
        return self.value

    @property
    def scriptPubKey(self) -> bytes:  # pylint: disable=invalid-name
        "Return the scriptPubKey bytes for compatibility with CTxOut."
        return self.script_pub_key

    @property
    def script_type(self) -> str:
        "Return the script_type, if any."
        return payload_from_script_pub_key(self.script_pub_key)[0]

    @property
    def addresses(self) -> List[str]:
        "Return the addresses, if any."
        return [address_from_script_pub_key(self.script_pub_key, self.network)]

    def __init__(
        self,
        value: int = 0,
        script_pub_key: Octets = b"",
        network: str = "mainnet",
        check_validity: bool = True,
    ) -> None:

        object.__setattr__(self, "value", value)
        object.__setattr__(self, "script_pub_key", bytes_from_octets(script_pub_key))
        object.__setattr__(self, "network", network)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        btc_from_sats(self.value)
        # TODO validate script_pub_key
        if self.network not in NETWORKS:
            raise BTClibValueError(f"unknown network: {self.network}")

    def to_dict(self, check_validity: bool = True) -> Dict[str, Any]:

        if check_validity:
            self.assert_valid()

        return {
            "value": str(btc_from_sats(self.value)),
            "scriptPubKey": self.script_pub_key.hex(),  # TODO make it { "asm": "", "hex": "" }
            "type": self.script_type,
            "reqSigs": None,  # FIXME
            "addresses": self.addresses,
            "network": self.network,
        }

    @classmethod
    def from_dict(
        cls: Type[_TxOut], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> _TxOut:

        return cls(
            sats_from_btc(dict_["value"]),
            dict_["scriptPubKey"],
            dict_.get("network", "mainnet"),
            check_validity,
        )

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
