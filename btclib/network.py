#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Network constants and associated functions."""


import json
from dataclasses import dataclass
from os import path
from typing import Any, Dict, List, Mapping, Optional, Tuple, Type, TypeVar, Union

from btclib.alias import Octets
from btclib.ecc.curve import CURVES, Curve
from btclib.exceptions import BTClibValueError
from btclib.utils import bytes_from_octets

_KEY_SIZE: List[Tuple[str, int]] = [
    ("magic_bytes", 4),
    ("genesis_block", 32),
    ("wif", 1),
    ("p2pkh", 1),
    ("p2sh", 1),
    ("bip32_prv", 4),
    ("bip32_pub", 4),
    ("slip132_p2wpkh_prv", 4),
    ("slip132_p2wpkh_pub", 4),
    ("slip132_p2wpkh_p2sh_prv", 4),
    ("slip132_p2wpkh_p2sh_pub", 4),
    ("slip132_p2wsh_prv", 4),
    ("slip132_p2wsh_pub", 4),
    ("slip132_p2wsh_p2sh_prv", 4),
    ("slip132_p2wsh_p2sh_pub", 4),
]

_Network = TypeVar("_Network", bound="Network")


@dataclass(frozen=True)
class Network:
    curve: Curve

    magic_bytes: bytes
    genesis_block: bytes

    # base58 wif starts with 'K' or 'L' if compressed else '5'
    wif: bytes

    # base58 address starts with '1'
    p2pkh: bytes
    # base58 address starts with '3'
    p2sh: bytes

    # bech32_address starts with 'bc1'
    hrp: str

    # slip132 "m / 44h / 0h" p2pkh or p2sh
    bip32_prv: bytes
    bip32_pub: bytes

    # slip132 "m / 49h / 0h" p2wpkh-p2sh (p2sh-wrapped legacy-segwit p2wpkh)
    slip132_p2wpkh_prv: bytes
    slip132_p2wpkh_pub: bytes

    # slip132 p2wsh-p2sh (p2sh-wrapped legacy-segwit p2wsh)
    slip132_p2wpkh_p2sh_prv: bytes
    slip132_p2wpkh_p2sh_pub: bytes

    # slip132 "m / 84h / 0h" p2wpkh (native-segwit p2wpkh)
    slip132_p2wsh_prv: bytes
    slip132_p2wsh_pub: bytes

    # slip132 p2wsh (native-segwit p2wsh)
    slip132_p2wsh_p2sh_prv: bytes
    slip132_p2wsh_p2sh_pub: bytes

    def __init__(
        self,
        curve: Curve,
        magic_bytes: Octets,
        genesis_block: Octets,
        wif: Octets,
        p2pkh: Octets,
        p2sh: Octets,
        hrp: str,
        bip32_prv: Octets,
        bip32_pub: Octets,
        slip132_p2wpkh_prv: Octets,
        slip132_p2wpkh_pub: Octets,
        slip132_p2wpkh_p2sh_prv: Octets,
        slip132_p2wpkh_p2sh_pub: Octets,
        slip132_p2wsh_prv: Octets,
        slip132_p2wsh_pub: Octets,
        slip132_p2wsh_p2sh_prv: Octets,
        slip132_p2wsh_p2sh_pub: Octets,
        check_validity: bool = True,
    ) -> None:

        object.__setattr__(self, "curve", curve)
        object.__setattr__(self, "magic_bytes", bytes_from_octets(magic_bytes))
        object.__setattr__(self, "genesis_block", bytes_from_octets(genesis_block))

        object.__setattr__(self, "wif", bytes_from_octets(wif))

        object.__setattr__(self, "p2pkh", bytes_from_octets(p2pkh))
        object.__setattr__(self, "p2sh", bytes_from_octets(p2sh))

        object.__setattr__(self, "hrp", hrp)

        object.__setattr__(self, "bip32_prv", bytes_from_octets(bip32_prv))
        object.__setattr__(self, "bip32_pub", bytes_from_octets(bip32_pub))

        object.__setattr__(
            self, "slip132_p2wpkh_prv", bytes_from_octets(slip132_p2wpkh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wpkh_pub", bytes_from_octets(slip132_p2wpkh_pub)
        )

        object.__setattr__(
            self, "slip132_p2wpkh_p2sh_prv", bytes_from_octets(slip132_p2wpkh_p2sh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wpkh_p2sh_pub", bytes_from_octets(slip132_p2wpkh_p2sh_pub)
        )

        object.__setattr__(
            self, "slip132_p2wsh_prv", bytes_from_octets(slip132_p2wsh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wsh_pub", bytes_from_octets(slip132_p2wsh_pub)
        )

        object.__setattr__(
            self, "slip132_p2wsh_p2sh_prv", bytes_from_octets(slip132_p2wsh_p2sh_prv)
        )
        object.__setattr__(
            self, "slip132_p2wsh_p2sh_pub", bytes_from_octets(slip132_p2wsh_p2sh_pub)
        )

        if check_validity:
            self.assert_valid()

    def to_dict(self, check_validity: bool = True) -> Dict[str, Optional[str]]:

        if check_validity:
            self.assert_valid()

        return {
            "curve": self.curve.name,
            "magic_bytes": self.magic_bytes.hex(),
            "genesis_block": self.genesis_block.hex(),
            "wif": self.wif.hex(),
            "p2pkh": self.p2pkh.hex(),
            "p2sh": self.p2sh.hex(),
            "hrp": self.hrp,
            "bip32_prv": self.bip32_prv.hex(),
            "bip32_pub": self.bip32_pub.hex(),
            "slip132_p2wpkh_prv": self.slip132_p2wpkh_prv.hex(),
            "slip132_p2wpkh_pub": self.slip132_p2wpkh_pub.hex(),
            "slip132_p2wpkh_p2sh_prv": self.slip132_p2wpkh_p2sh_prv.hex(),
            "slip132_p2wpkh_p2sh_pub": self.slip132_p2wpkh_p2sh_pub.hex(),
            "slip132_p2wsh_prv": self.slip132_p2wsh_prv.hex(),
            "slip132_p2wsh_pub": self.slip132_p2wsh_pub.hex(),
            "slip132_p2wsh_p2sh_prv": self.slip132_p2wsh_p2sh_prv.hex(),
            "slip132_p2wsh_p2sh_pub": self.slip132_p2wsh_p2sh_pub.hex(),
        }

    @classmethod
    def from_dict(
        cls: Type[_Network], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> _Network:

        return cls(
            CURVES[dict_["curve"]],
            dict_["magic_bytes"],
            dict_["genesis_block"],
            dict_["wif"],
            dict_["p2pkh"],
            dict_["p2sh"],
            dict_["hrp"],
            dict_["bip32_prv"],
            dict_["bip32_pub"],
            dict_["slip132_p2wpkh_prv"],
            dict_["slip132_p2wpkh_pub"],
            dict_["slip132_p2wpkh_p2sh_prv"],
            dict_["slip132_p2wpkh_p2sh_pub"],
            dict_["slip132_p2wsh_prv"],
            dict_["slip132_p2wsh_pub"],
            dict_["slip132_p2wsh_p2sh_prv"],
            dict_["slip132_p2wsh_p2sh_pub"],
            check_validity,
        )

    def assert_valid(self) -> None:

        # no check on self.curve

        str(self.hrp)

        for key, size in _KEY_SIZE:
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)


NETWORKS: Dict[str, Network] = {}
datadir = path.join(path.dirname(__file__), "_data")
for net in ("mainnet", "testnet", "regtest"):
    filename = path.join(datadir, net + ".json")
    with open(filename, "r") as f:
        NETWORKS[net] = Network.from_dict(json.load(f))


def network_from_key_value(key: str, prefix: Union[str, bytes, Curve]) -> Optional[str]:
    """Return network string from (key, value) pair.

    Warning: when used on 'regtest' it mostly returns 'testnet',
    which is not a problem as long as it is used for
    WIF/Base58Address/BIP32xkey
    because the two networks share the same prefixes.
    """
    for network in NETWORKS:
        if getattr(NETWORKS[network], key) == prefix:
            return network
    return None


def xpubversions_from_network(network: str = "mainnet") -> List[bytes]:
    network = network.strip().lower()
    return [
        NETWORKS[network].bip32_pub,
        NETWORKS[network].slip132_p2wsh_p2sh_pub,
        NETWORKS[network].slip132_p2wpkh_p2sh_pub,
        NETWORKS[network].slip132_p2wpkh_pub,
        NETWORKS[network].slip132_p2wsh_pub,
    ]


def xprvversions_from_network(network: str = "mainnet") -> List[bytes]:
    network = network.strip().lower()
    return [
        NETWORKS[network].bip32_prv,
        NETWORKS[network].slip132_p2wsh_p2sh_prv,
        NETWORKS[network].slip132_p2wpkh_p2sh_prv,
        NETWORKS[network].slip132_p2wpkh_prv,
        NETWORKS[network].slip132_p2wsh_prv,
    ]


XPRV_VERSIONS_ALL = (
    xprvversions_from_network("mainnet") + xprvversions_from_network("testnet") * 2
)
XPUB_VERSIONS_ALL = (
    xpubversions_from_network("mainnet") + xpubversions_from_network("testnet") * 2
)
n_versions = len(xprvversions_from_network("mainnet"))
_NETWORKS = list(NETWORKS.keys())
_REPEATED_NETWORKS = (
    [_NETWORKS[0]] * n_versions
    + [_NETWORKS[1]] * n_versions
    + [_NETWORKS[2]] * n_versions
)


def network_from_xkeyversion(xkeyversion: bytes) -> str:
    """Return network string from the xkey version prefix.

    Warning: when used on 'regtest' it returns 'testnet', which is not
    a problem as long as it is used for WIF/Base58Address/BIP32Key
    because the two networks share the same prefixes.
    """
    try:
        index = XPRV_VERSIONS_ALL.index(xkeyversion)
    except ValueError:
        index = XPUB_VERSIONS_ALL.index(xkeyversion)

    return _REPEATED_NETWORKS[index]


def curve_from_xkeyversion(xkeyversion: bytes) -> Curve:
    network = network_from_xkeyversion(xkeyversion)
    return NETWORKS[network].curve
