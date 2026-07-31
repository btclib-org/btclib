#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Network constants and associated functions."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from os import path
from typing import Any

from btclib.alias import Octets
from btclib.curves import Curve
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import bytes_from_octets

_KEY_SIZE: list[tuple[str, int]] = [
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
    bip32_prv: bytes  # xprv
    bip32_pub: bytes  # xpub

    # slip132 "m / 49h / 0h" p2wpkh-p2sh (i.e., p2sh-wrapped p2wpkh)
    slip132_p2wpkh_p2sh_prv: bytes  # yprv
    slip132_p2wpkh_p2sh_pub: bytes  # ypub

    # slip132 "m / 49h / 0h" p2wsh-p2sh (i.e., p2sh-wrapped p2wsh)
    slip132_p2wsh_p2sh_prv: bytes  # Yprv
    slip132_p2wsh_p2sh_pub: bytes  # Ypub

    # slip132 "m / 84h / 0h" p2wpkh
    slip132_p2wpkh_prv: bytes  # zprv
    slip132_p2wpkh_pub: bytes  # zpub

    # slip132 "m / 84h / 0h" p2wsh
    slip132_p2wsh_prv: bytes  # Zprv
    slip132_p2wsh_pub: bytes  # Zpub

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
        *,
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

    def to_dict(self, *, check_validity: bool = True) -> dict[str, str | None]:
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
        cls: type[Network], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Network:
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
            check_validity=check_validity,
        )

    def assert_valid(self) -> None:
        # no check on self.curve

        # the hrp is the human-readable part of every bech32 address of this
        # network, so it has to be a str. This was "str(self.hrp)" with the
        # result discarded, which is not a check of anything: str() accepts
        # every object there is. The bytes() calls below are the same idea
        # actually working, TypeError being what they raise for a field
        # rebound to something else
        if not isinstance(self.hrp, str):
            err_msg = f"invalid hrp type: {type(self.hrp).__name__}"
            raise BTClibTypeError(err_msg)

        for key, size in _KEY_SIZE:
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)


NETWORKS: dict[str, Network] = {}
datadir = path.join(path.dirname(__file__), "_data")
# order matters, and it is the order of the reverse lookups below: the
# first network holding a version prefix is the one they answer with, so
# testnet stays the answer it has always been for the four networks that
# share its prefixes. mainnet first, then the test networks oldest to
# newest -- signet.json and testnet4.json differ from testnet.json in
# the genesis block and the p2p magic, and in nothing else
for net in ("mainnet", "testnet", "regtest", "signet", "testnet4"):
    filename = path.join(datadir, f"{net}.json")
    with open(filename, encoding="ascii") as f:
        NETWORKS[net] = Network.from_dict(json.load(f))


def network_from_key_value(key: str, prefix: str | bytes | Curve) -> str | None:
    """Return network string from (key, value) pair.

    Warning: four of the five networks share one set of prefixes --
    testnet, regtest, signet and testnet4 differ in their genesis block
    and p2p magic and in nothing else -- so on any of them this mostly
    returns 'testnet', the first of the four. Which is not a problem as
    long as it is used for WIF/Base58Address/BIP32xkey, those being what
    the four have in common; it is not an answer to "which chain is
    this", and issue #207 is where deciding what it should return
    instead is being tracked.
    """
    return next(
        (
            network_str
            for network_str, network in NETWORKS.items()
            if getattr(network, key) == prefix
        ),
        None,
    )


def xpubversions_from_network(network: str = "mainnet") -> list[bytes]:
    network = network.strip().lower()
    return [
        NETWORKS[network].bip32_pub,
        NETWORKS[network].slip132_p2wsh_p2sh_pub,
        NETWORKS[network].slip132_p2wpkh_p2sh_pub,
        NETWORKS[network].slip132_p2wpkh_pub,
        NETWORKS[network].slip132_p2wsh_pub,
    ]


def xprvversions_from_network(network: str = "mainnet") -> list[bytes]:
    network = network.strip().lower()
    return [
        NETWORKS[network].bip32_prv,
        NETWORKS[network].slip132_p2wsh_p2sh_prv,
        NETWORKS[network].slip132_p2wpkh_p2sh_prv,
        NETWORKS[network].slip132_p2wpkh_prv,
        NETWORKS[network].slip132_p2wsh_prv,
    ]


# One block of version prefixes per network, in NETWORKS order, and
# _REPEATED_NETWORKS names the network of each entry. Built from
# NETWORKS rather than written out: this was `mainnet + testnet * 2` and
# three names indexed by hand, which said "three networks" in two places
# and in neither of them said why. Four of the five networks carry
# testnet's prefixes, so the lists hold each of them four times over and
# `.index()` finds the first -- which is testnet, the answer these
# lookups have always given for regtest and now give for signet and
# testnet4 too.
#
# That answer is the open half of issue #207 and is deliberately left
# where it was: with five networks behind one set of version bytes,
# "which network is this xpub from" wants a decision -- the canonical
# name, the whole list of candidates, or an error -- and adding the data
# is not the place to take it.
XPRV_VERSIONS_ALL = [
    version for network in NETWORKS for version in xprvversions_from_network(network)
]
XPUB_VERSIONS_ALL = [
    version for network in NETWORKS for version in xpubversions_from_network(network)
]
n_versions = len(xprvversions_from_network("mainnet"))
_NETWORKS = list(NETWORKS.keys())
_REPEATED_NETWORKS = [network for network in _NETWORKS for _ in range(n_versions)]


def network_from_xkeyversion(xkeyversion: bytes) -> str:
    """Return network string from the xkey version prefix.

    Warning: it returns 'testnet' for a testnet, regtest, signet or
    testnet4 version prefix, those four being the same bytes. Not a
    problem as long as it is used for WIF/Base58Address/BIP32Key, and
    not an answer to "which chain is this": see issue #207.
    """
    try:
        index = XPRV_VERSIONS_ALL.index(xkeyversion)
    except ValueError:
        index = XPUB_VERSIONS_ALL.index(xkeyversion)

    return _REPEATED_NETWORKS[index]


def curve_from_xkeyversion(xkeyversion: bytes) -> Curve:
    network = network_from_xkeyversion(xkeyversion)
    return NETWORKS[network].curve
