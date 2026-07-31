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

from btclib.alias import NetworkType, Octets
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

    # "main" or "test": see NetworkType in alias.py for why this is the
    # one question the version bytes can still answer, and the three
    # network_type_from_* functions below for the answering
    network_type: NetworkType

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
        # last and defaulted, where the field is declared second: a
        # caller building a Network by hand -- a custom signet, which is
        # what issue #207 says callers do today -- keeps every existing
        # call valid, and "test" is the safe direction for the default.
        # Defaulting to "main" would let a forgotten argument claim a
        # made-up chain is the real one
        network_type: NetworkType = "test",
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "curve", curve)
        object.__setattr__(self, "network_type", network_type)
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
            "network_type": self.network_type,
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
            # .get, alone among these keys: a dict serialized before the
            # field existed still loads, as a test network
            dict_.get("network_type", "test"),
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

        # NetworkType is a Literal, which is a mypy fact and not a runtime
        # one: from_dict takes whatever the json says, so this is the only
        # place a third network type can be refused
        if self.network_type not in ("main", "test"):
            err_msg = f"invalid network type: {self.network_type!r}"
            raise BTClibValueError(err_msg)

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


# Three questions, three functions, and one scan -- the plural one --
# because "which networks carry this prefix" is the only fact here and it
# belongs in one place. Which of the three to reach for:
#
# - networks_from_*: every candidate, oldest first. The whole truth, for
#   a caller that wants to show it or count it
# - network_from_*: the oldest candidate. The right answer for byte-level
#   work -- re-encoding an address, reading a curve, finding the sibling
#   version of an xprv -- because every candidate agrees on those bytes.
#   It is not an answer to "which chain is this"
# - network_type_from_*: "main" or "test". The honest answer to "is this
#   the real thing", and the one this module recommends: unlike the
#   singular name it cannot be wrong, no prefix crossing that boundary
#
# What none of them is is a substitute for the forward check, which is
# what a caller who *knows* the chain should use: a version among
# xprvversions_from_network(net), a prefix equal to NETWORKS[net].wif.
# That check is exact for all five networks, and issue #207 records the
# WIF path having got this wrong by comparing reverse-lookup names.
def networks_from_key_value(key: str, prefix: str | bytes | Curve) -> list[str]:
    """Return every network with the (key, value) pair, oldest first.

    The list is the ordinal the singular lookups below hide: [0] is the
    canonical answer, [n] the nth network sharing those bytes -- and its
    length says how many there are, which is what "testnet" alone could
    never say. Mostly it holds the four test networks (one set of
    prefixes between them) or exactly one (mainnet's bytes, and
    regtest's bcrt hrp, are unique).
    """
    return [
        network_str
        for network_str, network in NETWORKS.items()
        if getattr(network, key) == prefix
    ]


def network_from_key_value(key: str, prefix: str | bytes | Curve) -> str | None:
    """Return the oldest network with the (key, value) pair, else None.

    Oldest, i.e. 'testnet' for the prefixes testnet, regtest, signet and
    testnet4 share, 'regtest' for the bcrt hrp that is regtest's alone,
    'mainnet' for mainnet's. That is the network to encode *with*: the
    candidates differ in genesis block and p2p magic, which no encoding
    here reads, so the bytes it yields are right for all of them.
    It is not an answer to "which chain is this": use
    network_type_from_key_value for what the prefix does say, or
    networks_from_key_value for the candidates.
    """
    networks = networks_from_key_value(key, prefix)
    return networks[0] if networks else None


def network_type_from_key_value(
    key: str, prefix: str | bytes | Curve
) -> NetworkType | None:
    """Return "main" or "test" from a (key, value) pair, None if unknown.

    Unambiguous where the network name is not: no prefix of a test
    network equals a mainnet prefix, on any field, so every candidate
    has the same type and the first one speaks for all.
    """
    networks = networks_from_key_value(key, prefix)
    return NETWORKS[networks[0]].network_type if networks else None


def network_type_from_network(network: str = "mainnet") -> NetworkType:
    """Return the "main"/"test" type of a network name."""
    network = network.strip().lower()
    return NETWORKS[network].network_type


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


# every xkey version this library knows, one block per network in
# NETWORKS order. Four of the five networks carry testnet's, so each of
# those appears four times over -- which is why the lookups below ask
# each network whether it holds the version, rather than indexing a
# parallel list of names as they used to: `_REPEATED_NETWORKS` and the
# `n_versions` arithmetic that produced it are gone, the position of a
# repeated entry having meant nothing
XPRV_VERSIONS_ALL = [
    version for network in NETWORKS for version in xprvversions_from_network(network)
]
XPUB_VERSIONS_ALL = [
    version for network in NETWORKS for version in xpubversions_from_network(network)
]


def networks_from_xkeyversion(xkeyversion: bytes) -> list[str]:
    """Return every network with the xkey version prefix, oldest first."""
    return [
        network
        for network in NETWORKS
        if xkeyversion in xprvversions_from_network(network)
        or xkeyversion in xpubversions_from_network(network)
    ]


def network_from_xkeyversion(xkeyversion: bytes) -> str:
    """Return the oldest network with the xkey version prefix.

    'testnet' for a testnet, regtest, signet or testnet4 version, those
    four being the same bytes: the network to derive and re-encode
    *with*, since all four agree on every version prefix. It is not an
    answer to "which chain is this" -- network_type_from_xkeyversion is
    what a prefix can answer, networks_from_xkeyversion the candidates.
    """
    networks = networks_from_xkeyversion(xkeyversion)
    if not networks:
        # was a bare ValueError leaked by list.index, whose message named
        # the list; BTClibValueError subclasses ValueError, so an `except
        # ValueError` caller is unaffected
        err_msg = f"unknown xkey version: 0x{xkeyversion.hex()}"
        raise BTClibValueError(err_msg)
    return networks[0]


def network_type_from_xkeyversion(xkeyversion: bytes) -> NetworkType:
    """Return "main" or "test" from an xkey version prefix.

    Unambiguous where the network name is not: no test network version
    equals a mainnet one, so an xprv is either the real thing or not.
    """
    return NETWORKS[network_from_xkeyversion(xkeyversion)].network_type


def curve_from_xkeyversion(xkeyversion: bytes) -> Curve:
    network = network_from_xkeyversion(xkeyversion)
    return NETWORKS[network].curve
