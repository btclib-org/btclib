#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.network` module."""

import pytest

from btclib import var_bytes
from btclib.curves.curve import CURVES
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash256
from btclib.network import (
    NETWORKS,
    Network,
    curve_from_xkeyversion,
    network_from_xkeyversion,
    xprvversions_from_network,
    xpubversions_from_network,
)
from tests.conftest import JsonGolden


def test_bad_network() -> None:
    with pytest.raises(BTClibValueError, match="invalid genesis_block length: "):
        Network(
            curve=CURVES["secp256k1"],
            magic_bytes="d9b4bef9",
            genesis_block="000000000019d6689c08",  # too short
            wif=b"\x80",
            p2pkh=b"\x00",
            p2sh=b"\x05",
            hrp="bc",
            bip32_prv="0488ade4",
            bip32_pub="0488b21e",
            slip132_p2wpkh_prv="04b2430c",
            slip132_p2wpkh_pub="04b24746",
            slip132_p2wpkh_p2sh_prv="049d7878",
            slip132_p2wpkh_p2sh_pub="049d7cb2",
            slip132_p2wsh_prv="02aa7a99",
            slip132_p2wsh_pub="02aa7ed3",
            slip132_p2wsh_p2sh_prv="0295b005",
            slip132_p2wsh_p2sh_pub="0295b43f",
        )


def test_curve_from_xkeyversion() -> None:
    for net_str, net in NETWORKS.items():
        all_versions = xpubversions_from_network(net_str)
        all_versions += xprvversions_from_network(net_str)
        for version in all_versions:
            # four of the five networks carry testnet's version bytes, so
            # the reverse lookup answers "testnet" for all of them. That
            # is the open half of issue #207 -- with the data for signet
            # and testnet4 in, "which network is this xpub from" wants a
            # decision -- and pinning today's answer is what makes the
            # decision visible when it is taken
            expected = "mainnet" if net_str == "mainnet" else "testnet"
            assert expected == network_from_xkeyversion(version)
            assert net.curve == curve_from_xkeyversion(version)


def test_space_and_caps() -> None:
    net = " MainNet "
    assert xpubversions_from_network(net), f"unknown network: {net}"

    with pytest.raises(KeyError):
        net = " MainNet2 "
        xpubversions_from_network(net)


def test_numbers_of_networks() -> None:
    assert len(NETWORKS) == 5


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    for network_name, net in NETWORKS.items():
        assert net == Network.from_dict(net.to_dict())

        json_golden(f"{network_name}.json", net.to_dict())


# Bitcoin Core's default signet challenge, kernel/chainparams.cpp: a
# 1-of-2 multisig, and the only input to the p2p magic below
SIGNET_CHALLENGE = (
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430"
    "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"
)


def test_the_signet_magic_is_derived_and_not_copied() -> None:
    """Signet's p2p magic is a function of its challenge, so compute it.

    Core: "message start is defined as the first 4 bytes of the sha256d
    of the block script", the script being serialized with its
    CompactSize length, and the four bytes taken in the order the digest
    produces them -- which is the reverse of how this library writes
    magic_bytes, as the other four networks show.

    Which is also the limitation to record: a *custom* signet has a
    different challenge and therefore a different magic, so
    NETWORKS["signet"] describes the default signet alone. Anything else
    is a Network built by the caller, with this computation for the one
    field that changes.
    """
    challenge = bytes.fromhex(SIGNET_CHALLENGE)
    assert len(challenge) == 71
    core_message_start = hash256(var_bytes.serialize(challenge))[:4]
    assert core_message_start.hex() == "0a03cf40"
    assert NETWORKS["signet"].magic_bytes == core_message_start[::-1]


def test_the_test_networks_differ_from_testnet_in_two_fields() -> None:
    """Signet and testnet4 reuse everything of testnet but chain identity.

    The wif, p2pkh, p2sh, hrp and bip32 version bytes are testnet's,
    which is the whole reason the reverse lookups have an ambiguity to
    answer for; what a network of its own buys them is a genesis block
    and a p2p magic.
    """
    testnet = NETWORKS["testnet"].to_dict()
    for name in ("signet", "testnet4", "regtest"):
        differing = {
            key
            for key, value in NETWORKS[name].to_dict().items()
            if testnet[key] != value
        }
        expected = {"magic_bytes", "genesis_block"}
        if name == "regtest":
            expected.add("hrp")  # bcrt, where signet and testnet4 are tb
        assert differing == expected, name

    assert NETWORKS["signet"].hrp == "tb"
    assert NETWORKS["testnet4"].hrp == "tb"
    assert NETWORKS["testnet4"].genesis_block.hex() == (
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
    )
    assert NETWORKS["signet"].genesis_block.hex() == (
        "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6"
    )
    # every network is a distinct chain, and the genesis block says so
    genesis = {net.genesis_block for net in NETWORKS.values()}
    assert len(genesis) == len(NETWORKS)
    magics = {net.magic_bytes for net in NETWORKS.values()}
    assert len(magics) == len(NETWORKS)
