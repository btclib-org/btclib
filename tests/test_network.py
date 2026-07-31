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
    network_from_key_value,
    network_from_xkeyversion,
    network_type_from_key_value,
    network_type_from_network,
    network_type_from_xkeyversion,
    networks_from_key_value,
    networks_from_xkeyversion,
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
            # the singular lookup answers with testnet, the oldest of
            # them: the documented contract since issue #207, and the
            # right network to re-encode with, all four agreeing on
            # every version prefix
            expected = "mainnet" if net_str == "mainnet" else "testnet"
            assert expected == network_from_xkeyversion(version)
            assert net.curve == curve_from_xkeyversion(version)
            # what the version bytes *can* say, and cannot get wrong
            assert net.network_type == network_type_from_xkeyversion(version)


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


# the prefix fields, i.e. every field a reverse lookup is asked about:
# the two chain-identity fields and the curve are not prefixes, and no
# lookup in this library keys on them
_PREFIX_FIELDS = (
    "wif",
    "p2pkh",
    "p2sh",
    "hrp",
    "bip32_prv",
    "bip32_pub",
    "slip132_p2wpkh_prv",
    "slip132_p2wpkh_pub",
    "slip132_p2wpkh_p2sh_prv",
    "slip132_p2wpkh_p2sh_pub",
    "slip132_p2wsh_prv",
    "slip132_p2wsh_pub",
    "slip132_p2wsh_p2sh_prv",
    "slip132_p2wsh_p2sh_pub",
)


def test_no_prefix_crosses_the_main_test_boundary() -> None:
    """The invariant the network type rests on, checked rather than assumed.

    A network *name* cannot be recovered from a prefix -- four networks
    share one set of them -- but "main or test" always can, and only
    because no test network prefix equals a mainnet prefix. Every field
    against every field, not field against same field: the type would be
    just as wrong if testnet's p2sh were mainnet's p2pkh, since a caller
    asks the lookups one field at a time and a collision anywhere makes
    an answer of "main" reachable from test bytes.
    """
    mainnet_prefixes = {getattr(NETWORKS["mainnet"], f) for f in _PREFIX_FIELDS}
    for name, net in NETWORKS.items():
        if net.network_type == "main":
            assert name == "mainnet"
            continue
        for field in _PREFIX_FIELDS:
            assert getattr(net, field) not in mainnet_prefixes, (name, field)

    # so mainnet is the only network of its type, and the four test
    # networks are the rest: the shape the type is a name for
    types = [net.network_type for net in NETWORKS.values()]
    assert types.count("main") == 1
    assert types.count("test") == len(NETWORKS) - 1


def test_the_three_lookups_answer_one_question_each() -> None:
    """Candidates, canonical name, type -- and how they relate."""
    # the shared test prefixes: four candidates on the base58 fields,
    # three on the hrp, regtest's bcrt being its own
    assert networks_from_key_value("wif", b"\xef") == [
        "testnet",
        "regtest",
        "signet",
        "testnet4",
    ]
    assert networks_from_key_value("hrp", "tb") == ["testnet", "signet", "testnet4"]
    assert networks_from_key_value("hrp", "bcrt") == ["regtest"]
    assert networks_from_key_value("hrp", "bc") == ["mainnet"]

    # the singular lookup is the [0] of the plural one, everywhere
    for field in _PREFIX_FIELDS:
        for net in NETWORKS.values():
            prefix = getattr(net, field)
            candidates = networks_from_key_value(field, prefix)
            assert candidates
            assert network_from_key_value(field, prefix) == candidates[0]
            # and the type is one answer for all the candidates, which is
            # what makes taking the first of them sound
            assert len({NETWORKS[c].network_type for c in candidates}) == 1
            assert network_type_from_key_value(field, prefix) == net.network_type

    # unknown bytes: None from both, and an empty list rather than a raise
    assert networks_from_key_value("hrp", "nosuchhrp") == []
    assert network_from_key_value("hrp", "nosuchhrp") is None
    assert network_type_from_key_value("hrp", "nosuchhrp") is None


def test_the_three_xkeyversion_lookups() -> None:
    for name, net in NETWORKS.items():
        for version in xprvversions_from_network(name) + xpubversions_from_network(
            name
        ):
            candidates = networks_from_xkeyversion(version)
            assert network_from_xkeyversion(version) == candidates[0]
            assert network_type_from_xkeyversion(version) == net.network_type
            expected = (
                ["mainnet"]
                if name == "mainnet"
                else [
                    "testnet",
                    "regtest",
                    "signet",
                    "testnet4",
                ]
            )
            assert candidates == expected

    # an unknown version: a BTClibValueError, which is a ValueError, as
    # the bare one list.index used to leak was
    assert networks_from_xkeyversion(b"\x00\x00\x00\x00") == []
    with pytest.raises(BTClibValueError, match="unknown xkey version: 0x00000000"):
        network_from_xkeyversion(b"\x00\x00\x00\x00")
    with pytest.raises(ValueError, match="unknown xkey version"):
        network_type_from_xkeyversion(b"\xff\xff\xff\xff")


def test_network_type_from_network() -> None:
    assert network_type_from_network() == "main"
    assert network_type_from_network("mainnet") == "main"
    # the same space-and-caps tolerance as xpubversions_from_network
    assert network_type_from_network(" MainNet ") == "main"
    for name in ("testnet", "regtest", "signet", "testnet4"):
        assert network_type_from_network(name) == "test"
    with pytest.raises(KeyError):
        network_type_from_network("nosuchnet")


def test_the_network_type_default_is_test() -> None:
    """A Network built without one is a test network, not the real chain.

    Issue #207 filed this as the case that matters: a caller who needs a
    custom signet builds a Network by hand, and a forgotten argument
    must not let it claim to be mainnet.
    """
    mainnet = NETWORKS["mainnet"].to_dict()
    del mainnet["network_type"]
    assert Network.from_dict(mainnet).network_type == "test"

    # every field of mainnet, so nothing but the default is at work here
    assert Network.from_dict(mainnet).p2pkh == NETWORKS["mainnet"].p2pkh

    with pytest.raises(BTClibValueError, match="invalid network type: 'mainnet'"):
        # the type is not a network name, and the json is what says it
        Network.from_dict({**NETWORKS["mainnet"].to_dict(), "network_type": "mainnet"})
