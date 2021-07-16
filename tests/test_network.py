#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.network` module."

import json
from os import path

import pytest

from btclib.ecc.curve import CURVES
from btclib.exceptions import BTClibValueError
from btclib.network import (
    NETWORKS,
    Network,
    curve_from_xkeyversion,
    network_from_xkeyversion,
    xprvversions_from_network,
    xpubversions_from_network,
)


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
    for net in NETWORKS:
        all_versions = xpubversions_from_network(net) + xprvversions_from_network(net)
        for version in all_versions:
            # unfortunately 'regtest' shares same versions with 'testnet'
            if net != "regtest":
                assert net == network_from_xkeyversion(version)
            assert NETWORKS[net].curve == curve_from_xkeyversion(version)


def test_space_and_caps() -> None:
    net = " MainNet "
    assert xpubversions_from_network(net), f"unknown network: {net}"

    with pytest.raises(KeyError):
        net = " MainNet2 "
        xpubversions_from_network(net)


def test_numbers_of_networks() -> None:
    assert len(NETWORKS) == 3


def test_dataclasses_json_dict() -> None:
    for network_name, net in NETWORKS.items():
        assert net == Network.from_dict(net.to_dict())

        datadir = path.join(path.dirname(__file__), "_generated_files")
        filename = path.join(datadir, network_name + ".json")
        with open(filename, "w") as file_:
            json.dump(NETWORKS[network_name].to_dict(), file_, indent=4)
