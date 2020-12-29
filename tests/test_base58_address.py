#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.base58_address` module."

from typing import List, Tuple

import pytest

from btclib import base58_address, bech32_address, script
from btclib.base58 import b58encode
from btclib.base58_wif import wif_from_prv_key
from btclib.bip32 import bip32, slip132
from btclib.ecc.sec_point import bytes_from_point, point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160_from_key
from btclib.network import NETWORKS
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.utils import hash160, sha256


def test_address_from_h160() -> None:
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    prefix, payload, network, _ = base58_address.h160_from_address(address)
    assert address == base58_address.address_from_h160(prefix, payload, network)

    address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    prefix, payload, network, _ = base58_address.h160_from_address(address)
    assert address == base58_address.address_from_h160(prefix, payload, network)

    address = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    prefix, payload, network, _ = base58_address.h160_from_address(address)
    assert address == base58_address.address_from_h160(prefix, payload, network)

    err_msg = "invalid mainnet base58 address prefix: "
    with pytest.raises(BTClibValueError, match=err_msg):
        base58_address.address_from_h160(b"\xbb", payload, network)


def test_p2pkh_from_wif() -> None:
    seed = b"\x00" * 32  # better be a documented test case
    rxprv = bip32.rootxprv_from_seed(seed)
    path = "m/0h/0h/12"
    xprv = bip32.derive(rxprv, path)
    wif = wif_from_prv_key(xprv)
    assert wif == "L2L1dqRmkmVtwStNf5wg8nnGaRn3buoQr721XShM4VwDbTcn9bpm"
    pub_key, _ = pub_keyinfo_from_prv_key(wif)
    address = base58_address.p2pkh(pub_key)
    xpub = bip32.xpub_from_xprv(xprv)
    assert address == slip132.address_from_xpub(xpub)

    err_msg = "not a private key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        wif_from_prv_key(xpub)


def test_p2pkh_from_pub_key() -> None:
    # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert address == base58_address.p2pkh(pub_key)
    assert address == base58_address.p2pkh(pub_key, compressed=True)
    _, h160, _, _ = base58_address.h160_from_address(address)
    assert h160 == hash160(pub_key)

    # trailing/leading spaces in address string
    assert address == base58_address.p2pkh(" " + pub_key)
    assert h160 == hash160(" " + pub_key)
    assert address == base58_address.p2pkh(pub_key + " ")
    assert h160 == hash160(pub_key + " ")

    uncompr_pub_key = bytes_from_point(point_from_octets(pub_key), compressed=False)
    uncompr_address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    assert uncompr_address == base58_address.p2pkh(uncompr_pub_key, compressed=False)
    assert uncompr_address == base58_address.p2pkh(uncompr_pub_key)
    _, uncompr_h160, _, _ = base58_address.h160_from_address(uncompr_address)
    assert uncompr_h160 == hash160(uncompr_pub_key)

    err_msg = "not a private or uncompressed public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert uncompr_address == base58_address.p2pkh(pub_key, compressed=False)

    err_msg = "not a private or compressed public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert address == base58_address.p2pkh(uncompr_pub_key, compressed=True)


def test_p2sh() -> None:
    # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
    network = "mainnet"
    address = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    script_pub_key = script.serialize(
        [
            "OP_2DUP",
            "OP_EQUAL",
            "OP_NOT",
            "OP_VERIFY",
            "OP_SHA1",
            "OP_SWAP",
            "OP_SHA1",
            "OP_EQUAL",
        ]
    )

    assert script_pub_key.hex() == "6e879169a77ca787"
    assert address == base58_address.p2sh(script_pub_key, network)

    script_hash = hash160(script_pub_key)
    prefix = NETWORKS[network].p2sh
    assert (prefix, script_hash, network, True) == base58_address.h160_from_address(
        address
    )
    assert (prefix, script_hash, network, True) == base58_address.h160_from_address(
        " " + address + " "  # address with trailing/leading spaces
    )

    assert script_hash.hex() == "4266fc6f2c2861d7fe229b279a79803afca7ba34"
    script_sig: List[script.ScriptToken] = [
        "OP_HASH160",
        script_hash.hex(),
        "OP_EQUAL",
    ]
    script.serialize(script_sig)


def test_p2w_p2sh() -> None:

    pub_key = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    h160pub_key, network = hash160_from_key(pub_key)
    b58addr = base58_address.p2wpkh_p2sh(pub_key, network)
    assert b58addr == base58_address.address_from_witness(h160pub_key, network)

    script_pub_key = script.serialize(
        [
            "OP_DUP",
            "OP_HASH160",
            h160pub_key,
            "OP_EQUALVERIFY",
            "OP_CHECKSIG",
        ]
    )
    h256script = sha256(script_pub_key)
    b58addr = base58_address.p2wsh_p2sh(script_pub_key, network)
    assert b58addr == base58_address.address_from_witness(h256script, network)

    err_msg = "invalid witness program length for witness v0: "
    with pytest.raises(BTClibValueError, match=err_msg):
        base58_address.address_from_witness(h256script[:-1], network)


def test_address_from_wif() -> None:

    q = 0x19E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725

    test_cases: List[Tuple[bool, str, str, str]] = [
        (
            False,
            "mainnet",
            "5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW",
            "1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig",
        ),
        (
            True,
            "mainnet",
            "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162",
            "1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB",
        ),
        (
            False,
            "testnet",
            "91nKEXyJCPYaK9maw7bTJ7ZcCu6dy2gybvNtUWF1LTCYggzhZgy",
            "mzuJRVe3ERecM6F6V4R6GN9B5fKiPC9HxF",
        ),
        (
            True,
            "testnet",
            "cNT1UjhUuGWN37hnmr754XxvPWwtAJTSq8bcCQ4pUrdxqxbA1iU1",
            "mwp9QoLuLK65XZUFKhPtvfujBjmgkZnmPx",
        ),
    ]
    for compressed, network, wif, address in test_cases:
        assert wif == wif_from_prv_key(q, network, compressed)
        assert prv_keyinfo_from_prv_key(wif) == (q, network, compressed)
        assert address == base58_address.p2pkh(wif)
        _, payload, net, is_script_hash = base58_address.h160_from_address(address)
        assert net == network
        assert not is_script_hash
        if compressed:
            b32_address = bech32_address.p2wpkh(wif)
            assert (
                0,
                payload,
                network,
                False,  # is_script_hash
            ) == bech32_address.witness_from_address(b32_address)

            b58_address = base58_address.p2wpkh_p2sh(wif)
            assert (
                NETWORKS[network].p2sh,
                hash160(b"\x00\x14" + payload),
                network,
                True,  # is_script_hash
            ) == base58_address.h160_from_address(b58_address)

        else:
            err_msg = "not a private or compressed public key: "
            with pytest.raises(BTClibValueError, match=err_msg):
                bech32_address.p2wpkh(wif)  # type: ignore
            with pytest.raises(BTClibValueError, match=err_msg):
                base58_address.p2wpkh_p2sh(wif)  # type: ignore


def test_exceptions() -> None:

    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    payload = b"\xf5" + hash160(pub_key)
    invalid_address = b58encode(payload)
    with pytest.raises(BTClibValueError, match="invalid base58 address prefix: "):
        base58_address.h160_from_address(invalid_address)

    with pytest.raises(BTClibValueError, match="not a private or public key: "):
        base58_address.p2pkh(pub_key + "00")
