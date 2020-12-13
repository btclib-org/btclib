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

from btclib import bip32, script, slip132
from btclib.base58 import b58encode
from btclib.base58_address import (
    base58_address_from_h160,
    base58_address_from_witness,
    h160_from_base58_address,
    p2pkh,
    p2sh,
    p2wpkh_p2sh,
    p2wsh_p2sh,
)
from btclib.base58_wif import wif_from_prv_key
from btclib.bech32_address import p2wpkh, witness_from_bech32_address
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160_from_key
from btclib.sec_point import bytes_from_point, point_from_octets
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.utils import hash160, sha256


def test_base58_address_from_h160() -> None:
    addr = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    prefix, payload, network, _ = h160_from_base58_address(addr)
    assert addr == base58_address_from_h160(prefix, payload, network)

    addr = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    prefix, payload, network, _ = h160_from_base58_address(addr)
    assert addr == base58_address_from_h160(prefix, payload, network)

    addr = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    prefix, payload, network, _ = h160_from_base58_address(addr)
    assert addr == base58_address_from_h160(prefix, payload, network)

    err_msg = "invalid mainnet base58 address prefix: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bad_prefix = b"\xbb"
        base58_address_from_h160(bad_prefix, payload, network)


def test_p2pkh_from_wif() -> None:
    seed = b"\x00" * 32  # better be a documented test case
    rxprv = bip32.rootxprv_from_seed(seed)
    path = "m/0h/0h/12"
    xprv = bip32.derive(rxprv, path)
    wif = wif_from_prv_key(xprv)
    assert wif == "L2L1dqRmkmVtwStNf5wg8nnGaRn3buoQr721XShM4VwDbTcn9bpm"
    pub_key, _ = pub_keyinfo_from_prv_key(wif)
    address = p2pkh(pub_key)
    xpub = bip32.xpub_from_xprv(xprv)
    address2 = slip132.address_from_xpub(xpub)
    assert address == address2

    err_msg = "not a private key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        wif_from_prv_key(xpub)


def test_p2pkh_from_pub_key() -> None:
    # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    pub = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    addr = p2pkh(pub)
    assert addr == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    _, h160, _, _ = h160_from_base58_address(addr)
    assert h160 == hash160(pub)

    uncompr_pub = bytes_from_point(point_from_octets(pub), compressed=False)
    addr = p2pkh(uncompr_pub, compressed=False)
    assert addr == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    _, h160, _, _ = h160_from_base58_address(addr)
    assert h160 == hash160(uncompr_pub)

    # trailing/leading spaces in string
    pub = "  02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    addr = p2pkh(pub)
    assert addr == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    _, h160, _, _ = h160_from_base58_address(addr)
    assert h160 == hash160(pub)

    pub = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352  "
    addr = p2pkh(pub)
    assert addr == "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"


def test_p2sh() -> None:
    # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
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

    network = "mainnet"
    addr = p2sh(script_pub_key, network)
    assert addr == "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"

    _, redeem_script_hash, network2, is_script_hash = h160_from_base58_address(addr)
    assert network == network2
    assert is_script_hash
    assert redeem_script_hash == hash160(script_pub_key)

    assert redeem_script_hash.hex() == "4266fc6f2c2861d7fe229b279a79803afca7ba34"
    output_script: List[script.ScriptToken] = [
        "OP_HASH160",
        redeem_script_hash.hex(),
        "OP_EQUAL",
    ]
    script.serialize(output_script)

    # address with trailing/leading spaces
    _, h160, network2, is_script_hash = h160_from_base58_address(
        " 37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP "
    )
    assert network == network2
    assert is_script_hash
    assert redeem_script_hash == h160


def test_p2w_p2sh() -> None:

    pub_key = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    h160pub_key, network = hash160_from_key(pub_key)
    b58addr = p2wpkh_p2sh(pub_key, network)
    b58addr2 = base58_address_from_witness(h160pub_key, network)
    assert b58addr2 == b58addr

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
    b58addr = p2wsh_p2sh(script_pub_key, network)
    b58addr2 = base58_address_from_witness(h256script, network)
    assert b58addr2 == b58addr

    err_msg = "invalid witness program length for witness v0: "
    with pytest.raises(BTClibValueError, match=err_msg):
        base58_address_from_witness(h256script[:-1], network)


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
        b58 = p2pkh(wif)
        assert b58 == address
        _, payload, net, is_script = h160_from_base58_address(b58)
        assert net == network
        assert not is_script
        if compressed:
            b32 = p2wpkh(wif)
            assert (payload, network, is_script) == witness_from_bech32_address(b32)[1:]
            b = p2wpkh_p2sh(wif)
            _, payload2, net, is_script = h160_from_base58_address(b)
            assert is_script
            assert (hash160(b"\x00\x14" + payload), network) == (payload2, net)
        else:
            err_msg = "not a private or compressed public key: "
            with pytest.raises(BTClibValueError, match=err_msg):
                p2wpkh(wif)  # type: ignore
            with pytest.raises(BTClibValueError, match=err_msg):
                p2wpkh_p2sh(wif)  # type: ignore


def test_exceptions() -> None:

    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    payload = b"\xf5" + hash160(pub_key)
    invalid_address = b58encode(payload)
    with pytest.raises(BTClibValueError, match="invalid base58 address prefix: "):
        h160_from_base58_address(invalid_address)

    with pytest.raises(BTClibValueError, match="not a private or public key: "):
        p2pkh(pub_key + "00")
