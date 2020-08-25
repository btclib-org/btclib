#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.base58address` module."

from typing import List, Tuple

import pytest

from btclib import bip32, script, slip132
from btclib.alias import Token
from btclib.base58 import b58encode
from btclib.base58address import (
    b58address_from_h160,
    b58address_from_witness,
    h160_from_b58address,
    p2pkh,
    p2sh,
    p2wpkh_p2sh,
    p2wsh_p2sh,
)
from btclib.base58wif import wif_from_prvkey
from btclib.bech32address import p2wpkh, witness_from_b32address
from btclib.hashes import hash160_from_key, hash256_from_script
from btclib.secpoint import bytes_from_point, point_from_octets
from btclib.to_prvkey import prvkeyinfo_from_prvkey
from btclib.to_pubkey import pubkeyinfo_from_prvkey
from btclib.utils import hash160


def test_b58address_from_h160() -> None:
    addr = b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    prefix, payload, network, _ = h160_from_b58address(addr)
    assert addr == b58address_from_h160(prefix, payload, network)

    addr = b"16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    prefix, payload, network, _ = h160_from_b58address(addr)
    assert addr == b58address_from_h160(prefix, payload, network)

    addr = b"37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    prefix, payload, network, _ = h160_from_b58address(addr)
    assert addr == b58address_from_h160(prefix, payload, network)

    err_msg = "invalid mainnet base58 address prefix: "
    with pytest.raises(ValueError, match=err_msg):
        bad_prefix = b"\xbb"
        b58address_from_h160(bad_prefix, payload, network)


def test_p2pkh_from_wif() -> None:
    seed = b"00" * 32  # better be a documented test case
    rxprv = bip32.rootxprv_from_seed(seed)
    path = "m/0h/0h/12"
    xprv = bip32.derive(rxprv, path)
    wif = wif_from_prvkey(xprv)
    assert wif == b"KyLk7s6Z1FtgYEVp3bPckPVnXvLUWNCcVL6wNt3gaT96EmzTKZwP"
    pubkey, _ = pubkeyinfo_from_prvkey(wif)
    address = p2pkh(pubkey)
    xpub = bip32.xpub_from_xprv(xprv)
    address2 = slip132.address_from_xpub(xpub)
    assert address == address2

    err_msg = "not a private key: "
    with pytest.raises(ValueError, match=err_msg):
        wif_from_prvkey(xpub)


def test_p2pkh_from_pubkey() -> None:
    # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    pub = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    addr = p2pkh(pub)
    assert addr == b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    _, h160, _, _ = h160_from_b58address(addr)
    assert h160 == hash160(pub)

    uncompr_pub = bytes_from_point(point_from_octets(pub), compressed=False)
    addr = p2pkh(uncompr_pub, compressed=False)
    assert addr == b"16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    _, h160, _, _ = h160_from_b58address(addr)
    assert h160 == hash160(uncompr_pub)

    # trailing/leading spaces in string
    pub = "  02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    addr = p2pkh(pub)
    assert addr == b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    _, h160, _, _ = h160_from_b58address(addr)
    assert h160 == hash160(pub)

    pub = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352  "
    addr = p2pkh(pub)
    assert addr == b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"


def test_p2sh() -> None:
    # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
    scriptPubKey: List[Token] = [
        "OP_2DUP",
        "OP_EQUAL",
        "OP_NOT",
        "OP_VERIFY",
        "OP_SHA1",
        "OP_SWAP",
        "OP_SHA1",
        "OP_EQUAL",
    ]
    assert script.encode(scriptPubKey).hex() == "6e879169a77ca787"

    network = "mainnet"
    addr = p2sh(scriptPubKey, network)
    assert addr == b"37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"

    _, redeem_script_hash, network2, is_script_hash = h160_from_b58address(addr)
    assert network == network2
    assert is_script_hash
    assert redeem_script_hash == hash160(script.encode(scriptPubKey))

    assert redeem_script_hash.hex() == "4266fc6f2c2861d7fe229b279a79803afca7ba34"
    output_script: List[Token] = ["OP_HASH160", redeem_script_hash.hex(), "OP_EQUAL"]
    script.encode(output_script)

    # address with trailing/leading spaces
    _, h160, network2, is_script_hash = h160_from_b58address(
        " 37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP "
    )
    assert network == network2
    assert is_script_hash
    assert redeem_script_hash == h160


def test_p2w_p2sh() -> None:

    pubkey = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    h160pubkey, network = hash160_from_key(pubkey)
    b58addr = p2wpkh_p2sh(pubkey, network)
    b58addr2 = b58address_from_witness(h160pubkey, network)
    assert b58addr2 == b58addr

    scriptPubKey: List[Token] = [
        "OP_DUP",
        "OP_HASH160",
        h160pubkey,
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]
    h256script = hash256_from_script(scriptPubKey)
    b58addr = p2wsh_p2sh(scriptPubKey, network)
    b58addr2 = b58address_from_witness(h256script, network)
    assert b58addr2 == b58addr

    err_msg = "invalid witness program length for witness version zero: "
    with pytest.raises(ValueError, match=err_msg):
        b58address_from_witness(h256script[:-1], network)


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
        assert wif.encode() == wif_from_prvkey(q, network, compressed)
        assert prvkeyinfo_from_prvkey(wif) == (q, network, compressed)
        b58 = p2pkh(wif)
        assert b58 == address.encode()
        _, payload, net, is_script = h160_from_b58address(b58)
        assert net == network
        assert not is_script
        if compressed:
            b32 = p2wpkh(wif)
            assert (payload, network, is_script) == witness_from_b32address(b32)[1:]
            b = p2wpkh_p2sh(wif)
            _, payload2, net, is_script = h160_from_b58address(b)
            assert is_script
            assert (hash160(b"\x00\x14" + payload), network) == (payload2, net)
        else:
            err_msg = "not a private or compressed public key: "
            with pytest.raises(ValueError, match=err_msg):
                p2wpkh(wif)  # type: ignore
            with pytest.raises(ValueError, match=err_msg):
                p2wpkh_p2sh(wif)  # type: ignore


def test_exceptions() -> None:

    pubkey = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    payload = b"\xf5" + hash160(pubkey)
    invalid_address = b58encode(payload)
    with pytest.raises(ValueError, match="invalid base58 address prefix: "):
        h160_from_b58address(invalid_address)

    with pytest.raises(ValueError, match="not a private or public key: "):
        p2pkh(pubkey + "00")
