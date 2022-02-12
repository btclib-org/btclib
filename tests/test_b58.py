#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.b58` module."

from typing import List, Tuple

import pytest

from btclib import b32, b58
from btclib.base58 import b58encode
from btclib.bip32 import bip32, slip132
from btclib.ecc.curve import secp256k1
from btclib.ecc.sec_point import bytes_from_point, point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.script.script import Command, serialize
from btclib.to_prv_key import prv_keyinfo_from_prv_key
from btclib.to_pub_key import pub_keyinfo_from_key, pub_keyinfo_from_prv_key

ec = secp256k1


def test_wif_from_prv_key() -> None:
    q_prv_key = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
    wif_prv_keys = [
        "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
        "cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx",
        "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2",
        " KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617",
        "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 ",
    ]
    for alt_prv_key in wif_prv_keys:
        assert alt_prv_key.strip() == b58.wif_from_prv_key(alt_prv_key)

    test_vectors: List[Tuple[str, str, bool]] = [
        ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", "mainnet", True),
        ("cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx", "testnet", True),
        ("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "mainnet", False),
        ("91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2", "testnet", False),
        (" KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", "mainnet", True),
        ("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 ", "mainnet", True),
    ]
    for v in test_vectors:
        for prv_key in [q_prv_key] + wif_prv_keys:
            assert v[0].strip() == b58.wif_from_prv_key(prv_key, v[1], v[2])
            q, network, compressed = prv_keyinfo_from_prv_key(v[0])
            assert q == int(q_prv_key, 16)
            assert network == v[1]
            assert compressed == v[2]

    bad_q = ec.n.to_bytes(ec.n_size, byteorder="big", signed=False)
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1: "):
        b58.wif_from_prv_key(bad_q, "mainnet", True)

    payload = b"\x80" + bad_q
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # not a private key: 33 bytes
    bad_q = 33 * b"\x02"
    with pytest.raises(BTClibValueError, match="not a private key: "):
        b58.wif_from_prv_key(bad_q, "mainnet", True)
    payload = b"\x80" + bad_q
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # Not a WIF: missing leading 0x80
    good_q = 32 * b"\x02"
    payload = b"\x81" + good_q
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # Not a compressed WIF: missing trailing 0x01
    payload = b"\x80" + good_q + b"\x00"
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)

    # Not a WIF: wrong size (35)
    payload = b"\x80" + good_q + b"\x01\x00"
    badwif = b58encode(payload)
    with pytest.raises(BTClibValueError, match="not a private key: "):
        prv_keyinfo_from_prv_key(badwif)


def test_address_from_h160() -> None:
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert address == b58.address_from_h160(*b58.h160_from_address(address))

    address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    assert address == b58.address_from_h160(*b58.h160_from_address(address))

    address = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    assert address == b58.address_from_h160(*b58.h160_from_address(address))

    with pytest.raises(BTClibValueError, match="invalid script type: "):
        b58.address_from_h160("p2pk", b"\x00" * 20)


def test_p2pkh_from_wif() -> None:
    seed = b"\x00" * 32  # better be a documented test case
    rxprv = bip32.rootxprv_from_seed(seed)
    path = "m/0h/0h/12"
    xprv = bip32.derive(rxprv, path)
    wif = b58.wif_from_prv_key(xprv)
    assert wif == "L2L1dqRmkmVtwStNf5wg8nnGaRn3buoQr721XShM4VwDbTcn9bpm"
    pub_key, _ = pub_keyinfo_from_prv_key(wif)
    address = b58.p2pkh(pub_key)
    xpub = bip32.xpub_from_xprv(xprv)
    assert address == slip132.address_from_xpub(xpub)

    err_msg = "not a private key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        b58.wif_from_prv_key(xpub)


def test_p2pkh_from_pub_key() -> None:
    # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    address = "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert address == b58.p2pkh(pub_key)
    assert address == b58.p2pkh(pub_key, compressed=True)
    _, h160, _ = b58.h160_from_address(address)
    assert h160 == hash160(pub_key)

    # trailing/leading spaces in address string
    assert address == b58.p2pkh(" " + pub_key)
    assert h160 == hash160(" " + pub_key)
    assert address == b58.p2pkh(pub_key + " ")
    assert h160 == hash160(pub_key + " ")

    uncompr_pub_key = bytes_from_point(point_from_octets(pub_key), compressed=False)
    uncompr_address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    assert uncompr_address == b58.p2pkh(uncompr_pub_key, compressed=False)
    assert uncompr_address == b58.p2pkh(uncompr_pub_key)
    _, uncompr_h160, _ = b58.h160_from_address(uncompr_address)
    assert uncompr_h160 == hash160(uncompr_pub_key)

    err_msg = "not a private or uncompressed public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert uncompr_address == b58.p2pkh(pub_key, compressed=False)

    err_msg = "not a private or compressed public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        assert address == b58.p2pkh(uncompr_pub_key, compressed=True)


def test_p2sh() -> None:
    # https://medium.com/@darosior/bitcoin-raw-transactions-part-2-p2sh-94df206fee8d
    network = "mainnet"
    address = "37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP"
    script_pub_key = serialize(
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
    assert address == b58.p2sh(script_pub_key, network)

    script_hash = hash160(script_pub_key)
    assert ("p2sh", script_hash, network) == b58.h160_from_address(address)
    assert ("p2sh", script_hash, network) == b58.h160_from_address(" " + address + " ")

    assert script_hash.hex() == "4266fc6f2c2861d7fe229b279a79803afca7ba34"
    script_sig: List[Command] = ["OP_HASH160", script_hash.hex(), "OP_EQUAL"]
    serialize(script_sig)


def test_p2w_p2sh() -> None:

    pub_key_str = "03 a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"
    pub_key, network = pub_keyinfo_from_key(pub_key_str, compressed=True)
    witness_program = hash160(pub_key)
    b58addr = b58.p2wpkh_p2sh(pub_key, network)
    assert b58addr == "36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g"

    script_pub_key = serialize(
        ["OP_DUP", "OP_HASH160", witness_program, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    b58addr = b58.p2wsh_p2sh(script_pub_key, network)
    assert b58addr == "3QHRam4Hvp1GZVkgjoKWUC1GEd8ck8e4WX"


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
        assert wif == b58.wif_from_prv_key(q, network, compressed)
        assert prv_keyinfo_from_prv_key(wif) == (q, network, compressed)
        assert address == b58.p2pkh(wif)
        script_type, payload, net = b58.h160_from_address(address)
        assert net == network
        assert script_type == "p2pkh"

        if compressed:
            b32_address = b32.p2wpkh(wif)
            assert (0, payload, net) == b32.witness_from_address(b32_address)

            b58_address = b58.p2wpkh_p2sh(wif)
            script_bin = hash160(b"\x00\x14" + payload)
            assert ("p2sh", script_bin, net) == b58.h160_from_address(b58_address)

        else:
            err_msg = "not a private or compressed public key: "
            with pytest.raises(BTClibValueError, match=err_msg):
                b32.p2wpkh(wif)  # type: ignore
            with pytest.raises(BTClibValueError, match=err_msg):
                b58.p2wpkh_p2sh(wif)  # type: ignore


def test_exceptions() -> None:

    pub_key = "02 50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    payload = b"\xf5" + hash160(pub_key)
    invalid_address = b58encode(payload)
    with pytest.raises(BTClibValueError, match="invalid base58 address prefix: "):
        b58.h160_from_address(invalid_address)

    with pytest.raises(BTClibValueError, match="not a private or public key: "):
        b58.p2pkh(pub_key + "0A")
