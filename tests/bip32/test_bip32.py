#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.bip32` module."

import json
import re
from os import path

import pytest

from btclib import base58, hashes
from btclib.b58 import p2pkh  # FIXME why it is needed here
from btclib.bip32.bip32 import (
    BIP32KeyData,
    _derive,
    crack_prv_key,
    derive,
    derive_from_account,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib.bip32.der_path import _indexes_from_bip32_path_str
from btclib.exceptions import BTClibValueError
from btclib.to_pub_key import pub_keyinfo_from_key


def test_exceptions() -> None:

    with pytest.raises(BTClibValueError, match="not a private or public key: "):
        # invalid checksum
        xprv = "xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L"
        p2pkh(xprv)

    with pytest.raises(BTClibValueError, match="not a private key: "):
        xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        xpub_from_xprv(xpub)

    seed = "5b56c417303faa3fcba7e57400e120a0"
    with pytest.raises(BTClibValueError, match="unknown extended key version: "):
        version = b"\x04\x88\xAD\xE5"
        rootxprv_from_seed(seed, version)

    with pytest.raises(BTClibValueError, match="too many bits for seed: "):
        rootxprv_from_seed(seed * 5)

    with pytest.raises(BTClibValueError, match="too few bits for seed: "):
        rootxprv_from_seed(seed[:-2])


def test_assert_valid2() -> None:

    xkey = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.version = (xkey_data.version)[:-1]
    with pytest.raises(BTClibValueError, match="invalid version length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.version = "1234"  # type: ignore
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.depth = -1
    with pytest.raises(BTClibValueError, match="invalid depth: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.depth = 256
    with pytest.raises(BTClibValueError, match="invalid depth: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.depth = tuple()  # type: ignore
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.parent_fingerprint = (xkey_data.parent_fingerprint)[:-1]
    with pytest.raises(BTClibValueError, match="invalid parent_fingerprint length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.parent_fingerprint = "1234"  # type: ignore
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.index = -1
    with pytest.raises(BTClibValueError, match="invalid index: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.index = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match="invalid index: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.index = tuple()  # type: ignore
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.chain_code = (xkey_data.chain_code)[:-1]
    with pytest.raises(BTClibValueError, match="invalid chain_code length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.chain_code = "length is 32 but not a chaincode"  # type: ignore
    assert len(xkey_data.chain_code) == 32
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.key = (xkey_data.key)[:-1]
    with pytest.raises(BTClibValueError, match="invalid key length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.key = "length is 33, but not a key      "  # type: ignore
    assert len(xkey_data.key) == 33
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.parent_fingerprint = bytes.fromhex("deadbeef")
    err_msg = "zero depth with non-zero parent fingerprint: "
    with pytest.raises(BTClibValueError, match=err_msg):
        xkey_data.b58encode()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.index = 1
    with pytest.raises(BTClibValueError, match="zero depth with non-zero index: "):
        xkey_data.b58encode()


def test_serialization() -> None:
    xkey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xkey_data = BIP32KeyData.b58decode(xkey)

    decoded_key = base58.b58decode(xkey, 78)
    assert xkey_data.version == decoded_key[:4]
    assert xkey_data.depth == decoded_key[4]
    assert xkey_data.parent_fingerprint == decoded_key[5:9]
    assert xkey_data.index == int.from_bytes(decoded_key[9:13], "big", signed=False)
    assert xkey_data.chain_code == decoded_key[13:45]
    assert xkey_data.key == decoded_key[45:]

    assert xkey_data.b58encode() == xkey

    xpub = xpub_from_xprv(xkey)
    xpub2 = xpub_from_xprv(xkey_data)
    assert xpub == xpub2


data_folder = path.join(path.dirname(__file__), "_data")


def test_bip32_vectors() -> None:
    """BIP32 test vectors #1, #2, #3, and #4

    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """
    filename = path.join(data_folder, "bip32_test_vectors.json")
    with open(filename, "r", encoding="ascii") as file_:
        test_vectors = json.load(file_)

    for seed in test_vectors:
        mxprv = rootxprv_from_seed(seed)
        for der_path, xpub, xprv in test_vectors[seed]:
            assert xprv == derive(mxprv, der_path)
            assert xpub == xpub_from_xprv(xprv)


def test_invalid_bip32_xkeys() -> None:
    """BIP32 test vectors #5

    https://github.com/bitcoin/bips/pull/921
    """

    filename = path.join(data_folder, "bip32_invalid_keys.json")
    with open(filename, "r", encoding="ascii") as file_:
        test_vectors = json.load(file_)

    for xkey, err_msg in test_vectors:
        with pytest.raises(BTClibValueError, match=re.escape(err_msg)):
            BIP32KeyData.b58decode(xkey)


def test_derive() -> None:

    test_vectors = {
        "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS": [
            ["m / 0 h / 0 h / 463 h", "1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5"],
            ["M / 0H / 0h // 267' / ", "11x2mn59Qy43DjisZWQGRResjyQmgthki"],
        ],
        "tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK": [
            ["m / 0 h / 0 h / 51 h", "mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj"],
            ["m / 0 h / 1 h / 150 h", "mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb"],
        ],
    }

    for rootxprv, value in test_vectors.items():
        for der_path, address in value:
            assert address == p2pkh(derive(rootxprv, der_path))

            indexes = _indexes_from_bip32_path_str(der_path)
            assert address == p2pkh(derive(rootxprv, indexes))

        assert derive(rootxprv, "m") == rootxprv


def test_derive_exceptions() -> None:
    # root key, zero depth
    rootmxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv = BIP32KeyData.b58decode(rootmxprv)
    # FIXME
    # assert xprv == _derive(xprv, "m")
    assert rootmxprv == derive(xprv, "m")
    assert rootmxprv == derive(xprv, "")

    fingerprint = hashes.hash160(pub_keyinfo_from_key(xprv)[0])[:4]
    assert fingerprint == _derive(xprv, bytes.fromhex("80000000")).parent_fingerprint

    for der_path in ("/1", "800000", "80000000"):
        xkey = _derive(xprv, der_path)
        assert fingerprint == xkey.parent_fingerprint

    err_msg = "invalid literal for int"
    for der_path in (";/0", "invalid index"):
        with pytest.raises(ValueError, match=err_msg):
            derive(xprv, der_path)

    with pytest.raises(BTClibValueError, match="depth greater than 255: "):
        derive(xprv, "m" + 256 * "/0")

    with pytest.raises(BTClibValueError, match="index are not a multiple of 4-bytes: "):
        derive(xprv, b"\x00" * 5)

    for index in (2**32, 0x8000000000):
        with pytest.raises(OverflowError, match="int too big to convert"):
            derive(xprv, index)

    xprv = _derive(xprv, "1")
    err_msg = "final depth greater than 255: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(xprv, "m" + 255 * "/0")

    rootxprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"

    temp = base58.b58decode(rootxprv)
    bad_xprv = base58.b58encode(temp[:45] + b"\x02" + temp[46:], 78)
    err_msg = "invalid private key prefix: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(bad_xprv, 0x80000000)

    xpub = xpub_from_xprv(rootxprv)
    temp = base58.b58decode(xpub)
    bad_xpub = base58.b58encode(temp[:45] + b"\x00" + temp[46:], 78)
    err_msg = r"invalid public key prefix not in \(0x02, 0x03\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(bad_xpub, 0x80000000)

    err_msg = "hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(xpub, 0x80000000)


def test_derive_from_account() -> None:

    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    rmxprv = rootxprv_from_seed(seed)

    der_path = "m / 44 h / 0 h"
    mxpub = xpub_from_xprv(derive(rmxprv, der_path))

    test_vectors = [
        [0, 0],
        [0, 1],
        [0, 2],
        [1, 0],
        [1, 1],
        [1, 2],
    ]

    for branch, index in test_vectors:
        full_path = der_path + f"/{branch}/{index}"
        addr = p2pkh(derive(rmxprv, full_path))
        assert addr == p2pkh(derive_from_account(mxpub, branch, index))

    err_msg = "invalid private derivation at branch level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0x80000000, 0, True)

    err_msg = "too high branch: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0xFFFF + 1, 0)

    err_msg = "invalid branch: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 2, 0)

    err_msg = "invalid private derivation at address index level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0x80000000)

    err_msg = "too high address index: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0xFFFF + 1)

    der_path = "m / 44 h / 0"
    mxpub = xpub_from_xprv(derive(rmxprv, der_path))
    err_msg = "unhardened account/master key"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0)


def test_crack() -> None:
    parent_xpub = "xpub6BabMgRo8rKHfpAb8waRM5vj2AneD4kDMsJhm7jpBDHSJvrFAjHJHU5hM43YgsuJVUVHWacAcTsgnyRptfMdMP8b28LYfqGocGdKCFjhQMV"
    child_xprv = "xprv9xkG88dGyiurKbVbPH1kjdYrA8poBBBXa53RKuRGJXyruuoJUDd8e4m6poiz7rV8Z4NoM5AJNcPHN6aj8wRFt5CWvF8VPfQCrDUcLU5tcTm"
    parent_xprv = crack_prv_key(parent_xpub, child_xprv)
    assert xpub_from_xprv(parent_xprv) == parent_xpub
    # same check with XKeyDict
    parent_xprv = crack_prv_key(
        BIP32KeyData.b58decode(parent_xpub), BIP32KeyData.b58decode(child_xprv)
    )
    assert xpub_from_xprv(parent_xprv) == parent_xpub

    err_msg = "extended parent key is not a public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key(parent_xprv, child_xprv)

    err_msg = "extended child key is not a private key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key(parent_xpub, parent_xpub)

    child_xpub = xpub_from_xprv(child_xprv)
    with pytest.raises(BTClibValueError, match="not a parent's child: wrong depths"):
        crack_prv_key(child_xpub, child_xprv)

    child0_xprv = derive(parent_xprv, 0)
    grandchild_xprv = derive(child0_xprv, 0)
    err_msg = "not a parent's child: wrong parent fingerprint"
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key(child_xpub, grandchild_xprv)

    hardened_child_xprv = derive(parent_xprv, 0x80000000)
    with pytest.raises(BTClibValueError, match="hardened child derivation"):
        crack_prv_key(parent_xpub, hardened_child_xprv)


def test_bips_pr905() -> None:
    "https://github.com/bitcoin/bips/pull/905"

    seed = "57fb1e450b8afb95c62afbcd49e4100d6790e0822b8905608679180ac34ca0bd45bf7ccc6c5f5218236d0eb93afc78bd117b9f02a6b7df258ea182dfaef5aad7"
    xroot = rootxprv_from_seed(seed)
    der_path = "m/44H/60H/0H"
    xprv = "xprv9yqXG1Cns3YEQi6fsCJ7NGV5sHPiyZcbgLVst61dbLYyn7qy1G9aFtRmaYp481ounqnVf9Go2ymQ4gmxZLEwYSRhU868aDk4ZxzGvqHJVhe"
    assert derive(xroot, der_path) == xprv
    xpub = "xpub6CpsfWjghR6XdCB8yDq7jQRpRKEDP2LT3ZRUgURF9g5xevB7YoTpogkFRqq5nQtVSN8YCMZo2CD8u4zCaxRv85ctCWmzEi9gQ5DBhBFaTNo"
    assert xpub_from_xprv(xprv) == xpub
