#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.bip32` module."

import json
from os import path

import pytest

from btclib import bip32
from btclib.base58 import b58decode, b58encode
from btclib.base58address import p2pkh  # FIXME why it is needed here


def test_indexes_from_path() -> None:

    test_vectors = [
        # account 0, external branch, address_index 463
        ("m / 0 h / 0 / 463", True, [0x80000000, 0, 463]),
        (". / 0 h / 0 / 463", False, [0x80000000, 0, 463]),
        ("m / 0 H / 0 / 463", True, [0x80000000, 0, 463]),
        (". / 0 H / 0 / 463", False, [0x80000000, 0, 463]),
        ("m /  0' / 0 / 463", True, [0x80000000, 0, 463]),
        (". /  0' / 0 / 463", False, [0x80000000, 0, 463]),
        # account 0, internal branch, address_index 267
        ("m / 0 h / 1 / 267", True, [0x80000000, 1, 267]),
        (". / 0 h / 1 / 267", False, [0x80000000, 1, 267]),
        ("m / 0 H / 1 / 267", True, [0x80000000, 1, 267]),
        (". / 0 H / 1 / 267", False, [0x80000000, 1, 267]),
        ("m /  0' / 1 / 267", True, [0x80000000, 1, 267]),
        (". /  0' / 1 / 267", False, [0x80000000, 1, 267]),
    ]

    for der_path, absolute, indx in test_vectors:
        indexes = [i.to_bytes(4, "big") for i in indx]
        assert (indexes, absolute) == bip32._indexes_from_path(der_path)

    with pytest.raises(OverflowError, match="can't convert negative int to unsigned"):
        bip32._indexes_from_path("m/1/2/-3/4")

    with pytest.raises(ValueError, match="negative index in derivation path: "):
        bip32._indexes_from_path("m/1/2/-3h/4")


def test_exceptions() -> None:

    with pytest.raises(ValueError, match="not a private or public key: "):
        # invalid checksum
        xprv = "xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L"
        p2pkh(xprv)

    xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    with pytest.raises(ValueError, match="not a private key: "):
        bip32.xpub_from_xprv(xpub)

    xpub_dict = bip32.deserialize(xpub)
    xpub_dict = bip32.deserialize(xpub_dict)
    xpub_dict["chain_code"] = (xpub_dict["chain_code"])[:-1]
    with pytest.raises(ValueError, match="invalid chain code length: "):
        xpub_dict = bip32.deserialize(xpub_dict)
    xpub_dict = bip32.deserialize(xpub)
    xpub_dict["chain_code"] = "length is 32 but not a chaincode"  # type: ignore
    with pytest.raises(ValueError, match="invalid chain code"):
        xpub_dict = bip32.deserialize(xpub_dict)

    seed = "5b56c417303faa3fcba7e57400e120a0"
    with pytest.raises(ValueError, match="unknown private key version: "):
        version = b"\x04\x88\xAD\xE5"
        bip32.rootxprv_from_seed(seed, version)

    with pytest.raises(ValueError, match="too many bits for seed: "):
        bip32.rootxprv_from_seed(seed * 5)

    with pytest.raises(ValueError, match="too few bits for seed: "):
        bip32.rootxprv_from_seed(seed[:-2])


def test_deserialize() -> None:
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv_dict = bip32.deserialize(xprv)

    decoded_key = b58decode(xprv, 78)
    assert xprv_dict["version"] == decoded_key[:4]
    assert xprv_dict["depth"] == decoded_key[4]
    assert xprv_dict["parent_fingerprint"] == decoded_key[5:9]
    assert xprv_dict["index"] == decoded_key[9:13]
    assert xprv_dict["chain_code"] == decoded_key[13:45]
    assert xprv_dict["key"] == decoded_key[45:]

    # no harm in deserializing again an already deserialized key
    xprv_dict = bip32.deserialize(xprv_dict)
    xpr2 = bip32.serialize(xprv_dict)
    assert xpr2.decode() == xprv

    xpub = bip32.xpub_from_xprv(xprv)
    xpub2 = bip32.xpub_from_xprv(bip32.deserialize(xprv))
    assert xpub == xpub2


def test_serialize() -> None:
    rootxprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
    d = bip32.deserialize(rootxprv)
    assert bip32.serialize(d).decode() == rootxprv

    d["key"] += b"\x00"
    with pytest.raises(ValueError, match="invalid key length: "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["depth"] = 256
    with pytest.raises(ValueError, match="invalid depth "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["parent_fingerprint"] = b"\x00\x00\x00\x01"
    errmsg = "zero depth with non-zero parent fingerprint 0x"
    with pytest.raises(ValueError, match=errmsg):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["index"] = b"\x00\x00\x00\x01"
    with pytest.raises(ValueError, match="zero depth with non-zero index 0x"):
        bip32.serialize(d)

    xprv = bip32.deserialize(bip32.derive(rootxprv, 0x80000000))
    xprv["parent_fingerprint"] = b"\x00\x00\x00\x00"
    errmsg = "zero parent fingerprint with non-zero depth "
    with pytest.raises(ValueError, match=errmsg):
        bip32.serialize(xprv)

    d = bip32.deserialize(rootxprv)
    d["parent_fingerprint"] += b"\x00"
    with pytest.raises(ValueError, match="invalid parent fingerprint length: "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["index"] += b"\x00"
    with pytest.raises(ValueError, match="invalid index length: "):
        bip32.serialize(d)

    d = bip32.deserialize(rootxprv)
    d["chain_code"] += b"\x00"
    with pytest.raises(ValueError, match="invalid chain code length: "):
        bip32.serialize(d)


data_folder = path.join(path.dirname(__file__), "test_data")


def test_bip39_vectors() -> None:
    """BIP32 test vectors from BIP39

    https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
    """
    filename = path.join(data_folder, "bip39_test_vectors.json")
    with open(filename, "r") as f:
        test_vectors = json.load(f)["english"]

    # test_vector[0] and [1], i.e. entropy and mnemonic, are tested in bip39
    for _, _, seed, key in test_vectors:
        assert bip32.rootxprv_from_seed(seed) == key.encode("ascii")


def test_bip32_vectors() -> None:
    """BIP32 test vectors

    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """
    filename = path.join(data_folder, "bip32_test_vectors.json")
    with open(filename, "r") as f:
        test_vectors = json.load(f)

    for seed in test_vectors:
        mxprv = bip32.rootxprv_from_seed(seed)
        for der_path, xpub, xprv in test_vectors[seed]:
            assert xprv == bip32.derive(mxprv, der_path).decode()
            assert xpub == bip32.xpub_from_xprv(xprv).decode()


def test_invalid_bip32_xkeys() -> None:

    filename = path.join(data_folder, "bip32_invalid_keys.json")
    with open(filename, "r") as f:
        test_vectors = json.load(f)

    for xkey, err_msg in test_vectors:
        with pytest.raises(ValueError, match=err_msg):
            bip32.deserialize(xkey)


def test_rootxprv_from_mnemonic() -> None:
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    rootxprv = bip32.mxprv_from_bip39_mnemonic(mnemonic, "")
    exp = b"xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1"
    assert rootxprv == exp


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
            assert address == p2pkh(bip32.derive(rootxprv, der_path)).decode()

            b_indexes, _ = bip32._indexes_from_path(der_path)
            indexes = [int.from_bytes(b_index, "big") for b_index in b_indexes]
            assert address == p2pkh(bip32.derive(rootxprv, indexes)).decode()


def test_derive_exceptions() -> None:
    # root key, zero depth
    rootmxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv = bip32.derive(rootmxprv, b"\x80\x00\x00\x00")
    xprv = bip32.derive(xprv, ".")

    # FIXME: this failure shoud be required
    # errmsg = "public derivation at depth one level"
    # with pytest.raises(UserWarning, match=errmsg):
    #    bip32.deserialize(bip32.derive(rootmxprv, 0))

    for der_path in ("", "/1"):
        with pytest.raises(
            ValueError, match="empty derivation path root: must be m or ."
        ):
            bip32.derive(xprv, der_path)

    for der_path in (";/0", "invalid index", "800000"):
        with pytest.raises(ValueError, match="invalid derivation path root: "):
            bip32.derive(xprv, der_path)

    with pytest.raises(ValueError, match="derivation path depth greater than 255: "):
        bip32.derive(xprv, "." + 256 * "/0")

    errmsg = "absolute derivation path for non-root master key"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(xprv, "m / 44 h/0h/1h/0/10")

    with pytest.raises(ValueError, match="index must be 4-bytes, not "):
        bip32.derive(xprv, b"\x00" * 5)

    errmsg = "int too big to convert"
    for index in (256 ** 4, 0x8000000000):
        with pytest.raises(OverflowError, match=errmsg):
            bip32.derive(xprv, index)

    errmsg = "derivation path final depth greater than 255: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(xprv, "." + 255 * "/0")

    rootxprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"

    temp = b58decode(rootxprv)
    bad_xprv = b58encode(temp[0:45] + b"\x02" + temp[46:], 78)
    errmsg = "invalid private key prefix: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(bad_xprv, 0x80000000)

    xpub = bip32.xpub_from_xprv(rootxprv)
    temp = b58decode(xpub)
    bad_xpub = b58encode(temp[0:45] + b"\x00" + temp[46:], 78)
    errmsg = "invalid public key prefix: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(bad_xpub, 0x80000000)

    errmsg = "hardened derivation from public key"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive(xpub, 0x80000000)


def test_derive_from_account() -> None:

    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    rmxprv = bip32.rootxprv_from_seed(seed)

    der_path = "m / 44 h / 0 h"
    mxpub = bip32.xpub_from_xprv(bip32.derive(rmxprv, der_path))

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
        addr = p2pkh(bip32.derive(rmxprv, full_path)).decode()
        assert addr == p2pkh(bip32.derive_from_account(mxpub, branch, index)).decode()

    errmsg = "invalid private derivation at branch level"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive_from_account(mxpub, 0x80000000, 0, True)

    errmsg = "invalid branch: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive_from_account(mxpub, 2, 0)

    errmsg = "invalid private derivation at address index level"
    with pytest.raises(ValueError, match=errmsg):
        bip32.derive_from_account(mxpub, 0, 0x80000000)

    der_path = "m / 44 h / 0"
    mxpub = bip32.xpub_from_xprv(bip32.derive(rmxprv, der_path))
    errmsg = "public derivation at account level"
    with pytest.raises(UserWarning, match=errmsg):
        bip32.derive_from_account(mxpub, 0, 0)


def test_crack() -> None:
    parent_xpub = "xpub6BabMgRo8rKHfpAb8waRM5vj2AneD4kDMsJhm7jpBDHSJvrFAjHJHU5hM43YgsuJVUVHWacAcTsgnyRptfMdMP8b28LYfqGocGdKCFjhQMV"
    child_xprv = "xprv9xkG88dGyiurKbVbPH1kjdYrA8poBBBXa53RKuRGJXyruuoJUDd8e4m6poiz7rV8Z4NoM5AJNcPHN6aj8wRFt5CWvF8VPfQCrDUcLU5tcTm"
    parent_xprv = bip32.crack_prvkey(parent_xpub, child_xprv)
    assert bip32.xpub_from_xprv(parent_xprv).decode() == parent_xpub
    # same check with XKeyDict
    parent_xprv = bip32.crack_prvkey(
        bip32.deserialize(parent_xpub), bip32.deserialize(child_xprv)
    )
    assert bip32.xpub_from_xprv(parent_xprv).decode() == parent_xpub

    errmsg = "extended parent key is not a public key: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.crack_prvkey(parent_xprv, child_xprv)

    errmsg = "extended child key is not a private key: "
    with pytest.raises(ValueError, match=errmsg):
        bip32.crack_prvkey(parent_xpub, parent_xpub)

    child_xpub = bip32.xpub_from_xprv(child_xprv)
    with pytest.raises(ValueError, match="not a parent's child: wrong depths"):
        bip32.crack_prvkey(child_xpub, child_xprv)

    child0_xprv = bip32.derive(parent_xprv, 0)
    grandchild_xprv = bip32.derive(child0_xprv, 0)
    errmsg = "not a parent's child: wrong parent fingerprint"
    with pytest.raises(ValueError, match=errmsg):
        bip32.crack_prvkey(child_xpub, grandchild_xprv)

    hardened_child_xprv = bip32.derive(parent_xprv, 0x80000000)
    with pytest.raises(ValueError, match="hardened child derivation"):
        bip32.crack_prvkey(parent_xpub, hardened_child_xprv)
