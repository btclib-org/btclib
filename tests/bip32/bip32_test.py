#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.bip32` module."""

import hmac
import re
from typing import Any

import pytest

from btclib import base58
from btclib.b58 import p2pkh
from btclib.bip32 import (
    BIP32KeyData,
    crack_prv_key,
    derive,
    derive_from_account,
    pub_key_derivation_tweaks,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib.bip32.bip32 import _derive
from btclib.bip32.der_path import _indexes_from_der_path_str
from btclib.curves import (
    bytes_from_point,
    bytes_from_prv_key_int,
    mult,
    point_from_octets,
)
from btclib.curves import secp256k1 as ec
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.to_pub_key import pub_keyinfo_from_key
from tests import load, vector_id


def test_exceptions() -> None:
    with pytest.raises(BTClibValueError, match="not a private or public key"):
        # invalid checksum
        xprv = "xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L"
        p2pkh(xprv)

    with pytest.raises(BTClibValueError, match="not a private key"):
        xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        xpub_from_xprv(xpub)

    seed = "5b56c417303faa3fcba7e57400e120a0"
    with pytest.raises(BTClibValueError, match="unknown extended key version: "):
        version = b"\x04\x88\xad\xe5"
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
    xkey_data.version = "1234"  # type: ignore[assignment]
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
    xkey_data.depth = ()  # type: ignore[assignment]
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.parent_fingerprint = (xkey_data.parent_fingerprint)[:-1]
    with pytest.raises(BTClibValueError, match="invalid parent_fingerprint length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.parent_fingerprint = "1234"  # type: ignore[assignment]
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
    xkey_data.index = ()  # type: ignore[assignment]
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.chain_code = (xkey_data.chain_code)[:-1]
    with pytest.raises(BTClibValueError, match="invalid chain_code length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.chain_code = "length is 32 but not a chaincode"  # type: ignore[assignment]
    assert len(xkey_data.chain_code) == 32
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.key = (xkey_data.key)[:-1]
    with pytest.raises(BTClibValueError, match="invalid key length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    xkey_data.key = "length is 33, but not a key      "  # type: ignore[assignment]
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


def bip32_vectors() -> list[Any]:
    """One case per derivation of BIP32 test vectors #1 to #4.

    The file groups the derivations by seed, and the seed is the id of
    the vector it belongs to: "vector 3, m/0h" rather than a number that
    says nothing, and a failing derivation does not silence the rest.
    """
    test_vectors = load("bip32", "_data", "bip32_test_vectors.json")
    return [
        pytest.param(
            seed, der_path, xpub, xprv, id=vector_id(index, seed[:16], der_path)
        )
        for index, seed in enumerate(test_vectors)
        for der_path, xpub, xprv in test_vectors[seed]
    ]


@pytest.mark.parametrize(("seed", "der_path", "xpub", "xprv"), bip32_vectors())
def test_bip32_vectors(seed: str, der_path: str, xpub: str, xprv: str) -> None:
    """BIP32 test vectors #1, #2, #3, and #4.

    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """
    mxprv = rootxprv_from_seed(seed)
    assert xprv == derive(mxprv, der_path)
    assert xpub == xpub_from_xprv(xprv)


@pytest.mark.parametrize(
    ("xkey", "err_msg"),
    [
        pytest.param(xkey, err_msg, id=vector_id(index, err_msg))
        for index, (xkey, err_msg) in enumerate(
            load("bip32", "_data", "bip32_invalid_keys.json")
        )
    ],
)
def test_invalid_bip32_xkeys(xkey: str, err_msg: str) -> None:
    """BIP32 test vectors #5.

    https://github.com/bitcoin/bips/pull/921

    btclib is the upstream of these: that pull request is Ferdinando
    Ametrano's, and it landed the day the file was vendored. The 16 keys
    are the BIP's; the second column is btclib's own, holding btclib error
    messages the BIP does not and should not carry, so a refresh from
    upstream refreshes the keys and never the messages.
    tests/_data/README.md pins the revision.
    """
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

            indexes = _indexes_from_der_path_str(der_path)
            assert address == p2pkh(derive(rootxprv, indexes))

        assert derive(rootxprv, "m") == rootxprv


def test_derive_exceptions() -> None:
    # root key, zero depth
    rootmxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv = BIP32KeyData.b58decode(rootmxprv)
    # not `xprv == _derive(xprv, "m")`: `_derive` returns the private
    # `_BIP32KeyData`, whose two caching fields the class tells the reader
    # not to rely on, and a dataclass __eq__ answers False across classes
    # however equal the six fields are. What that would mean to assert --
    # the empty path derives the key itself -- is the line below, in the
    # encoding that compares all six
    assert rootmxprv == derive(xprv, "m")
    assert rootmxprv == derive(xprv, "")

    fingerprint = hash160(pub_keyinfo_from_key(xprv)[0])[:4]
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
        full_path = f"{der_path}/{branch}/{index}"
        addr = p2pkh(derive(rmxprv, full_path))
        assert addr == p2pkh(derive_from_account(mxpub, branch, index))

    err_msg = "invalid private derivation at branch level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0x80000000, 0, True)

    err_msg = "invalid branch number: 65536"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0xFFFF + 1, 0, branches_0_1_only=False)

    err_msg = "invalid branch number: 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 2, 0)

    err_msg = "invalid private derivation at address index level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0x80000000, max_index=0xFFFFFFFF)

    err_msg = "invalid address index: 65536"
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
    """Https://github.com/bitcoin/bips/pull/905."""
    seed = "57fb1e450b8afb95c62afbcd49e4100d6790e0822b8905608679180ac34ca0bd45bf7ccc6c5f5218236d0eb93afc78bd117b9f02a6b7df258ea182dfaef5aad7"
    xroot = rootxprv_from_seed(seed)
    der_path = "m/44H/60H/0H"
    xprv = "xprv9yqXG1Cns3YEQi6fsCJ7NGV5sHPiyZcbgLVst61dbLYyn7qy1G9aFtRmaYp481ounqnVf9Go2ymQ4gmxZLEwYSRhU868aDk4ZxzGvqHJVhe"
    assert derive(xroot, der_path) == xprv
    xpub = "xpub6CpsfWjghR6XdCB8yDq7jQRpRKEDP2LT3ZRUgURF9g5xevB7YoTpogkFRqq5nQtVSN8YCMZo2CD8u4zCaxRv85ctCWmzEi9gQ5DBhBFaTNo"
    assert xpub_from_xprv(xprv) == xpub


def test_pub_key_derivation() -> None:
    parent_xpub = "xpub6CpsfWjghR6XdCB8yDq7jQRpRKEDP2LT3ZRUgURF9g5xevB7YoTpogkFRqq5nQtVSN8YCMZo2CD8u4zCaxRv85ctCWmzEi9gQ5DBhBFaTNo"
    proper_child = "xpub6FCCuDg6j52SWRVZ1TugkjrnGkqPcDuNNKDzohU2mmd4dxiGJypZa535iqYT8KcN2oouRF7A6tXEGAX6HCSjQe7HVSDR4LQ4yUT3HwF1Tqi"
    assert derive(parent_xpub, "m/0") == proper_child
    parent_key = BIP32KeyData.b58decode(parent_xpub).key
    parent_fingerprint = hash160(parent_key)[:4]
    assert BIP32KeyData.b58decode(proper_child).parent_fingerprint == parent_fingerprint

    orphan_child_key = BIP32KeyData.b58decode(proper_child)
    orphan_child_key.parent_fingerprint = b"\x00" * 4
    orphan_child = "xpub6DXuQW1FgeHbhsSchbuDWE9Bj8mPiPUpiroAmAvRdRqYbGHXHTyEkttkxSvtCac64QzpasL1Tvd5Znvn5GQMswQUrpRBsPRz7npvyZ8ExWi"
    assert orphan_child_key.b58encode() == orphan_child


def test_no_key_material_in_repr_or_exceptions() -> None:
    """Private key material must not reach reprs or exception messages.

    https://github.com/btclib-org/btclib/issues/137
    """
    xprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
    xprv_data = BIP32KeyData.b58decode(xprv)

    # the dataclass-generated repr would print key and chain code
    for secret in (xprv_data.key, xprv_data.chain_code):
        assert secret.hex() not in repr(xprv_data)
        assert repr(secret) not in repr(xprv_data)
    # while the non-secret fields remain readable
    assert xprv_data.version.hex() in repr(xprv_data)

    # the derivation cache must not print the private scalar either
    prv_int = int.from_bytes(xprv_data.key, byteorder="big", signed=False)
    assert str(prv_int) not in repr(_derive(xprv_data, "m"))

    # public material is not masked
    xpub_data = BIP32KeyData.b58decode(xpub_from_xprv(xprv))
    assert xpub_data.key.hex() in repr(xpub_data)
    assert xpub_data.chain_code.hex() in repr(xpub_data)

    # the seed must not reach the exception message
    seed = "5b56c417303faa3fcba7e57400e120"
    with pytest.raises(BTClibValueError, match="too few bits for seed: ") as excinfo:
        rootxprv_from_seed(seed)
    assert seed not in str(excinfo.value)

    # an xprv passed where an xpub is expected must not be echoed
    child_xprv = derive(xprv, "m/0")
    with pytest.raises(BTClibValueError, match="not a public key: ") as excinfo:
        crack_prv_key(xprv, child_xprv)
    assert xprv not in str(excinfo.value)


class _ForcedHmac:
    """An hmac whose digest is chosen rather than computed."""

    def __init__(self, digest: bytes) -> None:
        self._digest = digest

    def digest(self) -> bytes:
        return self._digest


def _force_hmac(monkeypatch: pytest.MonkeyPatch, il: int, chain_code: bytes) -> None:
    """Make every derivation see il as the left half of its hmac.

    The three children BIP32 calls invalid are unreachable at odds of
    about 2^-127, which is exactly why the branches rejecting them can
    only be tested by dictating the hmac. bip32 calls hmac.new through
    the module, so patching it there is what the derivation sees.
    """
    digest = il.to_bytes(32, byteorder="big", signed=False) + chain_code
    monkeypatch.setattr(hmac, "new", lambda *args, **kwargs: _ForcedHmac(digest))


def test_derivation_is_the_arithmetic_bip32_defines() -> None:
    """Both derivations, against the scalar and point arithmetic in Python.

    libsecp256k1 adds the offset to the key, privately and publicly, and
    BIP32 is defined for secp256k1 alone: there is no other curve for a
    fallback to serve, so nothing in the library computes either sum the
    other way any more. What holds the delegation to BIP32's own
    equations is having them here -- `ki = parse256(IL) + kpar (mod n)`
    and `Ki = point(parse256(IL)) + Kpar` -- written out over the same
    hmac the derivation takes, and the shipped vectors for the rest.
    """
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    parent = BIP32KeyData.b58decode(rootxprv)
    index = 42
    parent_prv_key = int.from_bytes(parent.key[1:], byteorder="big", signed=False)
    parent_pub_key = bytes_from_prv_key_int(parent_prv_key)

    hmac_ = hmac.new(
        parent.chain_code,
        parent_pub_key + index.to_bytes(4, byteorder="big", signed=False),
        "sha512",
    ).digest()
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)

    child_prv_key = (parent_prv_key + offset) % ec.n
    child = BIP32KeyData.b58decode(derive(rootxprv, f"m/{index}"))
    assert child.chain_code == hmac_[32:]
    assert child.key == b"\x00" + child_prv_key.to_bytes(
        32, byteorder="big", signed=False
    )

    child_pub_key_point = ec.add(point_from_octets(parent_pub_key), mult(offset))
    child_pub = BIP32KeyData.b58decode(derive(xpub_from_xprv(rootxprv), f"m/{index}"))
    assert child_pub.chain_code == hmac_[32:]
    assert child_pub.key == bytes_from_point(child_pub_key_point)
    # and the two derivations of one index meet, as BIP32 requires
    assert child_pub.key == bytes_from_prv_key_int(child_prv_key)


def test_invalid_child_prv_key(monkeypatch: pytest.MonkeyPatch) -> None:
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xkey = BIP32KeyData.b58decode(rootxprv)
    prv_key_int = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)

    # parse256(IL) >= n: no valid scalar to offset the parent key by
    err_msg = "invalid child index 0: the hmac left half is not a valid scalar"
    _force_hmac(monkeypatch, ec.n, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxprv, "m/0")

    # ki = 0: the one offset that cancels the parent key out
    err_msg = "invalid child index 0: the child private key is zero"
    _force_hmac(monkeypatch, ec.n - prv_key_int, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxprv, "m/0")


def test_invalid_child_pub_key(monkeypatch: pytest.MonkeyPatch) -> None:
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    rootxpub = xpub_from_xprv(rootxprv)
    xkey = BIP32KeyData.b58decode(rootxprv)
    prv_key_int = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)

    err_msg = "invalid child index 0: the hmac left half is not a valid scalar"
    _force_hmac(monkeypatch, ec.n, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxpub, "m/0")

    # offset * G is the parent point negated, so their sum is infinity
    err_msg = "invalid child index 0: the child public key is the point at infinity"
    _force_hmac(monkeypatch, ec.n - prv_key_int, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxpub, "m/0")


XKEY = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"


def test_assert_valid_does_not_rewrite_the_key_data() -> None:
    """A read is a read: assert_valid must not coerce fields in place.

    Writing back bytes(version), bytes(parent_fingerprint),
    bytes(chain_code), bytes(key), int(index) and int(depth) from a
    method serialize() and b58encode() call lets nominally read-only
    operations rewrite the object. Coercion belongs in __init__, where
    b58decode and a json object go through it.
    """
    xkey_data = BIP32KeyData.b58decode(XKEY)
    # a bytearray is bytes-like, so it serializes and compares equal: what
    # it is not is bytes, and assert_valid must not silently make it so.
    #
    # Every read of the field goes through an object-typed local before
    # being asserted on: "isinstance(bytes, bytearray)" narrows to Never,
    # the two having disjoint bases, and mypy then takes the rest of the
    # function for unreachable and checks none of it -- warn_unreachable
    # being off, in silence. Measured: with the assertion written directly
    # on the attribute, a reveal_type below it prints nothing at all
    xkey_data.chain_code = bytearray(xkey_data.chain_code)  # type: ignore[assignment]
    chain_code: object = xkey_data.chain_code
    assert isinstance(chain_code, bytearray)

    xkey_data.assert_valid()
    after_assert_valid: object = xkey_data.chain_code
    assert isinstance(after_assert_valid, bytearray)


def test_assert_valid_does_not_rewrite_on_a_read() -> None:
    xkey_data = BIP32KeyData.b58decode(XKEY)
    xkey_data.chain_code = bytearray(xkey_data.chain_code)  # type: ignore[assignment]

    xkey_data.b58encode()
    after_b58encode: object = xkey_data.chain_code
    assert isinstance(after_b58encode, bytearray)

    xkey_data.serialize()
    after_serialize: object = xkey_data.chain_code
    assert isinstance(after_serialize, bytearray)


def test_assert_valid_reports_a_float_field_instead_of_coercing_it() -> None:
    """Reported, not repaired behind the caller's back.

    Dropping the check outright instead would let the float reach
    to_bytes and leave the library through an AttributeError.
    """
    xkey_data = BIP32KeyData.b58decode(XKEY)
    xkey_data.index = float(xkey_data.index)  # type: ignore[assignment]
    with pytest.raises(BTClibTypeError, match="invalid index type: float"):
        xkey_data.assert_valid()
    index: object = xkey_data.index
    assert isinstance(index, float)

    xkey_data = BIP32KeyData.b58decode(XKEY)
    xkey_data.depth = float(xkey_data.depth)  # type: ignore[assignment]
    with pytest.raises(BTClibTypeError, match="invalid depth type: float"):
        xkey_data.assert_valid()


def test_the_coercion_still_happens_in_init() -> None:
    """from_dict is the reason it exists: json has no integer type."""
    xkey_data = BIP32KeyData.b58decode(XKEY)
    coerced = BIP32KeyData(
        version=xkey_data.version,
        depth=0.0,  # type: ignore[arg-type]
        parent_fingerprint=xkey_data.parent_fingerprint,
        index=0.0,  # type: ignore[arg-type]
        chain_code=xkey_data.chain_code,
        key=xkey_data.key,
    )
    assert isinstance(coerced.depth, int)
    assert isinstance(coerced.index, int)
    assert coerced.b58encode() == XKEY
    assert BIP32KeyData.b58decode(coerced.b58encode()) == coerced


def test_the_tweaks_of_a_public_derivation_are_the_derivation() -> None:
    """The scalars a path adds up to, against the key the path derives.

    What they are for is a key that cannot be derived from -- a BIP327
    MuSig2 aggregate key has no private key, so BIP328 derivation reaches
    the signers as tweaks (BIP373, `btclib.psbt.musig2`) -- and what says
    they are right is that applying them by hand lands on the key `derive`
    answers for the same path.
    """
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xpub = BIP32KeyData.b58decode(xpub_from_xprv(rootxprv))

    tweaks = pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1/2")
    derived = BIP32KeyData.b58decode(derive(xpub_from_xprv(rootxprv), "m/1/2"))
    point = point_from_octets(xpub.key, ec)
    for tweak in tweaks:
        point = ec.add(point, mult(int.from_bytes(tweak, "big"), ec.G, ec))
    assert bytes_from_point(point, ec) == derived.key

    # a hardened index needs the private key, and the refusal comes before
    # any step of the path is walked
    err_msg = "invalid hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1h")
