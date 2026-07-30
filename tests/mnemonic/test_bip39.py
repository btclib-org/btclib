#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.bip39` module."""

import secrets
from math import ceil

import pytest

from btclib.bip32 import bip32
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39
from tests import vectors


def test_bip39() -> None:
    lang = "en"
    mnem = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"

    raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
    mnemonic = bip39.mnemonic_from_entropy(raw_entr, lang)
    assert mnemonic == mnem

    r = bip39.entropy_from_mnemonic(mnemonic, lang)
    size = ceil(len(r) / 8)
    assert raw_entr == int(r, 2).to_bytes(size, byteorder="big", signed=False)

    wrong_mnemonic = f"{mnemonic} abandon"
    err_msg = "invalid number of bits: "
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.entropy_from_mnemonic(wrong_mnemonic, lang)

    err_msg = "invalid checksum: "
    with pytest.raises(BTClibValueError, match=err_msg):
        wr_m = "abandon abandon atom trust ankle walnut oil across awake bunker divorce oil"
        bip39.entropy_from_mnemonic(wr_m, lang)


BIP39_VECTORS = [
    pytest.param(*vector, id=vectors.vector_id(index, vector[0]))
    for index, vector in enumerate(
        vectors.load("mnemonic", "_data", "bip39_test_vectors.json")["english"]
    )
]


@pytest.mark.parametrize(("entr", "mnemonic", "seed", "xprv"), BIP39_VECTORS)
def test_vectors(entr: str, mnemonic: str, seed: str, xprv: str) -> None:
    """BIP39 test vectors.

    https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    """
    lang = "en"
    entropy = bytes.fromhex(entr)
    # clean up mnemonic from spurious whitespaces
    mnemonic = " ".join(mnemonic.split())
    assert mnemonic == bip39.mnemonic_from_entropy(entropy, lang)
    assert seed == bip39.seed_from_mnemonic(mnemonic, "TREZOR").hex()

    raw_entr = bip39.entropy_from_mnemonic(mnemonic, lang)
    size = (len(raw_entr) + 7) // 8
    assert entropy == int(raw_entr, 2).to_bytes(size, byteorder="big", signed=False)
    assert bip32.rootxprv_from_seed(seed) == xprv


def test_mnemonic_from_entropy() -> None:
    # zero leading bit should not throw an error
    bip39.mnemonic_from_entropy(secrets.randbits(127), "en")
    # random mnemonic
    bip39.mnemonic_from_entropy()


def test_mxprv_from_mnemonic() -> None:
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "")
    exp = "xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1"
    assert rootxprv == exp
