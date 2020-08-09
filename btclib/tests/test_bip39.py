#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.bip39` module."

import json
import secrets
from math import ceil
from os import path

import pytest  # type: ignore

from btclib import bip39


def test_bip39() -> None:
    lang = "en"
    mnem = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"

    raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
    mnemonic = bip39.mnemonic_from_entropy(raw_entr, lang)
    assert mnemonic == mnem

    r = bip39.entropy_from_mnemonic(mnemonic, lang)
    size = ceil(len(r) / 8)
    assert raw_entr == int(r, 2).to_bytes(size, byteorder="big")

    wrong_mnemonic = mnemonic + " abandon"
    err_msg = "Wrong number of words: "
    with pytest.raises(ValueError, match=err_msg):
        bip39.entropy_from_mnemonic(wrong_mnemonic, lang)

    err_msg = "invalid checksum: "
    with pytest.raises(ValueError, match=err_msg):
        wr_m = "abandon abandon atom trust ankle walnut oil across awake bunker divorce oil"
        bip39.entropy_from_mnemonic(wr_m, lang)

    err_msg = "invalid number of bits for BIP39 entropy: "
    with pytest.raises(ValueError, match=err_msg):
        # Invalid number of bits (130) for BIP39 entropy; must be in ...
        binstr_entropy = "01" * 65  # 130 bits
        bip39._entropy_checksum(binstr_entropy)


def test_vectors() -> None:
    """BIP39 test vectors

    https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    """
    fname = "bip39_test_vectors.json"
    filename = path.join(path.dirname(__file__), "test_data", fname)
    with open(filename, "r") as f:
        test_vectors = json.load(f)["english"]

    lang = "en"
    # test_vector[3], i.e. the bip32 master private key, is tested in bip32
    for entr, mnemonic, seed, _ in test_vectors:
        entropy = bytes.fromhex(entr)
        # clean up mnemonic from spurious whitespaces
        mnemonic = " ".join(mnemonic.split())
        assert mnemonic == bip39.mnemonic_from_entropy(entropy, lang)
        assert seed == bip39.seed_from_mnemonic(mnemonic, "TREZOR").hex()

        raw_entr = bip39.entropy_from_mnemonic(mnemonic, lang)
        size = (len(raw_entr) + 7) // 8
        assert entropy == int(raw_entr, 2).to_bytes(size, byteorder="big")


def test_zeroleadingbit() -> None:
    # it should not throw an error
    bip39.mnemonic_from_entropy(secrets.randbits(127), "en")
