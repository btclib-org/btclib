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
import unicodedata
from math import ceil

import pytest

from btclib.bip32 import bip32
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import WORDLISTS, bip39, normalize_mnemonic
from tests import load, vector_id
from tests.mnemonic.mnemonic_test import fullwidth


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
    pytest.param(*vector, id=vector_id(index, vector[0]))
    for index, vector in enumerate(
        load("mnemonic", "_data", "bip39_test_vectors.json")["english"]
    )
]


@pytest.mark.parametrize(("entr", "mnemonic", "seed", "xprv"), BIP39_VECTORS)
def test_vectors(entr: str, mnemonic: str, seed: str, xprv: str) -> None:
    """BIP39 test vectors.

    https://github.com/trezor/python-mnemonic/blob/master/vectors.json

    Upstream's 24 English vectors, in order and value for value, plus a
    25th that is btclib's own: the last one repeated with tabs, newlines
    and doubled spaces through the mnemonic. Only the English array was
    ever taken, `english.txt` being the one wordlist shipped;
    tests/_data/README.md pins the revision.

    That 25th vector reaches the library with its whitespace intact:
    normalising it here first would ask `" ".join(mnemonic.split())`
    whether it collapses whitespace, and never ask btclib.
    """
    lang = "en"
    entropy = bytes.fromhex(entr)
    assert normalize_mnemonic(mnemonic) == bip39.mnemonic_from_entropy(entropy, lang)
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


# BIP39's japanese vectors, from bip32JP/bip32JP.github.io's
# test_JP_BIP39.json, the file bip-0039.mediawiki links as the japanese
# test vectors. Two of the twenty-four inline, the first and the last:
# what they pin is the NFKD, and two pin it as well as twenty-four would.
#
# The words are joined here rather than written as one string, because
# the separator is the point: U+3000 IDEOGRAPHIC SPACE is what the
# vectors put between words, and NFKD is what makes it U+0020 -- so a
# separator BIP39 never names is handled by the normalization BIP39 does.
#
# The passphrase is the vectors' own and decomposes twice over: U+334D
# SQUARE MEETORU is a compatibility character NFKD expands to four kana,
# and the voiced kana carry dakuten that separate from the kana they sit
# on. Without the NFKD BIP39 mandates, all twenty-four seeds come out
# wrong while every english vector still passes, "TREZOR" and
# `english.txt` being ASCII, which is NFKD already.
#
# S105 reads the name and sees a hardcoded password: it is one, and it is
# a published test vector guarding no wallet. Renaming it around the
# check would cost the reader the one word that says what BIP39 does with
# the string
JAPANESE_PASSPHRASE = "㍍ガバヴァぱばぐゞちぢ十人十色"  # noqa: S105

JAPANESE_VECTORS = [
    pytest.param(
        ["あいこくしん"] * 11 + ["あおぞら"],
        "a262d6fb6122ecf45be09c50492b31f92e9beb7d9a845987a02cefda57a15f9c"
        "467a17872029a9e92299b5cbdf306e3a0ee620245cbd508959b6cb7ca637bd55",
        "xprv9s21ZrQH143K258jAiWPAM6JYT9hLA91MV3AZUKfxmLZJCjCHeSjBvMbDy8C1mJ2FL5ytExyS97FAe6pQ6SD5Jt9SwHaLorA8i5Eojokfo1",
        id="jp-0",
    ),
    pytest.param(
        [
            "うちゅう",
            "ふそく",
            "ひしょ",
            "がちょう",
            "うけもつ",
            "めいそう",
            "みかん",
            "そざい",
            "いばる",
            "うけとる",
            "さんま",
            "さこつ",
            "おうさま",
            "ぱんつ",
            "しひょう",
            "めした",
            "たはつ",
            "いちぶ",
            "つうじょう",
            "てさぎょう",
            "きつね",
            "みすえる",
            "いりぐち",
            "かめれおん",
        ],
        "346b7321d8c04f6f37b49fdf062a2fddc8e1bf8f1d33171b65074531ec546d1d"
        "3469974beccb1a09263440fc92e1042580a557fdce314e27ee4eabb25fa5e5fe",
        "xprv9s21ZrQH143K2qVq43Phs1xyVc6jSxXHWJ6CDJjod3cgyEin7hgeQV6Dkw6s1LSfMYxoah4bPAnW4wmXfDUS9ghBEM18xoY634CBtX8HPrA",
        id="jp-23",
    ),
]


@pytest.mark.parametrize(("words", "seed", "xprv"), JAPANESE_VECTORS)
def test_nfkd_japanese_vectors(words: list[str], seed: str, xprv: str) -> None:
    """BIP39 stretches the NFKD of the sentence and of the passphrase.

    The checksum goes unverified because there is no japanese word-list
    to verify it against -- btclib ships english and italian -- which is
    why these are a seed test and not a round trip. The seed is what the
    normalization decides, so nothing is lost.
    """
    mnemonic = "　".join(words)
    assert bip39.seed_from_mnemonic(mnemonic, JAPANESE_PASSPHRASE, False).hex() == seed
    assert bip32.rootxprv_from_seed(seed) == xprv

    # the ideographic separator is not privileged: an ASCII space, a
    # newline or a doubled U+3000 is the same sentence and the same seed
    for separator in (" ", "\n", "　　", " \t"):
        respaced = separator.join(words)
        assert (
            bip39.seed_from_mnemonic(respaced, JAPANESE_PASSPHRASE, False).hex() == seed
        )

    # and the passphrase is normalized where it stands: handing over the
    # decomposition BIP39 asks for reaches the same seed, which is the
    # whole claim
    decomposed = unicodedata.normalize("NFKD", JAPANESE_PASSPHRASE)
    assert decomposed != JAPANESE_PASSPHRASE
    assert bip39.seed_from_mnemonic(mnemonic, decomposed, False).hex() == seed

    # the passphrase's own whitespace is content, not a separator: a
    # doubled space in it is a different passphrase and must not collapse
    spaced = f"{JAPANESE_PASSPHRASE}  x"
    collapsed = f"{JAPANESE_PASSPHRASE} x"
    assert bip39.seed_from_mnemonic(
        mnemonic, spaced, False
    ) != bip39.seed_from_mnemonic(mnemonic, collapsed, False)


def test_nfkd_fullwidth_latin() -> None:
    """A japanese IME types english words in fullwidth latin.

    U+FF41 is not "a" until NFKD decomposes it, so without the
    normalization the word-list lookup fails and a mnemonic a user can
    read back to themselves is refused.
    """
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    wide = " ".join(fullwidth(word) for word in mnemonic.split())
    assert wide != mnemonic
    assert normalize_mnemonic(wide) == mnemonic
    assert bip39.entropy_from_mnemonic(wide) == bip39.entropy_from_mnemonic(mnemonic)
    assert bip39.seed_from_mnemonic(wide, "") == bip39.seed_from_mnemonic(mnemonic, "")
    assert bip39.mxprv_from_mnemonic(wide) == bip39.mxprv_from_mnemonic(mnemonic)


def test_mxprv_from_mnemonic() -> None:
    mnemonic = "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
    rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "")
    exp = "xprv9s21ZrQH143K3ZxBCax3Wu25iWt3yQJjdekBuGrVa5LDAvbLeCT99U59szPSFdnMe5szsWHbFyo8g5nAFowWJnwe8r6DiecBXTVGHG124G1"
    assert rootxprv == exp


def test_the_wordlist_has_to_be_bip39_sized() -> None:
    """WORDLISTS is shared, and only its 2048-word lists are BIP39's.

    slip39 is registered on the same registry, so lang="slip39" is a
    request bip39 can be given; 1024 words encode ten bits each, and
    answering would be a base-1024 sentence no BIP39 wallet reads. The
    power-of-two test inside load_lang does not catch it -- 1024 is one.
    """
    assert WORDLISTS.language_length("slip39") == 1024

    err_msg = "invalid bip39 wordlist length: 1024; expected: 2048"
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.mnemonic_from_entropy(bytes.fromhex("00" * 16), "slip39")

    # a sentence of slip39 words, so that the refusal is the word-list
    # length and not an unknown word
    mnemonic = " ".join(WORDLISTS.wordlist("slip39")[:12])
    with pytest.raises(BTClibValueError, match=err_msg):
        bip39.entropy_from_mnemonic(mnemonic, "slip39")
