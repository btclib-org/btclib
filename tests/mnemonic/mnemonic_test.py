#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.mnemonic` module."""

import builtins
import threading
from os import path
from typing import Any, get_args

import pytest

from btclib.alias import MnemonicLang
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import (
    WORDLISTS,
    bip39,
    electrum,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
    normalize_mnemonic,
)
from btclib.mnemonic.mnemonic import WordLists


def test_mnemonic() -> None:
    lang = "en"
    mnem = (
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    )
    expected = [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313]
    indexes = indexes_from_mnemonic(mnem, lang)
    assert indexes == expected
    mnemonic = mnemonic_from_indexes(expected, lang)
    assert mnemonic == mnem


def fullwidth(text: str) -> str:
    # ASCII lower-case as a japanese IME types it, U+FF41 upwards. Built
    # rather than written out: the fullwidth letters are indistinguishable
    # from the ASCII ones in a diff, which is the whole reason NFKD has to
    # reach them
    return "".join(chr(ord(char) - ord("a") + 0xFF41) for char in text)


def test_normalize_mnemonic() -> None:
    # the ideographic space BIP39's japanese vectors separate words with
    # is a separator because NFKD says so, not because btclib says so
    assert normalize_mnemonic("\u3000a\u3000b\u3000") == "a b"
    # and so is every other run of unicode whitespace
    assert normalize_mnemonic(" \ta\r\n\v\fb\u00a0\u1680") == "a b"
    # fullwidth latin decomposes: an IME types the same sentence
    assert normalize_mnemonic(fullwidth("abandon")) == "abandon"
    # NFKD before the collapse and not after: U+00A8 decomposes to a
    # space plus a combining diaeresis, so the other order hands PBKDF2
    # two adjacent spaces
    assert normalize_mnemonic("x \u00a8y") == "x \u0308y"
    # zero-width characters carry no White_Space property and survive
    # NFKD, so a word holding one stays one unknown word -- a refusal,
    # which is safe, rather than a silently different seed
    assert normalize_mnemonic("a\u200bb") == "a\u200bb"
    assert normalize_mnemonic("a\ufeffb") == "a\ufeffb"
    # idempotent, so normalizing twice is not a second answer
    assert normalize_mnemonic(normalize_mnemonic(" a\tb ")) == "a b"


# every shape a mnemonic's whitespace plausibly arrives in: a paper
# backup transcribed over two lines, a sentence pasted out of a mail
# client, the leading space a double-click selection picks up, the
# ideographic space a japanese keyboard produces. btclib's answer is the
# canonical sentence's answer in all of them, whichever scheme reads it
WHITESPACE_SHAPES = [
    pytest.param("", " ", "", id="canonical"),
    pytest.param(" ", " ", "", id="leading-space"),
    pytest.param("", " ", " ", id="trailing-space"),
    pytest.param("\n\t", " ", " \n", id="leading-and-trailing"),
    pytest.param("", "  ", "", id="doubled-space"),
    pytest.param("", "\t", "", id="tab"),
    pytest.param("", "\n", "", id="newline"),
    pytest.param("", "\r\n", "", id="crlf"),
    pytest.param("", "\v", "", id="vertical-tab"),
    pytest.param("", "\f", "", id="form-feed"),
    pytest.param("", "\x85", "", id="next-line"),
    pytest.param("", "\u00a0", "", id="no-break-space"),
    pytest.param("", "\u1680", "", id="ogham-space-mark"),
    pytest.param("", "\u2003", "", id="em-space"),
    pytest.param("", "\u2028", "", id="line-separator"),
    pytest.param("", "\u202f", "", id="narrow-no-break-space"),
    pytest.param("", "\u205f", "", id="medium-mathematical-space"),
    pytest.param("", "\u3000", "", id="ideographic-space"),
    pytest.param(" \t\n", " \u3000\t\u00a0 ", "\u3000 ", id="all-at-once"),
]

BIP39_MNEMONIC = (
    "abandon abandon atom trust ankle walnut oil across awake bunker divorce abstract"
)

# electrum's own "standard" vector, from tests/mnemonic/electrum_test.py:
# mxprv_from_mnemonic answers for it, which "segwit" and the two "2fa"
# versions do not, so one mnemonic covers all three entry points
ELECTRUM_MNEMONIC = (
    "diagram crouch ball canal then hat panda spatial company "
    "liberty fetch awful ability"
)


def respace(mnemonic: str, prefix: str, separator: str, suffix: str) -> str:
    return prefix + separator.join(mnemonic.split()) + suffix


@pytest.mark.parametrize(("prefix", "separator", "suffix"), WHITESPACE_SHAPES)
def test_bip39_whitespace(prefix: str, separator: str, suffix: str) -> None:
    mnemonic = respace(BIP39_MNEMONIC, prefix, separator, suffix)
    assert normalize_mnemonic(mnemonic) == BIP39_MNEMONIC
    assert bip39.entropy_from_mnemonic(mnemonic) == bip39.entropy_from_mnemonic(
        BIP39_MNEMONIC
    )
    assert bip39.seed_from_mnemonic(mnemonic, "") == bip39.seed_from_mnemonic(
        BIP39_MNEMONIC, ""
    )
    assert bip39.mxprv_from_mnemonic(mnemonic) == bip39.mxprv_from_mnemonic(
        BIP39_MNEMONIC
    )


@pytest.mark.parametrize(("prefix", "separator", "suffix"), WHITESPACE_SHAPES)
def test_electrum_whitespace(prefix: str, separator: str, suffix: str) -> None:
    mnemonic = respace(ELECTRUM_MNEMONIC, prefix, separator, suffix)
    assert electrum.version_from_mnemonic(mnemonic) == electrum.version_from_mnemonic(
        ELECTRUM_MNEMONIC
    )
    assert electrum.entropy_from_mnemonic(mnemonic) == electrum.entropy_from_mnemonic(
        ELECTRUM_MNEMONIC
    )
    assert electrum.mxprv_from_mnemonic(mnemonic) == electrum.mxprv_from_mnemonic(
        ELECTRUM_MNEMONIC
    )


@pytest.mark.parametrize(("prefix", "separator", "suffix"), WHITESPACE_SHAPES)
def test_indexes_from_mnemonic_whitespace(
    prefix: str, separator: str, suffix: str
) -> None:
    # the shared layer answers the same question the two schemes do:
    # str.split() with no argument is already a split on any run of
    # unicode whitespace, which is half of normalize_mnemonic
    mnemonic = respace(BIP39_MNEMONIC, prefix, separator, suffix)
    assert indexes_from_mnemonic(mnemonic, "en") == indexes_from_mnemonic(
        BIP39_MNEMONIC, "en"
    )


def test_wordlist_1() -> None:
    lang = "en"
    d = WORDLISTS.wordlist(lang)
    assert isinstance(d, list)
    assert len(d) == 2048
    length = WORDLISTS.language_length(lang)
    assert length == 2048


def test_wordlist_2() -> None:
    lang = "fakeen"
    # missing file for language 'fakeen''
    err_msg = "Missing file for language 'fakeen'"
    with pytest.raises(BTClibValueError, match=err_msg):
        WORDLISTS.load_lang(lang)

    # dictionary length must be a power of two.
    # fakeenglish.txt is btclib's own and deliberately broken: bip-0039's
    # english.txt with `abandon` deleted, so 2047 words. Regenerate it from
    # english.txt if that ever changes, which it has not since 2014;
    # tests/_data/README.md records both
    fname = "fakeenglish.txt"
    filename = path.join(path.dirname(__file__), "_data", fname)
    err_msg = "invalid wordlist length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        WORDLISTS.load_lang(lang, filename)

    # dynamically add a new language
    lang = "en2"
    fname = "english.txt"
    filename = path.join(path.dirname(__file__), "_data", fname)
    WORDLISTS.load_lang(lang, filename)
    length = WORDLISTS.language_length(lang)
    assert length == 2048


def test_load_lang_is_not_a_race() -> None:
    """Guards against a concurrent reader getting an empty word-list.

    load_lang treats a non-zero word count as "already loaded", so were
    the count recorded before the words, a second thread arriving between
    the two assignments would skip the load and get back the empty list
    the constructor put there: 0 words instead of 2048. This test forces
    that interleaving.
    """
    word_lists = WordLists()
    paused = threading.Event()
    release = threading.Event()

    class BlockingDict(dict[str, list[str]]):
        """Block inside the assignment the race needed to interleave."""

        def __setitem__(self, key: str, value: list[str]) -> None:
            if key == "en" and value:
                paused.set()
                release.wait(10)
            super().__setitem__(key, value)

    word_lists._wordlist = BlockingDict(word_lists._wordlist)

    loaded: list[int] = []

    def load_in_thread() -> None:
        loaded.append(len(word_lists.wordlist("en")))

    thread = threading.Thread(target=load_in_thread)
    thread.start()
    try:
        assert paused.wait(10), "the blocking assignment was never reached"
        # the other thread is mid-load; a second caller must not see the
        # empty list it has not filled in yet. Without the lock this
        # returns immediately with 0 words
        second = threading.Thread(target=load_in_thread)
        second.start()
        second.join(0.5)
        assert second.is_alive(), (
            "the second caller did not wait for the load to finish"
        )
    finally:
        release.set()
        thread.join(10)
        second.join(10)

    assert loaded == [2048, 2048]


def test_load_lang_is_idempotent_and_reads_once() -> None:
    """Loaded lazily, and read from disk only once."""
    word_lists = WordLists()
    reads = []
    real_open = builtins.open

    def counting_open(*args: Any, **kwargs: Any) -> Any:
        reads.append(args[0])
        return real_open(*args, **kwargs)

    builtins.open = counting_open
    try:
        assert word_lists.language_length("en") == 2048
        assert len(word_lists.wordlist("en")) == 2048
        assert word_lists.language_length("en") == 2048
    finally:
        builtins.open = real_open

    assert len(reads) == 1


def test_mnemonic_lang_names_the_shipped_word_lists() -> None:
    """MnemonicLang is what a fresh WordLists knows, and no more.

    A fresh one, not the WORDLISTS singleton the tests above add two
    languages to: that openness is the reason no lang parameter is typed
    with the alias (issue #216), and the reason the alias needs a check
    of its own here rather than one from mypy.
    """
    assert set(get_args(MnemonicLang)) == set(WordLists().languages)
