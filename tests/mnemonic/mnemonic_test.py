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
from typing import Any

import pytest

from btclib.exceptions import BTClibValueError
from btclib.mnemonic import WORDLISTS, indexes_from_mnemonic, mnemonic_from_indexes
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

    # dictionary length (must be a power of two.
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
    """A concurrent reader used to get an empty word-list.

    load_lang recorded the word count before the words, and treats a
    non-zero count as "already loaded". A second thread arriving between
    the two assignments therefore skipped the load and got back the empty
    list the constructor had put there. Forcing that interleaving, the
    second caller saw 0 words instead of 2048.
    """
    word_lists = WordLists()
    paused = threading.Event()
    release = threading.Event()

    class BlockingDict(dict):  # type: ignore[type-arg]
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
    """Still loaded lazily, and still read from disk only once."""
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
