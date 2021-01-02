#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.mnemonic` module."

from os import path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.mnemonic.mnemonic import (
    WORDLISTS,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
)


def test_mnemonic() -> None:
    lang = "en"
    mnem = (
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
    )
    indx = [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313]
    indexes = indexes_from_mnemonic(mnem, lang)
    assert indexes == indx
    mnemonic = mnemonic_from_indexes(indx, lang)
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

    # dictionary length (must be a power of two
    fname = "fakeenglish.txt"
    filename = path.join(path.dirname(__file__), "_data", fname)
    err_msg = "invalid wordlist length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        WORDLISTS.load_lang(lang, filename)

    # dinamically add a new language
    lang = "en2"
    fname = "english.txt"
    filename = path.join(path.dirname(__file__), "_data", fname)
    WORDLISTS.load_lang(lang, filename)
    length = WORDLISTS.language_length(lang)
    assert length == 2048
