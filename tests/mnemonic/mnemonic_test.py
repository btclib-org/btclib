# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.mnemonic` module."""

import threading
from pathlib import Path
from typing import Any, get_args
from unicodedata import normalize

import pytest
from typing_extensions import override

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
from btclib.mnemonic.mnemonic import WordLists, data_file


def test_mnemonic() -> None:
    """Round-trip a mnemonic through its wordlist indexes."""
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
    """Return text in fullwidth latin, as a japanese IME types it."""
    # ASCII lower-case as a japanese IME types it, U+FF41 upwards. Built
    # rather than written out: the fullwidth letters are indistinguishable
    # from the ASCII ones in a diff, which is the whole reason NFKD has to
    # reach them
    return "".join(chr(ord(char) - ord("a") + 0xFF41) for char in text)


def test_normalize_mnemonic() -> None:
    """Verify NFKD then whitespace collapse, and what must survive it."""
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
    """Return the mnemonic re-joined with the given whitespace shape."""
    return prefix + separator.join(mnemonic.split()) + suffix


@pytest.mark.parametrize("prefix, separator, suffix", WHITESPACE_SHAPES)
def test_bip39_whitespace(prefix: str, separator: str, suffix: str) -> None:
    """Verify BIP39's answers are unchanged by the whitespace shape."""
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


@pytest.mark.parametrize("prefix, separator, suffix", WHITESPACE_SHAPES)
def test_electrum_whitespace(prefix: str, separator: str, suffix: str) -> None:
    """Verify electrum's answers are unchanged by the whitespace shape."""
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


@pytest.mark.parametrize("prefix, separator, suffix", WHITESPACE_SHAPES)
def test_indexes_from_mnemonic_whitespace(
    prefix: str, separator: str, suffix: str
) -> None:
    """Verify the shared index layer is whitespace-insensitive too."""
    # the shared layer answers the same question the two schemes do:
    # str.split() with no argument is already a split on any run of
    # unicode whitespace, which is half of normalize_mnemonic
    mnemonic = respace(BIP39_MNEMONIC, prefix, separator, suffix)
    assert indexes_from_mnemonic(mnemonic, "en") == indexes_from_mnemonic(
        BIP39_MNEMONIC, "en"
    )


def test_wordlist_1() -> None:
    """Verify the english word-list loads its 2048 words."""
    lang = "en"
    d = WORDLISTS.wordlist(lang)
    assert isinstance(d, list)
    assert len(d) == 2048
    length = WORDLISTS.language_length(lang)
    assert length == 2048


def test_wordlist_2() -> None:
    """Refuse a missing or short word-list; add a language dynamically."""
    # a private WordLists and not the singleton: adding a language to that
    # one is process-wide, so a test that did would leave every later test
    # of language detection with a language it did not expect
    word_lists = WordLists()

    lang = "fakeen"
    # missing file for language 'fakeen''
    err_msg = "Missing file for language 'fakeen'"
    with pytest.raises(BTClibValueError, match=err_msg):
        word_lists.load_lang(lang)

    # dictionary length must be a power of two.
    # fakeenglish.txt is btclib's own and deliberately broken: bip-0039's
    # english.txt with `abandon` deleted, so 2047 words. Regenerate it from
    # english.txt if that ever changes, which it has not since 2014;
    # tests/_data/README.md records both
    fname = "fakeenglish.txt"
    filename = str(Path(__file__).parent / "_data" / fname)
    err_msg = "invalid wordlist length: "
    with pytest.raises(BTClibValueError, match=err_msg):
        word_lists.load_lang(lang, filename)
    # and the language it could not read is not registered: asked again,
    # it reads the file again and raises again, rather than answering as
    # a language with no words
    assert lang not in word_lists.languages
    with pytest.raises(BTClibValueError, match=err_msg):
        word_lists.load_lang(lang, filename)

    # dynamically add a new language
    lang = "en2"
    fname = "english.txt"
    filename = str(Path(__file__).parent / "_data" / fname)
    word_lists.load_lang(lang, filename)
    length = word_lists.language_length(lang)
    assert length == 2048
    assert word_lists.langs_of_words(["abandon", "zoo"]) == ["en", "en2"]


def test_every_wordlist() -> None:
    """Twelve BIP39 languages, and 2048 unique NFKD words in each.

    A private WordLists rather than the singleton: test_wordlist_2 adds
    two languages to that one, so a count taken from it would depend on
    which test ran first.

    Thirteen entries and twelve languages, because the registry holds
    every word-list btclib ships: "slip39" is a scheme keyed beside them,
    1024 words rather than 2048, and it is what bip39._base refuses.
    """
    bip39_languages = [
        "cs",
        "en",
        "es",
        "fr",
        "it",
        "ja",
        "ko",
        "pt",
        "ru",
        "tr",
        "zh",
        "zh_tw",
    ]
    word_lists = WordLists()
    assert word_lists.languages == [*bip39_languages, "slip39"]
    assert word_lists.language_length("slip39") == 1024
    for lang in bip39_languages:
        words = word_lists.wordlist(lang)
        assert len(words) == 2048 == word_lists.language_length(lang)
        assert len(set(words)) == 2048
        # NFKD is what BIP39 publishes and what a lookup normalizes to;
        # a word with whitespace around it would never be found
        assert all(word == normalize("NFKD", word) for word in words)
        assert all(word == word.strip() and word for word in words)


def test_index() -> None:
    """A word is looked up in any normalization, and named when unknown."""
    word_lists = WordLists()
    assert word_lists.index("abandon", "en") == 0
    assert word_lists.index("zoo", "en") == 2047
    # the spanish list is NFKD, so this is the composed spelling of a word
    # that is in it
    assert word_lists.index(normalize("NFC", "ábaco"), "es") == 0

    with pytest.raises(BTClibValueError, match="unknown 'en' word: 'abaco'"):
        word_lists.index("abaco", "en")


def test_langs_of_words() -> None:
    """The languages whose word-list holds every word, in registry order."""
    word_lists = WordLists()
    assert word_lists.langs_of_words(["abandon", "zoo"]) == ["en"]
    # a hundred words are in both english and french
    assert word_lists.langs_of_words(["abandon"]) == ["en", "fr"]
    assert word_lists.langs_of_words(["btclib"]) == []


def test_power_of_two() -> None:
    """The word count must be a power of two, unless the caller says not.

    BIP39 spends eleven bits on an index and so needs 2048 words;
    electrum converts to base len(wordlist) and reads a 1626-word
    Portuguese list, which is why the check is a policy of the registry
    rather than of the loader.
    """
    fname = "fakeenglish.txt"
    filename = str(Path(__file__).parent / "_data" / fname)

    with pytest.raises(BTClibValueError, match="invalid wordlist length: 2047"):
        WordLists().load_lang("fakeen", filename)

    word_lists = WordLists(power_of_two=False)
    word_lists.load_lang("fakeen", filename)
    assert word_lists.language_length("fakeen") == 2047


def test_comments_are_not_words() -> None:
    """A '#' starts a comment, which is what carries a licence header.

    Electrum's Portuguese word-list opens with Monero's BSD-3 notice, and
    electrum's own loader reads it the same way.
    """
    word_lists = WordLists(
        {"pt": data_file("electrum_portuguese.txt")}, power_of_two=False
    )
    words = word_lists.wordlist("pt")
    assert len(words) == 1626
    assert not any(word.startswith("#") for word in words)
    assert words[0] == "abaular"


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

        @override
        def __setitem__(self, key: str, value: list[str]) -> None:
            # `no branch`: this test loads one language, so the guard is
            # never false here. It is what keeps the block to the
            # assignment the race needs, another language or the empty
            # value of a failed load being neither
            if key == "en" and value:  # pragma: no branch
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
    real_open = Path.open

    def counting_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        reads.append(self)
        return real_open(self, *args, **kwargs)

    Path.open = counting_open  # type: ignore[method-assign]
    try:
        assert word_lists.language_length("en") == 2048
        assert len(word_lists.wordlist("en")) == 2048
        assert word_lists.language_length("en") == 2048
    finally:
        Path.open = real_open  # type: ignore[method-assign]

    assert len(reads) == 1


def test_mnemonic_lang_names_the_shipped_word_lists() -> None:
    """MnemonicLang is what a fresh WordLists knows, and no more.

    A fresh one, not the WORDLISTS singleton the tests above add two
    languages to: that openness is the reason no lang parameter is typed
    with the alias (issue #216), and the reason the alias needs a check
    of its own here rather than one from mypy.
    """
    assert set(get_args(MnemonicLang)) == set(WordLists().languages)
