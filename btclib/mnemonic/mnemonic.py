# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Mnemonic sentence conversion from/to sequence of integer indexes."""

from __future__ import annotations

import threading
import unicodedata
from collections.abc import Sequence
from pathlib import Path

from btclib.exceptions import BTClibValueError

__all__ = [
    "BIP39_LANGUAGE_FILES",
    "DEFAULT_LANGUAGE_FILES",
    "WORDLISTS",
    "Mnemonic",
    "WordList",
    "WordLists",
    "data_file",
    "indexes_from_mnemonic",
    "mnemonic_from_indexes",
    "normalize_mnemonic",
]

WordList = Sequence[str]


def data_file(filename: str) -> str:
    """Return the path of a word-list shipped with btclib."""
    return str(Path(__file__).parent / "_data" / filename)


# The twelve word-lists of BIP39's reference implementation, keyed by
# ISO 639-1 code. Ten are bip-0039/'s own; russian and turkish are in
# trezor/python-mnemonic and on no page of the BIP, which is what makes
# them a way to read what that implementation writes rather than a
# language to reach for when generating -- and BIP39 itself says
# non-English word-lists are strongly discouraged for generating.
#
# "zh" is Simplified Chinese, which is also the Chinese electrum reads;
# Traditional is "zh_tw". The two share 1275 of their 2048 words, so a
# Chinese sentence is ambiguous between them about once in three hundred,
# and that is the case lang_from_mnemonic has to answer for.
BIP39_LANGUAGE_FILES = {
    "cs": data_file("czech.txt"),
    "en": data_file("english.txt"),
    "es": data_file("spanish.txt"),
    "fr": data_file("french.txt"),
    "it": data_file("italian.txt"),
    "ja": data_file("japanese.txt"),
    "ko": data_file("korean.txt"),
    "pt": data_file("portuguese.txt"),
    "ru": data_file("russian.txt"),
    "tr": data_file("turkish.txt"),
    "zh": data_file("chinese_simplified.txt"),
    "zh_tw": data_file("chinese_traditional.txt"),
}

# every word-list btclib ships: BIP39's twelve and slip39's, which is a
# scheme and not a language code, as its key says. SLIP-0039 supports no
# localization at all, so there is no "en" of it to collide with BIP39's
# -- which is a different list of a different length, 1024 words of ten
# bits against 2048 of eleven. It is registered here rather than on a
# private WordLists built by slip39.py so that every word-list btclib
# ships is reachable from the one place that holds them. Sharing the
# registry is what lets a caller ask bip39 for lang="slip39", so bip39
# refuses any list that is not 2048 words long rather than answer with a
# base-1024 sentence no BIP39 wallet reads
DEFAULT_LANGUAGE_FILES = {
    **BIP39_LANGUAGE_FILES,
    "slip39": data_file("wordlist.txt"),
}


class WordLists:
    """Class for word-lists to be used in entropy/mnemonic conversions.

    The word-lists loaded by default are DEFAULT_LANGUAGE_FILES: the
    twelve of BIP39's reference implementation, plus slip39's. More can
    be added, or an existing language pointed at another file, with the
    load_lang method; a caller wanting an altogether different set -- as
    electrum.py does, electrum's Portuguese not being BIP39's -- passes
    language_files to the constructor.

    The thirteen keys above are what alias.MnemonicLang names, and
    load_lang is why no lang parameter here or in bip39 and electrum is
    typed with it: the set is open, so a Literal would reject the
    language a caller has just loaded (issue #216).

    Word-lists are loaded only if needed and read only once from disk.
    Each word is NFKD-normalized as it is read, which is the form BIP39
    requires and the form electrum normalizes to, so a word looked up in
    either form is found; a '#' starts a comment, which is what carries
    the licence header of electrum's Portuguese list.

    power_of_two says whether the word count must be one. A BIP39 index
    is eleven bits, so for BIP39 it must; electrum converts to base
    len(wordlist) instead, and its Portuguese list has 1626 words, so for
    electrum it must not.

    The loading is under a lock, and the reason is not merely that two
    threads might read the same file twice. load_lang recorded the word
    count before the words -- "self._language_length[lang] = nwords" and
    then "self._wordlist[lang] = ..." -- and it treats a non-zero count as
    "already loaded". A second thread arriving between those two statements
    therefore skipped the load and got an *empty* word-list back, so
    mnemonic_from_indexes raised IndexError and indexes_from_mnemonic
    reported every word as unknown. The lock closes that, and the two
    assignments are also ordered the other way round now, so that the
    published count is never ahead of the words it counts.

    The module-level WORDLISTS is a singleton, and load_lang mutating it
    affects every caller in the process: adding a language, or pointing an
    existing one at another file, is a process-wide decision. Callers
    wanting a private set can build their own WordLists().
    """

    def __init__(
        self,
        language_files: dict[str, str] | None = None,
        power_of_two: bool = True,
    ) -> None:
        self._lock = threading.Lock()
        self.power_of_two = power_of_two
        self.language_files = dict(language_files or DEFAULT_LANGUAGE_FILES)
        self.languages = list(self.language_files)

        # create dictionaries where each language has empty word-list
        wordlists: list[list[str]] = [[] for _ in self.languages]
        self._wordlist = dict(zip(self.languages, wordlists, strict=True))
        # the index of every word, so that a lookup is not a scan of 2048
        # strings: indexes_from_mnemonic does one per word, and
        # lang_from_mnemonic one per word per language
        indexes: list[dict[str, int]] = [{} for _ in self.languages]
        self._index = dict(zip(self.languages, indexes, strict=True))

        zeros = len(self.languages) * [0]
        self._language_length = dict(zip(self.languages, zeros, strict=True))

    def load_lang(self, lang: str, filename: str | None = None) -> None:
        """Load/add a language word-list if not loaded/added yet.

        The language file has to be provided for adding new languages
        beyond those already provided.
        """
        with self._lock:
            known = lang in self.languages
            # language has been loaded already
            if known and self._language_length[lang] != 0:
                return
            if known:
                filename = self.language_files[lang]
            elif filename is None:
                raise BTClibValueError(f"Missing file for language '{lang}'")

            words = self._read_wordlist(filename)

            # a language is registered once its file has been read and
            # accepted, and not before: one left behind by a load that
            # raised would raise again on every call, langs_of_words
            # asking each language in turn whether it holds a word
            if not known:
                self.languages.append(lang)
                self.language_files[lang] = filename
            # the words first and the count second: the count is what
            # marks the language loaded, so publishing it before the
            # words it counts is what let a concurrent reader see an
            # empty list. Belt and braces beside the lock, which is
            # what actually closes it
            self._index[lang] = {word: i for i, word in enumerate(words)}
            self._wordlist[lang] = words
            self._language_length[lang] = len(words)

    def _read_wordlist(self, filename: str) -> list[str]:
        """Return the words of a word-list file, NFKD and comments dropped."""
        # utf-8 and not ascii: nine of the twelve word-lists are not
        # ascii, japanese and korean not even close, and the BIP
        # publishes them NFKD-encoded. A '#' starts a comment, which is
        # what carries the licence header of electrum's Portuguese list
        with Path(filename).open(encoding="utf-8") as file_:
            lines = file_.readlines()
        stripped = (line.split("#")[0].strip() for line in lines)
        words = [unicodedata.normalize("NFKD", word) for word in stripped if word]

        nwords = len(words)
        # http://www.graphics.stanford.edu/~seander/bithacks.html
        if self.power_of_two and nwords & (nwords - 1) != 0:
            err_msg = f"invalid wordlist length: {nwords}, not a power of two"
            raise BTClibValueError(err_msg)
        return words

    def wordlist(self, lang: str) -> WordList:
        """Return the language word-list."""
        self.load_lang(lang)
        return self._wordlist[lang]

    def language_length(self, lang: str) -> int:
        """Return the number of words in the language word-list."""
        self.load_lang(lang)
        return self._language_length[lang]

    def index(self, word: str, lang: str) -> int:
        """Return the index of a word into the language word-list."""
        self.load_lang(lang)
        normalized = unicodedata.normalize("NFKD", word)
        if normalized not in self._index[lang]:
            raise BTClibValueError(f"unknown '{lang}' word: '{word}'")
        return self._index[lang][normalized]

    def langs_of_words(self, words: Sequence[str]) -> list[str]:
        """Return the languages whose word-list holds every word.

        Every language is read from disk, the question being about all of
        them; a caller that knows the language names it instead of asking.
        """
        normalized = [unicodedata.normalize("NFKD", word) for word in words]
        langs = []
        for lang in self.languages:
            # the membership test below is on the dictionary load_lang
            # fills, so the load is a statement of its own rather than
            # something to hide inside the comprehension
            self.load_lang(lang)
            if all(word in self._index[lang] for word in normalized):
                langs.append(lang)
        return langs


# singleton
WORDLISTS = WordLists()

Mnemonic = str


def normalize_mnemonic(mnemonic: Mnemonic) -> Mnemonic:
    r"""Return the mnemonic as btclib reads it, whatever separates its words.

    NFKD first, then every run of unicode whitespace becomes one space,
    so that `" abandon  abandon\tabandon "` and
    `"abandon abandon abandon"` are the same sentence and reach the same
    seed. That is btclib's answer for every mnemonic scheme: BIP39
    mandates the NFKD and describes words separated by spaces, but says
    nothing about a doubled space, a tab, or the newline a mnemonic
    wrapped across two lines of a paper backup carries.

    The NFKD comes first, and not merely because BIP39 asks for it.
    U+3000, the ideographic space BIP39's own Japanese vectors separate
    words with, decomposes to U+0020, so the separator question is
    answered by the normalization the spec already requires rather than
    by a rule of btclib's; and normalizing first leaves no run of
    whitespace for the collapse to miss, which the other order does --
    U+00A8 decomposes to a space plus a combining diaeresis, so
    collapsing before normalizing hands PBKDF2 two adjacent spaces.

    Refusing anything but a single space is the other defensible
    position, and it is what the reference implementation reads: trezor's
    python-mnemonic splits on `" "`, so a doubled space is an empty word
    and an error. It is not taken here because that implementation is
    strict only where it checks a mnemonic -- its `to_seed` applies NFKD
    and nothing else, so a leading space or a trailing newline stretches
    into a *different seed* with no complaint, and an unreadable wallet
    is the one outcome worse than a refusal. Collapsing cannot do that,
    and it refuses nothing a wallet, a mail client or an editor can
    plausibly produce.

    Zero-width characters stay: U+200B and U+FEFF carry no White_Space
    property and survive NFKD, so a word holding one is an unknown word
    rather than two words -- which is a refusal, the safe answer, and not
    a silently different seed.

    This is not electrum's normalization, and cannot be: `electrum.py`
    lower-cases, drops the combining characters and joins words that NFKD
    left either side of a space between two CJK characters. Dropping
    combining characters undoes the very decomposition BIP39 requires, so
    the two schemes need two functions, and electrum keeps its own.
    """
    return " ".join(unicodedata.normalize("NFKD", mnemonic).split())


def mnemonic_from_indexes(
    indexes: Sequence[int],
    lang: str,
    wordlists: WordLists = WORDLISTS,
    separator: str = " ",
) -> Mnemonic:
    """Return the mnemonic from a list of word-list integer indexes.

    Return the mnemonic from a list of integer indexes into a given
    language word-list.
    """
    wordlist = wordlists.wordlist(lang)
    words = [wordlist[index] for index in indexes]
    return separator.join(words)


def indexes_from_mnemonic(
    mnemonic: Mnemonic, lang: str, wordlists: WordLists = WORDLISTS
) -> list[int]:
    """Return the word-list integer indexes for a given mnemonic.

    Return the list of integer indexes into a language word-list for a
    given mnemonic. The sentence is split on any whitespace, the
    ideographic space of a japanese mnemonic included.
    """
    words = mnemonic.split()
    return [wordlists.index(word, lang) for word in words]
