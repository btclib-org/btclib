#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Mnemonic sentence conversion from/to sequence of integer indexes."""

from __future__ import annotations

import threading
import unicodedata
from collections.abc import Sequence
from os import path

from btclib.exceptions import BTClibValueError

WordList = Sequence[str]


class WordLists:
    """Class for word-lists to be used in entropy/mnemonic conversions.

    Word-lists are from:

    * *en*: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    * *it*: https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt

    More word-lists can be added using the load_lang method.

    Word-lists are loaded only if needed and read only once from disk.

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

    def __init__(self) -> None:
        self._lock = threading.Lock()
        path_to_filename = path.join(path.dirname(__file__), "_data")
        self.language_files = {
            "en": path.join(path_to_filename, "english.txt"),
            "it": path.join(path_to_filename, "italian.txt"),
        }
        self.languages = list(self.language_files)

        # create dictionaries where each language has empty word-list
        wordlists: list[list[str]] = [[] for _ in self.languages]
        self._wordlist = dict(zip(self.languages, wordlists, strict=True))

        zeros = len(self.languages) * [0]
        self._language_length = dict(zip(self.languages, zeros, strict=True))

    def load_lang(self, lang: str, filename: str | None = None) -> None:
        """Load/add a language word-list if not loaded/added yet.

        The language file has to be provided for adding new languages
        beyond those already provided.
        """
        with self._lock:
            # a new language, unknown before
            if lang not in self.languages:
                self._init_new_lang(lang, filename)
            # language has not been loaded yet
            if self._language_length[lang] == 0:
                with open(self.language_files[lang], encoding="ascii") as file_:
                    lines = file_.readlines()

                nwords = len(lines)
                # http://www.graphics.stanford.edu/~seander/bithacks.html
                if nwords & (nwords - 1) != 0:
                    err_msg = f"invalid wordlist length: {nwords}, not a power of two"
                    raise BTClibValueError(err_msg)

                # the words first and the count second: the count is what
                # marks the language loaded, so publishing it before the
                # words it counts is what let a concurrent reader see an
                # empty list. Belt and braces beside the lock, which is
                # what actually closes it
                # clean up and normalization are missing, but removal of \n
                self._wordlist[lang] = [line[:-1] for line in lines]
                self._language_length[lang] = nwords

    def _init_new_lang(self, lang: str, filename: str | None) -> None:
        if filename is None:
            raise BTClibValueError(f"Missing file for language '{lang}'")
        # initialize the new language
        self.languages.append(lang)
        self.language_files[lang] = filename
        self._wordlist[lang] = []
        self._language_length[lang] = 0

    def wordlist(self, lang: str) -> WordList:
        """Return the language word-list."""
        self.load_lang(lang)
        return self._wordlist[lang]

    def language_length(self, lang: str) -> int:
        """Return the number of words in the language word-list."""
        self.load_lang(lang)
        return self._language_length[lang]


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


def mnemonic_from_indexes(indexes: Sequence[int], lang: str) -> Mnemonic:
    """Return the mnemonic from a list of word-list integer indexes.

    Return the mnemonic from a list of integer indexes into a given
    language word-list.
    """
    wordlist = WORDLISTS.wordlist(lang)
    words = [wordlist[index] for index in indexes]
    return " ".join(words)


def indexes_from_mnemonic(mnemonic: Mnemonic, lang: str) -> list[int]:
    """Return the word-list integer indexes for a given mnemonic.

    Return the list of integer indexes into a language word-list for a
    given mnemonic.
    """
    words = mnemonic.split()
    wordlist = WORDLISTS.wordlist(lang)
    return [wordlist.index(w) for w in words]
