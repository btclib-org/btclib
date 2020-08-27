#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Entropy conversion from/to mnemonic word-list sentence.

Entropy must be represented as binary 0/1 string.

Warning: these functions are not meant for end-users which are
better served by the bip39 and electrum module functions.
"""

from os import path
from typing import List

from .utils import ensure_is_power_of_two

WordList = List[str]


class WordLists:
    """Class for word-lists to be used in entropy/mnemonic conversions.

    Word-lists are from:

    * *en*: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    * *it*: https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt

    More word-lists can be added using the load_lang method.

    Word-lists are loaded only if needed and read only once from disk.
    """

    def __init__(self) -> None:

        path_to_filename = path.join(path.dirname(__file__), "data")
        self.language_files = {
            "en": path.join(path_to_filename, "english.txt"),
            "it": path.join(path_to_filename, "italian.txt"),
        }
        self.languages = list(self.language_files)

        # create dictionaries where each language has empty word-list
        wordlists: List[List[str]] = [[] for _ in self.languages]
        self._wordlist = dict(zip(self.languages, wordlists))

        zeros = len(self.languages) * [0]
        self._bits_per_word = dict(zip(self.languages, zeros))
        self._language_length = dict(zip(self.languages, zeros))

    def load_lang(self, lang: str, filename: str = None) -> None:
        """Load/add a language word-list if not loaded/added yet.

        The language file has to be provided for adding new languages
        beyond those already provided.
        """

        # a new language, unknown before
        if lang not in self.languages:
            if filename is None:
                raise ValueError(f"Missing file for language '{lang}'")
            else:
                # initialize the new language
                self.languages.append(lang)
                self.language_files[lang] = filename
                self._wordlist[lang] = []
                self._bits_per_word[lang] = 0
                self._language_length[lang] = 0

        # language has not been loaded yet
        if self._language_length[lang] == 0:
            with open(self.language_files[lang], "r") as f:
                lines = f.readlines()

            nwords = len(lines)
            ensure_is_power_of_two(nwords, "invalid wordlist length")

            self._language_length[lang] = nwords
            # clean up and normalization are missing, but removal of \n
            self._wordlist[lang] = [line[:-1] for line in lines]

    def wordlist(self, lang: str) -> WordList:
        """Return the language word-list."""

        self.load_lang(lang)
        return self._wordlist[lang]

    def language_length(self, lang: str) -> int:
        """Return the number of words in the language word-list."""

        self.load_lang(lang)
        return self._language_length[lang]


# singleton
_wordlists = WordLists()

Mnemonic = str


def _mnemonic_from_indexes(indexes: List[int], lang: str) -> Mnemonic:
    """Return the mnemonic from a list of word-list indexes.

    Return the mnemonic from a list of integer indexes into
    a given language word-list.
    """

    words = []
    wordlist = _wordlists.wordlist(lang)
    for index in indexes:
        word = wordlist[index]
        words.append(word)
    return " ".join(words)


def _indexes_from_mnemonic(mnemonic: Mnemonic, lang: str) -> List[int]:
    """Return the word-list indexes for a given mnemonic.

    Return the list of integer indexes into a language word-list
    for a given mnemonic.
    """

    words = mnemonic.split()
    wordlist = _wordlists.wordlist(lang)
    return [wordlist.index(w) for w in words]
