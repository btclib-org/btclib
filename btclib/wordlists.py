#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Class for word-lists to be used in entropy/mnemonic conversions."""

import math
from os import path
from typing import List

from btclib.utils import ensure_is_power_of_two

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

        path_to_filename = path.join(path.dirname(__file__), "dictdata")
        self.language_files = {
            'en': path.join(path_to_filename, 'english.txt'),
            'it': path.join(path_to_filename, 'italian.txt')
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
                raise ValueError(f"missing file for language '{lang}'")
            else:
                # initialize the new language
                self.languages.append(lang)
                self.language_files[lang] = filename
                self._wordlist[lang] = []
                self._bits_per_word[lang] = 0
                self._language_length[lang] = 0

        # language has not been loaded yet
        if self._language_length[lang] == 0:
            with open(self.language_files[lang], 'r') as f:
                lines = f.readlines()
            f.closed

            nwords = len(lines)
            ensure_is_power_of_two(nwords, "wordlist length")

            self._bits_per_word[lang] = int(math.log(nwords, 2))
            self._language_length[lang] = nwords
            # clean up and normalization are missing, but removal of \n
            self._wordlist[lang] = [line[:-1] for line in lines]

    def bits_per_word(self, lang: str) -> int:
        """Return the number of bits represented by a single word.

        Return the number of bits represented by a single word for
        the given language.
        """
        self.load_lang(lang)
        return self._bits_per_word[lang]

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
