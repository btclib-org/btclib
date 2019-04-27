#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Class for word-lists to be used in entropy/mnemonic conversions.
"""

import math
import os
from typing import List

WordList = List[str]

class WordLists:
    """Class for word-lists to be used in entropy/mnemonic conversions.
    
    Word-lists are from:

    * https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    * https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt

    More word-list can be added using the load_lang method.

    Word-lists are loaded only if needed and read only once from disk.
    """

    def __init__(self) -> None:

        path = os.path.join(os.path.dirname(__file__), "dictdata")
        self.language_files = {
            'en': os.path.join(path, 'english.txt'),
            'it': os.path.join(path, 'italian.txt')
        }
        self.languages = list(self.language_files)

        # create dictionaries where each language has None word-list
        values = len(self.languages)*[None]
        self._wordlist = dict(zip(self.languages, values))
        self._bits_per_word = dict(zip(self.languages, values))
        self._language_length = dict(zip(self.languages, values))

    def load_lang(self, lang: str, filename: str = None) -> None:
        """Load the language word-list if not loaded yet."""

        # a new language, unknown before
        if lang not in self.languages:
            if filename is None:
                raise ValueError(f"missing file for language '{lang}'")
            else:
                # initialize the new language
                self.languages.append(lang)
                self.language_files[lang] = filename
                self._wordlist[lang] = None
                self._bits_per_word[lang] = None
                self._language_length[lang] = None

        # language has not been loaded yet
        if self._wordlist[lang] == None:
            with open(self.language_files[lang], 'r') as f:
                lines = f.readlines()
            f.closed

            nwords = len(lines)
            # http://www.graphics.stanford.edu/~seander/bithacks.html
            # Determining if an integer is a power of 2
            if nwords & (nwords - 1) != 0:
                errMsg = f"wordlist length ({nwords}) must be a power of two"
                raise ValueError(errMsg)

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
