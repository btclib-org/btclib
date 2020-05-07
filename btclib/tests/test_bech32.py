#!/usr/bin/python3

# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""Reference tests for bech32.

These tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original tests.py file in test_bech32.py and test_segwitaddr.py
* checked for assertRaises instead of assertIsNone
"""

import unittest

from btclib.bech32 import b32decode

VALID_CHECKSUM = [
    "A12UEL5L",
    "a12uel5l",
    ("an83characterlonghumanreadablepartthatcontainsthenumber1andthe"
     "excludedcharactersbio1tt5tgs"),
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    ("11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
     "qqqqqqqqqqqqqqqqqqqqqqqqqc8247j"),
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
    # the next one would have been invalid with the 90 char limit
    ("an84characterslonghumanreadablepartthatcontainsthenumber1and"
     "theexcludedcharactersbio1569pvx"),
]

INVALID_CHECKSUM = [
    " 1nwldj5",  # HRP character out of range
    "\x7F" + "1axkwrx",  # HRP character out of range
    "\x80" + "1eym55h",  # HRP character out of range
    "pzry9x0s0muk",  # No separator character
    "1pzry9x0s0muk",  # Empty HRP
    "x1b4n0q5v",  # Invalid data character
    "li1dgmt3",  # Too short checksum
    "de1lg7wt\xff",  # Invalid character in checksum
    "A1G7SGD8",  # checksum calculated with uppercase form of HRP"
    "10a06t8",  # empty HRP
    "1qzzfhee",  # empty HRP
]


class TestBech32(unittest.TestCase):
    """Unit test class for bech32 encodings."""

    def test_valid_checksum(self):
        """Test validation of valid checksums."""
        for test in VALID_CHECKSUM:
            _, _ = b32decode(test)
            pos = test.rfind('1')
            test = test[:pos + 1] + \
                chr(ord(test[pos + 1]) ^ 1) + test[pos + 2:]
            self.assertRaises(ValueError, b32decode, test)

    def test_invalid_checksum(self):
        """Test validation (failure) of invalid checksums."""
        for test in INVALID_CHECKSUM:
            self.assertRaises(ValueError, b32decode, test)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
