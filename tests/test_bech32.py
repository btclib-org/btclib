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


"""Reference tests for Bech32

These tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original tests.py file in test_bech32.py and test_segwitaddr.py
* checked for assertRaises instead of assertIsNone
"""

import unittest
from btclib import bech32

VALID_CHECKSUM = [
    "A12UEL5L",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
]

INVALID_CHECKSUM = [
    " 1nwldj5",
    "\x7F" + "1axkwrx",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
]


class TestBech32(unittest.TestCase):
    """Unit test class for segwit addressess."""


    def test_valid_checksum(self):
        """Test checksum creation and validation."""
        for test in VALID_CHECKSUM:
            hrp, _ = bech32.decode(test)
            pos = test.rfind('1')
            test = test[:pos+1] + chr(ord(test[pos + 1]) ^ 1) + test[pos+2:]
            self.assertRaises(ValueError, bech32.decode, test)


    def test_invalid_checksum(self):
        """Test validation of invalid checksums."""
        for test in INVALID_CHECKSUM:
            self.assertRaises(ValueError, bech32.decode, test)


if __name__ == "__main__":
    unittest.main()
