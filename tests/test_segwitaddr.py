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


"""Reference tests for segwit adresses

These tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original tests.py file in test_bech32.py and test_segwitaddr.py
* splitted VALID_ADDRESS in VALID_BC_ADDRESS and VALID_TB_ADDRESS
* checked for assertRaises instead of assertIsNone
"""

import binascii
import unittest
from btclib import segwitaddr


VALID_BC_ADDRESS = [
    ["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["BC1SW50QA3JX3S", "6002751e"],
    ["bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        "5210751e76e8199196d454941c45d1b3a323"],
]

VALID_TB_ADDRESS = [
    ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"],
    ["tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"],
]

INVALID_ADDRESS = [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
    "bc1rw5uspcuh",
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu",
]

INVALID_ADDRESS_ENC = [
    ("BC", 0, 20),
    ("bc", 0, 21),
    ("bc", 17, 32),
    ("bc", 1, 1),
    ("bc", 16, 41),
]


class TestSegwitAddress(unittest.TestCase):
    """Unit test class for segwit addressess."""


    def test_valid_address(self):
        """Test whether valid addresses decode to the correct output."""
        for (address, hexscript) in VALID_BC_ADDRESS:
            hrp = "bc"
            wit_version, wit_program = segwitaddr.decode(hrp, address)
            script_pubkey = segwitaddr.scriptpubkey(wit_version, wit_program)
            self.assertEqual(script_pubkey, binascii.unhexlify(hexscript))
            addr = segwitaddr.encode(hrp, wit_version, wit_program)
            self.assertEqual(address.lower(), addr)
            self.assertRaises(ValueError, segwitaddr.decode, "tb", address)
        for (address, hexscript) in VALID_TB_ADDRESS:
            hrp = "tb"
            wit_version, wit_program = segwitaddr.decode(hrp, address)
            script_pubkey = segwitaddr.scriptpubkey(wit_version, wit_program)
            self.assertEqual(script_pubkey, binascii.unhexlify(hexscript))
            addr = segwitaddr.encode(hrp, wit_version, wit_program)
            self.assertEqual(address.lower(), addr)
            self.assertRaises(ValueError, segwitaddr.decode, "bc", address)


    def test_invalid_address(self):
        """Test whether invalid addresses fail to decode."""
        for test in INVALID_ADDRESS:
            self.assertRaises(ValueError, segwitaddr.decode, "bc", test)
            self.assertRaises(ValueError, segwitaddr.decode, "tb", test)


    def test_invalid_address_enc(self):
        """Test whether address encoding fails on invalid input."""
        for hrp, version, length in INVALID_ADDRESS_ENC:
            self.assertRaises(ValueError, segwitaddr.encode, hrp, version, [0] * length)


if __name__ == "__main__":
    unittest.main()
