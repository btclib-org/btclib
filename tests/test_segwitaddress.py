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


"""Reference tests for segwit adresses

Some of these tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original tests.py file in test_bech32.py and test_segwitaddr.py
* splitted VALID_ADDRESS in VALID_BC_ADDRESS and VALID_TB_ADDRESS
* checked for assertRaises instead of assertIsNone
"""

import binascii
import unittest

from btclib.curves import secp256k1 as ec
from btclib.script import serialize
from btclib.segwitaddress import (
    _decode, _encode, _scriptpubkey, h160_from_p2wpkh_address,
    p2wpkh_address, p2wpkh_p2sh_address, p2wsh_address, p2wsh_p2sh_address)
from btclib.utils import h160, octets_from_point, point_from_octets, _sha256

VALID_BC_ADDRESS = [
    ["BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"],
    ["BC1SW50QA3JX3S", "6002751e"],
    ["bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        "5210751e76e8199196d454941c45d1b3a323"],
    [" bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
        "5210751e76e8199196d454941c45d1b3a323"],
]

VALID_TB_ADDRESS = [
    ["tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"],
    ["tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"],
]

INVALID_ADDRESS = [
    "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",  # Invalid human-readable part
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",  # Invalid checksum
    "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",  # Invalid witness version
    "bc1rw5uspcuh",  # Invalid program length
    # Invalid program length
    "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
    # Invalid program length for witness version 0 (per BIP141)
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",  # Mixed case
    "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",  # zero padding of more than 4 bits
    # Non-zero padding in 8-to-5 conversion
    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
    "bc1gmk9yu",  # Empty data section
    # 92 chars
    "bc1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqv0jstn5"
]

INVALID_ADDRESS_ENC = [
    ("MAINNET", 0, 20),
    ("mainnet", 0, 21),
    ("mainnet", 17, 32),
    ("mainnet", 1, 1),
    ("mainnet", 16, 41),
]


class TestSegwitAddress(unittest.TestCase):
    """Unit test class for SegWit addressess."""

    def test_valid_address(self):
        """Test whether valid addresses decode to the correct output"""
        for a, hexscript in VALID_BC_ADDRESS:
            _, witvers, witprog = _decode(a, 'mainnet')
            script_pubkey = _scriptpubkey(witvers, witprog)
            self.assertEqual(script_pubkey, binascii.unhexlify(hexscript))
            address = _encode(witvers, witprog, 'mainnet')
            self.assertEqual(a.lower().strip(), address.decode())
            self.assertRaises(ValueError, _decode, a, 'testnet')
        for a, hexscript in VALID_TB_ADDRESS:
            _, witvers, witprog = _decode(a, 'testnet')
            script_pubkey = _scriptpubkey(witvers, witprog)
            self.assertEqual(script_pubkey, binascii.unhexlify(hexscript))
            address = _encode(witvers, witprog, 'testnet')
            self.assertEqual(a.lower(), address.decode())
            self.assertRaises(ValueError, _decode, a, 'mainnet')

    def test_invalid_address(self):
        """Test whether invalid addresses fail to decode"""
        for a in INVALID_ADDRESS:
            self.assertRaises(ValueError, _decode, a, 'mainnet')
            self.assertRaises(ValueError, _decode, a, 'testnet')

    def test_invalid_address_enc(self):
        """Test whether address encoding fails on invalid input"""
        for network, version, length in INVALID_ADDRESS_ENC:
            self.assertRaises(ValueError, _encode,
                              version, [0] * length, network)

    def test_encode_decode(self):

        # self-consistency
        addr = b'bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck'
        _, wv, wp = _decode(addr)
        self.assertEqual(_encode(wv, wp), addr)

        # invalid value
        wp[-1] = -1
        self.assertRaises(ValueError, _encode, wv, wp)
        # _encode(wv, wp)

        # string input
        addr = 'bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck'
        _, wv, wp = _decode(addr)
        self.assertEqual(_encode(wv, wp), addr.encode())

    def test_p2wpkh_p2sh_address(self):
        # https://matthewdowney.github.io/create-segwit-address.html
        pub = " 03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f"

        address = p2wpkh_p2sh_address(pub)
        self.assertEqual(address, b'36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g')

        address = p2wpkh_p2sh_address(pub, 'testnet')
        self.assertEqual(address, b'2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2')

        # http://bitcoinscri.pt/pages/segwit_p2sh_p2wpkh_address
        pub = "02f118cc409775419a931c57664d0c19c405e856ac0ee2f0e2a4137d8250531128"

        address = p2wpkh_p2sh_address(pub)
        self.assertEqual(address, b'3Mwz6cg8Fz81B7ukexK8u8EVAW2yymgWNd')

    def test_p2wpkh_address(self):

        # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
        # leading/trailing spaces should be tolerated
        pub = " 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        addr = b'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
        self.assertEqual(addr, p2wpkh_address(pub))
        addr = b'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'
        self.assertEqual(addr, p2wpkh_address(pub, 'testnet'))

        # http://bitcoinscri.pt/pages/segwit_native_p2wpkh_address
        pub = "02530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69261b42def7"
        addr = b'bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck'
        self.assertEqual(addr, p2wpkh_address(pub))

        _, _, wp = _decode(addr)
        self.assertEqual(bytes(wp), h160(pub))

        # SegWit address for 'mainnet', not 'testnet'
        self.assertRaises(ValueError, _decode, addr, 'testnet')
        # _decode(addr, 'testnet')

        # Uncompressed pubkey
        uncompr_pub = octets_from_point(ec, point_from_octets(ec, pub), False)
        self.assertRaises(ValueError, p2wpkh_address, uncompr_pub)
        # p2wpkh_address(uncompr_pub)

        # Wrong pubkey size: 34 instead of 33
        wrong_size_pub = pub + '00'
        self.assertRaises(ValueError, p2wpkh_address, wrong_size_pub)
        # p2wpkh_address(wrong_size_pub)

    def test_h160_from_p2wphk(self):
        pass
        network = "testnet"
        wv = 0
        wp = 20 * b'\x05'
        addr = _encode(wv, wp, network)
        h160_from_p2wpkh_address(addr, network)

        # Invalid witness version: 1
        addr = _encode(1, wp, network)
        self.assertRaises(ValueError, h160_from_p2wpkh_address, addr, network)
        # h160_from_p2wpkh_address(addr, network)

        # witness program length (21) is not 20 or 32
        addr = 'tb1qq5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5mpvsef'
        self.assertRaises(ValueError, h160_from_p2wpkh_address, addr, network)
        # h160_from_p2wpkh_address(addr, network)

        # is a SegWit address for 'mainnet', not 'testnet'
        addr = _encode(wv, wp, 'mainnet')
        self.assertRaises(ValueError, h160_from_p2wpkh_address, addr, network)
        # h160_from_p2wpkh_address(addr, network)

    def test_p2wsh_p2sh_address(self):

        # leading/trailing spaces should be tolerated
        pub = " 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        witness_script = [pub, 'OP_CHECKSIG']
        witness_script_bytes = serialize(witness_script)
        p2wsh_p2sh_address(witness_script_bytes)
        p2wsh_p2sh_address(witness_script_bytes, 'testnet')

    def test_p2wsh_address(self):

        # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
        pub = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        witness_script = [pub, 'OP_CHECKSIG']
        witness_script_bytes = serialize(witness_script)
        addr = b'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'
        self.assertEqual(addr, p2wsh_address(witness_script_bytes, 'testnet'))
        addr = b'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'
        self.assertEqual(addr, p2wsh_address(witness_script_bytes))

        _, _, wp = _decode(addr)
        self.assertEqual(bytes(wp), _sha256(witness_script_bytes))

        # SegWit address for 'mainnet', not 'testnet'
        self.assertRaises(ValueError, _decode, addr, 'testnet')
        # _decode(addr, 'testnet')


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
