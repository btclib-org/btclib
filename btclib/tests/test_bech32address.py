#!/usr/bin/env python3

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


"""Tests for `btclib.bech32address` module.

Some of these tests are originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

- splitted the original tests.py file in test_bech32.py
  and test_bech32address.py
- checked for raised exceptions instead of assertIsNone
"""

import unittest

import pytest

from btclib.base58address import p2wpkh_p2sh, p2wsh_p2sh
from btclib.bech32address import (
    b32address_from_witness,
    p2wpkh,
    p2wsh,
    witness_from_b32address,
)
from btclib.script import encode
from btclib.secpoint import bytes_from_point, point_from_octets
from btclib.utils import hash160, sha256


class TestSegwitAddress(unittest.TestCase):
    """Unit test class for SegWit addressess."""

    def test_valid_address(self):
        """Test whether valid addresses decode to the correct output"""

        VALID_BC_ADDRESS = [
            [
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            ],
            [
                (
                    "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarva"
                    "ry0c5xw7k7grplx"
                ),
                (
                    "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d"
                    "454941c45d1b3a323f1433bd6"
                ),
            ],
            ["BC1SW50QA3JX3S", "6002751e"],
            [
                "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
                "5210751e76e8199196d454941c45d1b3a323",
            ],
            [
                " bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",  # extra leading space
                "5210751e76e8199196d454941c45d1b3a323",
            ],
        ]
        VALID_TB_ADDRESS = [
            [
                ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0s" "l5k7"),
                (
                    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329"
                    "604903262"
                ),
            ],
            [
                ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrx" "h6hy"),
                (
                    "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165da"
                    "b93e86433"
                ),
            ],
        ]

        for a, hexscript in VALID_BC_ADDRESS + VALID_TB_ADDRESS:
            witvers, witprog, network, _ = witness_from_b32address(a)
            script_pubkey = [witvers, witprog]
            self.assertEqual(encode(script_pubkey).hex(), hexscript)
            address = b32address_from_witness(witvers, witprog, network)
            self.assertEqual(a.lower().strip(), address.decode("ascii"))

    def test_invalid_address(self):
        """Test whether invalid addresses fail to decode"""

        INVALID_ADDRESS = [
            # Invalid human-readable part
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
            # invalid checksum
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
            # Invalid witness version
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
            # Invalid program length
            "bc1rw5uspcuh",
            # Invalid program length
            (
                "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qe"
                "jxtdg4y5r3zarvary0c5xw7kw5rljs90"
            ),
            # Invalid program length for witness version 0 (per BIP141)
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
            # Mixed case
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
            # zero padding of more than 4 bits
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
            # Non-zero padding in 8-to-5 conversion
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
            # Empty data section
            "bc1gmk9yu",
            # 92 chars
            (
                "bc1qqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqv"
                "psxqcrqvpsxqcrqvpsxqcrqvpsxqcrqvpsxqcrqv0jstn5"
            ),
        ]

        for a in INVALID_ADDRESS:
            self.assertRaises(ValueError, witness_from_b32address, a)

    def test_invalid_address_enc(self):
        """Test whether address encoding fails on invalid input"""

        INVALID_ADDRESS_ENC = [
            ("MAINNET", 0, 20),
            ("mainnet", 0, 21),
            ("mainnet", 17, 32),
            ("mainnet", 1, 1),
            ("mainnet", 16, 41),
        ]

        network, version, length = INVALID_ADDRESS_ENC[0]
        self.assertRaises(
            KeyError, b32address_from_witness, version, [0] * length, network
        )

        for network, version, length in INVALID_ADDRESS_ENC[1:]:
            self.assertRaises(
                ValueError, b32address_from_witness, version, [0] * length, network
            )

    def test_b32address_from_witness(self):

        # self-consistency
        addr = b"bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
        wv, wp, network, _ = witness_from_b32address(addr)
        self.assertEqual(b32address_from_witness(wv, wp, network), addr)

        # invalid value -1
        wp = [i for i in wp]  # convert to List[int]
        wp[-1] = -1  # alter the last element with an invalid value
        self.assertRaises(ValueError, b32address_from_witness, wv, wp, network)
        # b32address_from_witness(wv, wp, network)

        # string input
        addr = "bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
        wv, wp, network, _ = witness_from_b32address(addr)
        self.assertEqual(b32address_from_witness(wv, wp, network), addr.encode())

    def test_p2wpkh_p2sh(self):
        # https://matthewdowney.github.io/create-segwit-address.html
        pub = " 03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76" "276fa69a4eae77f"

        address = p2wpkh_p2sh(pub)
        self.assertEqual(address, b"36NvZTcMsMowbt78wPzJaHHWaNiyR73Y4g")

        address = p2wpkh_p2sh(pub, "testnet")
        self.assertEqual(address, b"2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2")

        # http://bitcoinscri.pt/pages/segwit_p2sh_p2wpkh
        pub = "02 f118cc409775419a931c57664d0c19c405e856ac0ee2f0e2a41" "37d8250531128"

        address = p2wpkh_p2sh(pub)
        self.assertEqual(address, b"3Mwz6cg8Fz81B7ukexK8u8EVAW2yymgWNd")

    def test_p2wpkh(self):

        # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
        # leading/trailing spaces should be tolerated
        pub = " 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2" "815B16F81798"
        addr = b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        self.assertEqual(addr, p2wpkh(pub))
        addr = b"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
        self.assertEqual(addr, p2wpkh(pub, "testnet"))

        # http://bitcoinscri.pt/pages/segwit_native_p2wpkh
        pub = "02 530c548d402670b13ad8887ff99c294e67fc18097d236d57880c69" "261b42def7"
        addr = b"bc1qg9stkxrszkdqsuj92lm4c7akvk36zvhqw7p6ck"
        self.assertEqual(addr, p2wpkh(pub))

        _, wp, _, _ = witness_from_b32address(addr)
        self.assertEqual(bytes(wp), hash160(pub))

        # Wrong size (65-bytes) for compressed SEC key
        uncompr_pub = bytes_from_point(point_from_octets(pub), compressed=False)
        self.assertRaises(ValueError, p2wpkh, uncompr_pub)
        # p2wpkh(uncompr_pub)

        # Wrong pubkey size: 34 instead of 33
        self.assertRaises(ValueError, p2wpkh, pub + "00")
        # p2wpkh(pub + '00')

        # Witness program length (21) is not 20
        self.assertRaises(
            ValueError, b32address_from_witness, 0, hash160(pub) + b"\x00"
        )
        # b32address_from_witness(0, hash160(pub) + b'\x00')

    def test_hash_from_bech32(self):
        network = "testnet"
        wv = 0
        wp = 20 * b"\x05"
        addr = b32address_from_witness(wv, wp, network)
        _, wp2, n2, _ = witness_from_b32address(addr)
        self.assertEqual(n2, network)
        self.assertEqual(wp2, wp)

        # witness program length (21) is not 20 or 32
        addr = "tb1qq5zs2pg9q5zs2pg9q5zs2pg9q5zs2pg9q5mpvsef"
        self.assertRaises(ValueError, witness_from_b32address, addr)
        # witness_from_b32address(addr)

    def test_p2wsh_p2sh(self):

        # leading/trailing spaces should be tolerated
        pub = " 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2D" "CE28D959F2815B16F81798"
        witness_script = [pub, "OP_CHECKSIG"]
        witness_script_bytes = encode(witness_script)
        p2wsh_p2sh(witness_script_bytes)
        p2wsh_p2sh(witness_script_bytes, "testnet")


def test_p2wsh():

    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    pub = "02 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D" "959F2815B16F81798"
    witness_script = [pub, "OP_CHECKSIG"]
    witness_script_bytes = encode(witness_script)

    addr = b"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert addr == p2wsh(witness_script_bytes, "testnet")
    _, wp, _, _ = witness_from_b32address(addr)
    assert bytes(wp) == sha256(witness_script_bytes)

    addr = b"bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"
    assert addr == p2wsh(witness_script_bytes)
    _, wp, _, _ = witness_from_b32address(addr)
    assert bytes(wp) == sha256(witness_script_bytes)

    assert witness_from_b32address(addr)[1] == sha256(witness_script_bytes)

    errMsg = r"witness program length \(35\) is not 20 or 32"
    with pytest.raises(ValueError, match=errMsg):
        b32address_from_witness(0, witness_script_bytes)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
