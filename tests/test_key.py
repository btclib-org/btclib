#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import bip32, key
from btclib.curves import secp256k1 as ec
from btclib.utils import octets_from_point


class TestPrvKey(unittest.TestCase):

    def test_to_pub_tuple(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode()
        xpub_dict = bip32.deserialize(xpub)
        Pbytes_compressed = xpub_dict['key']
        Pbytes_compressed_hexstr = Pbytes_compressed.hex()
        P = xpub_dict['Q']
        Pbytes_uncompressed = octets_from_point(P, False, ec)
        Pbytes_uncompressed_hexstr = Pbytes_uncompressed.hex()

        # BIP32
        self.assertEqual(key.to_pub_tuple(xpub), P)
        self.assertEqual(key.to_pub_tuple(xpub_str), P)
        self.assertEqual(key.to_pub_tuple(' ' + xpub_str + ' '), P)
        self.assertEqual(key.to_pub_tuple(xpub_dict), P)

        # compressed Octets (bytes or hex-string)
        self.assertEqual(key.to_pub_tuple(Pbytes_compressed), P)
        self.assertRaises(ValueError, key.to_pub_tuple, b'\x00' + Pbytes_compressed)
        self.assertEqual(key.to_pub_tuple(Pbytes_compressed_hexstr), P)
        self.assertEqual(key.to_pub_tuple(' ' + Pbytes_compressed_hexstr + ' '), P)
        self.assertRaises(ValueError, key.to_pub_tuple, Pbytes_compressed_hexstr + '00')

        # uncompressed Octets (bytes or hex-string)
        self.assertEqual(key.to_pub_tuple(Pbytes_uncompressed), P)
        self.assertRaises(ValueError, key.to_pub_tuple, b'\x00' + Pbytes_uncompressed)
        self.assertEqual(key.to_pub_tuple(Pbytes_uncompressed_hexstr), P)
        self.assertEqual(key.to_pub_tuple(' ' + Pbytes_uncompressed_hexstr + ' '), P)
        self.assertRaises(ValueError, key.to_pub_tuple, Pbytes_uncompressed_hexstr + '00')

        # native tuple
        self.assertEqual(key.to_pub_tuple(P), P)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, key.to_pub_tuple, xprv)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, key.to_pub_tuple, xprv_dict)

    def test_to_pub_bytes(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode()
        xpub_dict = bip32.deserialize(xpub)
        Pbytes_compressed = xpub_dict['key']
        Pbytes_compressed_hexstr = Pbytes_compressed.hex()
        P = xpub_dict['Q']
        Pbytes_uncompressed = octets_from_point(P, False, ec)
        Pbytes_uncompressed_hexstr = Pbytes_uncompressed.hex()

        # BIP32 input, compressed result
        self.assertEqual(key.to_pub_bytes(xpub), Pbytes_compressed)
        self.assertEqual(key.to_pub_bytes(xpub_str), Pbytes_compressed)
        self.assertEqual(key.to_pub_bytes(' ' + xpub_str + ' '), Pbytes_compressed)
        self.assertEqual(key.to_pub_bytes(xpub_dict), Pbytes_compressed)

        # compressed Octets (bytes or hex-string) input, compressed result
        self.assertEqual(key.to_pub_bytes(Pbytes_compressed), Pbytes_compressed)
        self.assertRaises(ValueError, key.to_pub_bytes, b'\x00' + Pbytes_compressed)
        self.assertEqual(key.to_pub_bytes(Pbytes_compressed_hexstr), Pbytes_compressed)
        self.assertEqual(key.to_pub_bytes(' ' + Pbytes_compressed_hexstr + ' '), Pbytes_compressed)
        self.assertRaises(ValueError, key.to_pub_bytes, Pbytes_compressed_hexstr + '00')

        # uncompressed Octets (bytes or hex-string) input, compressed result
        self.assertEqual(key.to_pub_bytes(Pbytes_uncompressed), Pbytes_compressed)
        self.assertRaises(ValueError, key.to_pub_bytes, b'\x00' + Pbytes_uncompressed)
        self.assertEqual(key.to_pub_bytes(Pbytes_uncompressed_hexstr), Pbytes_compressed)
        self.assertEqual(key.to_pub_bytes(' ' + Pbytes_uncompressed_hexstr + ' '), Pbytes_compressed)
        self.assertRaises(ValueError, key.to_pub_bytes, Pbytes_uncompressed_hexstr + '00')

        # native tuple input, compressed result
        self.assertEqual(key.to_pub_bytes(P), Pbytes_compressed)

        # BIP32 input, uncompressed result
        self.assertEqual(key.to_pub_bytes(xpub, False), Pbytes_uncompressed)
        self.assertEqual(key.to_pub_bytes(xpub_str, False), Pbytes_uncompressed)
        self.assertEqual(key.to_pub_bytes(' ' + xpub_str + ' ', False), Pbytes_uncompressed)
        self.assertEqual(key.to_pub_bytes(xpub_dict, False), Pbytes_uncompressed)

        # compressed Octets (bytes or hex-string) input, uncompressed result
        self.assertEqual(key.to_pub_bytes(Pbytes_uncompressed, False), Pbytes_uncompressed)
        self.assertRaises(ValueError, key.to_pub_bytes, b'\x00' + Pbytes_uncompressed, False)
        self.assertEqual(key.to_pub_bytes(Pbytes_compressed_hexstr, False), Pbytes_uncompressed)
        self.assertEqual(key.to_pub_bytes(' ' + Pbytes_compressed_hexstr + ' ', False), Pbytes_uncompressed)
        self.assertRaises(ValueError, key.to_pub_bytes, Pbytes_compressed_hexstr + '00', False)

        # uncompressed Octets (bytes or hex-string) input, uncompressed result
        self.assertEqual(key.to_pub_bytes(Pbytes_uncompressed, False), Pbytes_uncompressed)
        self.assertRaises(ValueError, key.to_pub_bytes, b'\x00' + Pbytes_uncompressed, False)
        self.assertEqual(key.to_pub_bytes(Pbytes_uncompressed_hexstr, False), Pbytes_uncompressed)
        self.assertEqual(key.to_pub_bytes(' ' + Pbytes_uncompressed_hexstr + ' ', False), Pbytes_uncompressed)
        self.assertRaises(ValueError, key.to_pub_bytes, Pbytes_uncompressed_hexstr + '00', False)

        # native tuple input, uncompressed result
        self.assertEqual(key.to_pub_bytes(P, False), Pbytes_uncompressed)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, key.to_pub_bytes, xprv)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, key.to_pub_bytes, xprv_dict)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
