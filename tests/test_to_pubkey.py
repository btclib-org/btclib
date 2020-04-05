#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import bip32
from btclib.alias import INF
from btclib.base58 import b58encode
from btclib.curves import secp256k1 as ec
from btclib.to_pubkey import to_pub_bytes, to_pub_tuple
from btclib.utils import bytes_from_point


class TestToPubKey(unittest.TestCase):

    def test_to_pub_tuple(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode('ascii')
        xpub_dict = bip32.deserialize(xpub)
        Pbytes_compressed = xpub_dict['key']
        Pbytes_compressed_hexstr = Pbytes_compressed.hex()
        P = xpub_dict['Q']
        Pbytes_uncompressed = bytes_from_point(P, False, ec)
        Pbytes_uncompressed_hexstr = Pbytes_uncompressed.hex()

        # BIP32
        self.assertEqual(to_pub_tuple(xpub, ec), P)
        self.assertEqual(to_pub_tuple(xpub_str, ec), P)
        self.assertEqual(to_pub_tuple(' ' + xpub_str + ' ', ec), P)
        self.assertEqual(to_pub_tuple(xpub_dict, ec), P)

        # compressed Octets (bytes or hex-string)
        self.assertEqual(to_pub_tuple(Pbytes_compressed, ec), P)
        self.assertRaises(ValueError, to_pub_tuple, b'\x00' + Pbytes_compressed, ec)
        self.assertEqual(to_pub_tuple(Pbytes_compressed_hexstr, ec), P)
        self.assertEqual(to_pub_tuple(' ' + Pbytes_compressed_hexstr + ' ', ec), P)
        self.assertRaises(ValueError, to_pub_tuple, Pbytes_compressed_hexstr + '00', ec)

        # uncompressed Octets (bytes or hex-string)
        self.assertEqual(to_pub_tuple(Pbytes_uncompressed, ec), P)
        self.assertRaises(ValueError, to_pub_tuple, b'\x00' + Pbytes_uncompressed, ec)
        self.assertEqual(to_pub_tuple(Pbytes_uncompressed_hexstr, ec), P)
        self.assertEqual(to_pub_tuple(' ' + Pbytes_uncompressed_hexstr + ' ', ec), P)
        self.assertRaises(ValueError, to_pub_tuple, Pbytes_uncompressed_hexstr + '00', ec)

        # native tuple
        self.assertEqual(to_pub_tuple(P, ec), P)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, to_pub_tuple, xprv, ec)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, to_pub_tuple, xprv_dict, ec)

        # Invalid point: 7 is not a field element
        P = INF
        self.assertRaises(ValueError, to_pub_tuple, P, ec)
        Pbytes_compressed = b'\x02' + P[0].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pub_tuple, Pbytes_compressed, ec)
        Pbytes_uncompressed = b'\x04' + P[0].to_bytes(ec.psize, 'big') + P[1].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pub_tuple, Pbytes_uncompressed, ec)
        Pbytes_compressed_hexstr = Pbytes_compressed.hex()
        self.assertRaises(ValueError, to_pub_tuple, Pbytes_compressed_hexstr, ec)
        Pbytes_uncompressed_hexstr = Pbytes_uncompressed.hex()
        self.assertRaises(ValueError, to_pub_tuple, Pbytes_uncompressed_hexstr, ec)
        t = xpub_dict['version']
        t += xpub_dict['depth'].to_bytes(1, 'big')
        t += xpub_dict['parent_fingerprint']
        t += xpub_dict['index']
        t += xpub_dict['chain_code']
        t += Pbytes_compressed
        xpub = b58encode(t)
        self.assertRaises(ValueError, to_pub_tuple, xpub, ec)
        xpub_str = xpub.decode('ascii')
        self.assertRaises(ValueError, to_pub_tuple, xpub_str, ec)

    def test_to_pub_bytes(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode('ascii')
        xpub_dict = bip32.deserialize(xpub)
        Pbytes_compressed = xpub_dict['key']
        Pbytes_compressed_hexstr = Pbytes_compressed.hex()
        P = xpub_dict['Q']
        Pbytes_uncompressed = bytes_from_point(P, False, ec)
        Pbytes_uncompressed_hexstr = Pbytes_uncompressed.hex()

        # BIP32 input, compressed result
        self.assertEqual(to_pub_bytes(xpub, True, ec), Pbytes_compressed)
        self.assertEqual(to_pub_bytes(xpub_str, True, ec), Pbytes_compressed)
        self.assertEqual(to_pub_bytes(' ' + xpub_str + ' ', True, ec), Pbytes_compressed)
        self.assertEqual(to_pub_bytes(xpub_dict, True, ec), Pbytes_compressed)

        # compressed Octets (bytes or hex-string) input, compressed result
        self.assertEqual(to_pub_bytes(Pbytes_compressed, True, ec), Pbytes_compressed)
        self.assertRaises(ValueError, to_pub_bytes, b'\x00' + Pbytes_compressed, True, ec)
        self.assertEqual(to_pub_bytes(Pbytes_compressed_hexstr, True, ec), Pbytes_compressed)
        self.assertEqual(to_pub_bytes(' ' + Pbytes_compressed_hexstr + ' ', True, ec), Pbytes_compressed)
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_compressed_hexstr + '00', True, ec)

        # uncompressed Octets (bytes or hex-string) input, compressed result
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_uncompressed, True, ec)
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_uncompressed_hexstr, True, ec)
        self.assertRaises(ValueError, to_pub_bytes, ' ' + Pbytes_uncompressed_hexstr + ' ', True, ec)

        # native tuple input, compressed result
        self.assertEqual(to_pub_bytes(P, True, ec), Pbytes_compressed)

        # BIP32 input, uncompressed result
        self.assertRaises(ValueError, to_pub_bytes, xpub, False, ec)
        self.assertRaises(ValueError, to_pub_bytes, xpub_str, False, ec)
        self.assertRaises(ValueError, to_pub_bytes, ' ' + xpub_str + ' ', False, ec)
        self.assertRaises(ValueError, to_pub_bytes, xpub_dict, False, ec)

        # compressed Octets (bytes or hex-string) input, uncompressed result
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_compressed, False, ec)
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_compressed_hexstr, False, ec)
        self.assertRaises(ValueError, to_pub_bytes, ' ' + Pbytes_compressed_hexstr + ' ', False, ec)

        # uncompressed Octets (bytes or hex-string) input, uncompressed result
        self.assertEqual(to_pub_bytes(Pbytes_uncompressed, False, ec), Pbytes_uncompressed)
        self.assertRaises(ValueError, to_pub_bytes, b'\x00' + Pbytes_uncompressed, False, ec)
        self.assertEqual(to_pub_bytes(Pbytes_uncompressed_hexstr, False, ec), Pbytes_uncompressed)
        self.assertEqual(to_pub_bytes(' ' + Pbytes_uncompressed_hexstr + ' ', False, ec), Pbytes_uncompressed)
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_uncompressed_hexstr + '00', False, ec)

        # native tuple input, uncompressed result
        self.assertEqual(to_pub_bytes(P, False, ec), Pbytes_uncompressed)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, to_pub_bytes, xprv, True, ec)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, to_pub_bytes, xprv_dict, True, ec)

        # Invalid point: 7 is not a field element
        P = INF
        self.assertRaises(ValueError, to_pub_bytes, P, True, ec)
        Pbytes_compressed = b'\x02' + P[0].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_compressed, True, ec)
        Pbytes_uncompressed = b'\x04' + P[0].to_bytes(ec.psize, 'big') + P[1].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_uncompressed, True, ec)
        Pbytes_compressed_hexstr = Pbytes_compressed.hex()
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_compressed_hexstr, True, ec)
        Pbytes_uncompressed_hexstr = Pbytes_uncompressed.hex()
        self.assertRaises(ValueError, to_pub_bytes, Pbytes_uncompressed_hexstr, True, ec)
        t = xpub_dict['version']
        t += xpub_dict['depth'].to_bytes(1, 'big')
        t += xpub_dict['parent_fingerprint']
        t += xpub_dict['index']
        t += xpub_dict['chain_code']
        t += Pbytes_compressed
        xpub = b58encode(t)
        self.assertRaises(ValueError, to_pub_bytes, xpub, True, ec)
        xpub_str = xpub.decode('ascii')
        self.assertRaises(ValueError, to_pub_bytes, xpub_str, True, ec)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
