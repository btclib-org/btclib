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
from btclib.secpoint import bytes_from_point
from btclib.to_pubkey import to_pubkey_bytes, to_pubkey_tuple


class TestToPubKey(unittest.TestCase):

    def test_to_pub_tuple(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode('ascii')
        xpub_dict = bip32.deserialize(xpub)
        P_compr = xpub_dict['key']
        P_compr_hexstr = P_compr.hex()
        P = xpub_dict['Q']
        P_uncompr = bytes_from_point(P, False, ec)
        P_uncompr_hexstr = P_uncompr.hex()

        # BIP32
        self.assertEqual(to_pubkey_tuple(xpub, ec), P)
        self.assertEqual(to_pubkey_tuple(xpub_str, ec), P)
        self.assertEqual(to_pubkey_tuple(' ' + xpub_str + ' ', ec), P)
        self.assertEqual(to_pubkey_tuple(xpub_dict, ec), P)

        # compressed SEC Octets (bytes or hex-string, with 02 or 03 prefix)
        self.assertEqual(to_pubkey_tuple(P_compr, ec), P)
        self.assertRaises(ValueError, to_pubkey_tuple, b'\x00' + P_compr, ec)
        self.assertEqual(to_pubkey_tuple(P_compr_hexstr, ec), P)
        self.assertEqual(to_pubkey_tuple(' ' + P_compr_hexstr + ' ', ec), P)
        self.assertRaises(ValueError, to_pubkey_tuple, P_compr_hexstr + '00', ec)

        # uncompressed SEC Octets (bytes or hex-string, with 04 prefix)
        self.assertEqual(to_pubkey_tuple(P_uncompr, ec), P)
        self.assertRaises(ValueError, to_pubkey_tuple, b'\x00' + P_uncompr, ec)
        self.assertEqual(to_pubkey_tuple(P_uncompr_hexstr, ec), P)
        self.assertEqual(to_pubkey_tuple(' ' + P_uncompr_hexstr + ' ', ec), P)
        self.assertRaises(ValueError, to_pubkey_tuple, P_uncompr_hexstr + '00', ec)

        # native tuple
        self.assertEqual(to_pubkey_tuple(P, ec), P)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, to_pubkey_tuple, xprv, ec)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, to_pubkey_tuple, xprv_dict, ec)

        # Invalid point: 7 is not a field element
        P = INF
        self.assertRaises(ValueError, to_pubkey_tuple, P, ec)
        P_compr = b'\x02' + P[0].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pubkey_tuple, P_compr, ec)
        P_uncompr = b'\x04' + P[0].to_bytes(ec.psize, 'big') + P[1].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pubkey_tuple, P_uncompr, ec)
        P_compr_hexstr = P_compr.hex()
        self.assertRaises(ValueError, to_pubkey_tuple, P_compr_hexstr, ec)
        P_uncompr_hexstr = P_uncompr.hex()
        self.assertRaises(ValueError, to_pubkey_tuple, P_uncompr_hexstr, ec)
        t = xpub_dict['version']
        t += xpub_dict['depth'].to_bytes(1, 'big')
        t += xpub_dict['parent_fingerprint']
        t += xpub_dict['index']
        t += xpub_dict['chain_code']
        t += P_compr
        xpub = b58encode(t)
        self.assertRaises(ValueError, to_pubkey_tuple, xpub, ec)
        xpub_str = xpub.decode('ascii')
        self.assertRaises(ValueError, to_pubkey_tuple, xpub_str, ec)

    def test_to_pub_bytes(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode('ascii')
        xpub_dict = bip32.deserialize(xpub)
        P_compr = xpub_dict['key']
        P_compr_hexstr = P_compr.hex()
        P = xpub_dict['Q']
        P_uncompr = bytes_from_point(P, False, ec)
        P_uncompr_hexstr = P_uncompr.hex()

        # BIP32 input, compressed result
        self.assertEqual(to_pubkey_bytes(xpub, True, ec), P_compr)
        self.assertEqual(to_pubkey_bytes(xpub_str, True, ec), P_compr)
        self.assertEqual(to_pubkey_bytes(' ' + xpub_str + ' ', True, ec), P_compr)
        self.assertEqual(to_pubkey_bytes(xpub_dict, True, ec), P_compr)

        # compressed SEC Octets input, compressed result
        self.assertEqual(to_pubkey_bytes(P_compr, True, ec), P_compr)
        self.assertRaises(ValueError, to_pubkey_bytes, b'\x00' + P_compr, True, ec)
        self.assertEqual(to_pubkey_bytes(P_compr_hexstr, True, ec), P_compr)
        self.assertEqual(to_pubkey_bytes(' ' + P_compr_hexstr + ' ', True, ec), P_compr)
        self.assertRaises(ValueError, to_pubkey_bytes, P_compr_hexstr + '00', True, ec)

        # uncompressed SEC Octets input, compressed result
        self.assertRaises(ValueError, to_pubkey_bytes, P_uncompr, True, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, P_uncompr_hexstr, True, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, ' ' + P_uncompr_hexstr + ' ', True, ec)

        # native tuple input, compressed result
        self.assertEqual(to_pubkey_bytes(P, True, ec), P_compr)

        # BIP32 input, uncompressed result
        self.assertRaises(ValueError, to_pubkey_bytes, xpub, False, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, xpub_str, False, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, ' ' + xpub_str + ' ', False, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, xpub_dict, False, ec)

        # compressed SEC Octets input, uncompressed result
        self.assertRaises(ValueError, to_pubkey_bytes, P_compr, False, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, P_compr_hexstr, False, ec)
        self.assertRaises(ValueError, to_pubkey_bytes, ' ' + P_compr_hexstr + ' ', False, ec)

        # uncompressed SEC Octets input, uncompressed result
        self.assertEqual(to_pubkey_bytes(P_uncompr, False, ec), P_uncompr)
        self.assertRaises(ValueError, to_pubkey_bytes, b'\x00' + P_uncompr, False, ec)
        self.assertEqual(to_pubkey_bytes(P_uncompr_hexstr, False, ec), P_uncompr)
        self.assertEqual(to_pubkey_bytes(' ' + P_uncompr_hexstr + ' ', False, ec), P_uncompr)
        self.assertRaises(ValueError, to_pubkey_bytes, P_uncompr_hexstr + '00', False, ec)

        # native tuple input, uncompressed result
        self.assertEqual(to_pubkey_bytes(P, False, ec), P_uncompr)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, to_pubkey_bytes, xprv, True, ec)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, to_pubkey_bytes, xprv_dict, True, ec)

        # Invalid point: 7 is not a field element
        P = INF
        self.assertRaises(ValueError, to_pubkey_bytes, P, True, ec)
        P_compr = b'\x02' + P[0].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pubkey_bytes, P_compr, True, ec)
        P_uncompr = b'\x04' + P[0].to_bytes(ec.psize, 'big') + P[1].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, to_pubkey_bytes, P_uncompr, True, ec)
        P_compr_hexstr = P_compr.hex()
        self.assertRaises(ValueError, to_pubkey_bytes, P_compr_hexstr, True, ec)
        P_uncompr_hexstr = P_uncompr.hex()
        self.assertRaises(ValueError, to_pubkey_bytes, P_uncompr_hexstr, True, ec)
        t = xpub_dict['version']
        t += xpub_dict['depth'].to_bytes(1, 'big')
        t += xpub_dict['parent_fingerprint']
        t += xpub_dict['index']
        t += xpub_dict['chain_code']
        t += P_compr
        xpub = b58encode(t)
        self.assertRaises(ValueError, to_pubkey_bytes, xpub, True, ec)
        xpub_str = xpub.decode('ascii')
        self.assertRaises(ValueError, to_pubkey_bytes, xpub_str, True, ec)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
