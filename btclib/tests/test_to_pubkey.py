#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import copy
import unittest

from btclib import bip32
from btclib.alias import INF
from btclib.base58 import b58encode
from btclib.curves import secp256k1 as ec
from btclib.secpoint import bytes_from_point
from btclib.to_pubkey import (
    _bytes_from_xpub, bytes_from_pubkey, fingerprint, point_from_pubkey)


class TestToPubKey(unittest.TestCase):

    def test_point_from_pubkey(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode('ascii')
        xpub_dict = bip32.deserialize(xpub)
        P_compr = xpub_dict['key']
        P_compr_hexstr = P_compr.hex()
        P = xpub_dict['Q']
        P_uncompr = bytes_from_point(P, ec, False)
        P_uncompr_hexstr = P_uncompr.hex()

        # BIP32
        self.assertEqual(point_from_pubkey(xpub, ec), P)
        self.assertEqual(point_from_pubkey(xpub_str, ec), P)
        self.assertEqual(point_from_pubkey(' ' + xpub_str + ' ', ec), P)
        self.assertEqual(point_from_pubkey(xpub_dict, ec), P)

        # compressed SEC Octets (bytes or hex-string, with 02 or 03 prefix)
        self.assertEqual(point_from_pubkey(P_compr, ec), P)
        self.assertRaises(ValueError, point_from_pubkey, b'\x00' + P_compr, ec)
        self.assertEqual(point_from_pubkey(P_compr_hexstr, ec), P)
        self.assertEqual(point_from_pubkey(' ' + P_compr_hexstr + ' ', ec), P)
        self.assertRaises(ValueError, point_from_pubkey, P_compr_hexstr + '00', ec)

        # uncompressed SEC Octets (bytes or hex-string, with 04 prefix)
        self.assertEqual(point_from_pubkey(P_uncompr, ec), P)
        self.assertRaises(ValueError, point_from_pubkey, b'\x00' + P_uncompr, ec)
        self.assertEqual(point_from_pubkey(P_uncompr_hexstr, ec), P)
        self.assertEqual(point_from_pubkey(' ' + P_uncompr_hexstr + ' ', ec), P)
        self.assertRaises(ValueError, point_from_pubkey, P_uncompr_hexstr + '00', ec)

        # native tuple
        self.assertEqual(point_from_pubkey(P, ec), P)

        # pubkey input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, point_from_pubkey, xprv, ec)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, point_from_pubkey, xprv_dict, ec)

        # Invalid point: 7 is not a field element
        P = INF
        self.assertRaises(ValueError, point_from_pubkey, P, ec)
        P_compr = b'\x02' + P[0].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, point_from_pubkey, P_compr, ec)
        P_uncompr = b'\x04' + P[0].to_bytes(ec.psize, 'big') + P[1].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, point_from_pubkey, P_uncompr, ec)
        P_compr_hexstr = P_compr.hex()
        self.assertRaises(ValueError, point_from_pubkey, P_compr_hexstr, ec)
        P_uncompr_hexstr = P_uncompr.hex()
        self.assertRaises(ValueError, point_from_pubkey, P_uncompr_hexstr, ec)
        t = xpub_dict['version']
        t += xpub_dict['depth'].to_bytes(1, 'big')
        t += xpub_dict['parent_fingerprint']
        t += xpub_dict['index']
        t += xpub_dict['chain_code']
        t += P_compr
        xpub = b58encode(t)
        self.assertRaises(ValueError, point_from_pubkey, xpub, ec)
        xpub_str = xpub.decode('ascii')
        self.assertRaises(ValueError, point_from_pubkey, xpub_str, ec)

    def test_bytes_from_pubkey(self):

        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        xpub_str = xpub.decode('ascii')
        xpub_dict = bip32.deserialize(xpub)
        P_compr = xpub_dict['key']
        P_compr_hexstr = P_compr.hex()
        P = xpub_dict['Q']
        P_uncompr = bytes_from_point(P, ec, False)
        P_uncompr_hexstr = P_uncompr.hex()

        # BIP32 input, compressed result
        self.assertEqual(bytes_from_pubkey(xpub)[0], P_compr)
        self.assertEqual(bytes_from_pubkey(xpub_str)[0], P_compr)
        self.assertEqual(bytes_from_pubkey(' ' + xpub_str + ' ')[0], P_compr)
        self.assertEqual(bytes_from_pubkey(xpub_dict)[0], P_compr)

        # compressed SEC Octets input, compressed result
        self.assertEqual(bytes_from_pubkey(P_compr)[0], P_compr)
        self.assertRaises(ValueError, bytes_from_pubkey, b'\x00' + P_compr)
        self.assertEqual(bytes_from_pubkey(P_compr_hexstr)[0], P_compr)
        self.assertEqual(bytes_from_pubkey(' ' + P_compr_hexstr + ' ')[0], P_compr)
        self.assertRaises(ValueError, bytes_from_pubkey, P_compr_hexstr + '00')

        # uncompressed SEC Octets input, compressed result
        self.assertRaises(ValueError, bytes_from_pubkey, P_uncompr, True)
        self.assertRaises(ValueError, bytes_from_pubkey, P_uncompr_hexstr, True)
        self.assertRaises(ValueError, bytes_from_pubkey, ' ' + P_uncompr_hexstr + ' ', True)

        # native tuple input, compressed result
        self.assertEqual(bytes_from_pubkey(P)[0], P_compr)

        # BIP32 input, uncompressed result
        self.assertRaises(ValueError, bytes_from_pubkey, xpub, False)
        self.assertRaises(ValueError, bytes_from_pubkey, xpub_str, False)
        self.assertRaises(ValueError, bytes_from_pubkey, ' ' + xpub_str + ' ', False)
        self.assertRaises(ValueError, bytes_from_pubkey, xpub_dict, False)

        # compressed SEC Octets input, uncompressed result
        self.assertRaises(ValueError, bytes_from_pubkey, P_compr, False)
        self.assertRaises(ValueError, bytes_from_pubkey, P_compr_hexstr, False)
        self.assertRaises(ValueError, bytes_from_pubkey, ' ' + P_compr_hexstr + ' ', False)

        # uncompressed SEC Octets input, uncompressed result
        self.assertEqual(bytes_from_pubkey(P_uncompr)[0], P_uncompr)
        self.assertRaises(ValueError, bytes_from_pubkey, b'\x00' + P_uncompr)
        self.assertEqual(bytes_from_pubkey(P_uncompr_hexstr)[0], P_uncompr)
        self.assertEqual(bytes_from_pubkey(' ' + P_uncompr_hexstr + ' ')[0], P_uncompr)
        self.assertRaises(ValueError, bytes_from_pubkey, P_uncompr_hexstr + '00')

        # native tuple input, uncompressed result
        self.assertEqual(bytes_from_pubkey(P, compressed=False)[0], P_uncompr)

        # xprv input
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        self.assertRaises(ValueError, bytes_from_pubkey, xprv)
        xprv_dict = bip32.deserialize(xprv)
        self.assertRaises(ValueError, bytes_from_pubkey, xprv_dict)

        # Not a public key:
        xpub_dict_bad = copy.copy(xpub_dict)
        xpub_dict_bad['key'] = b'\x00' + xpub_dict['key'][1:]
        self.assertRaises(ValueError, _bytes_from_xpub, xpub_dict_bad)
        #_bytes_from_xpub(xpub_dict_bad)

        # Invalid point: 7 is not a field element
        P = INF
        self.assertRaises(ValueError, bytes_from_pubkey, P)
        P_compr = b'\x02' + P[0].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, bytes_from_pubkey, P_compr)
        P_uncompr = b'\x04' + P[0].to_bytes(ec.psize, 'big') + P[1].to_bytes(ec.psize, 'big')
        self.assertRaises(ValueError, bytes_from_pubkey, P_uncompr)
        P_compr_hexstr = P_compr.hex()
        self.assertRaises(ValueError, bytes_from_pubkey, P_compr_hexstr)
        P_uncompr_hexstr = P_uncompr.hex()
        self.assertRaises(ValueError, bytes_from_pubkey, P_uncompr_hexstr)
        t = xpub_dict['version']
        t += xpub_dict['depth'].to_bytes(1, 'big')
        t += xpub_dict['parent_fingerprint']
        t += xpub_dict['index']
        t += xpub_dict['chain_code']
        t += P_compr
        xpub = b58encode(t)
        self.assertRaises(ValueError, bytes_from_pubkey, xpub)
        xpub_str = xpub.decode('ascii')
        self.assertRaises(ValueError, bytes_from_pubkey, xpub_str)

    def test_fingerprint(self):
        xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        pf = fingerprint(xpub)
        # bytes are used to increase code coverage
        # dict is used to increase code coverage
        xpubd = bip32.deserialize(xpub)
        child_key = bip32.derive(xpubd, b'\x00'*4)
        pf2 = bip32.deserialize(child_key)['parent_fingerprint']
        self.assertEqual(pf, pf2)

    def test_exceptions(self):

        # Not a key for (testnet) network
        xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        xpubd = bip32.deserialize(xpub)
        self.assertRaises(ValueError, _bytes_from_xpub, xpubd, 'testnet', None)
        #_bytes_from_xpub(xpubd, 'testnet', None)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
