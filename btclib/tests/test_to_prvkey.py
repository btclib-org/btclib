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
from btclib.base58 import b58encode
from btclib.base58wif import wif_from_prvkey
from btclib.curves import secp256k1 as ec
from btclib.to_prvkey import int_from_prvkey, prvkeyinfo_from_prvkey


class TestToPrvKey(unittest.TestCase):

    def test_int_from_prvkey(self):

        # BIP32
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode('ascii')
        xprv_dict = bip32.deserialize(xprv)
        # WIF
        wif = wif_from_prvkey(xprv)
        wif_str = wif.decode('ascii')
        # bytes
        qbytes = xprv_dict['key'][1:]
        qhex = qbytes.hex()
        # int
        q = xprv_dict['q']
        self.assertEqual(q, int_from_prvkey(q))
        # bytes
        self.assertEqual(q, int_from_prvkey(qbytes))
        self.assertRaises(ValueError, int_from_prvkey, b'\x00' + qbytes)
        self.assertEqual(q, int_from_prvkey(qhex))
        self.assertEqual(q, int_from_prvkey(' ' + qhex + ' '))
        self.assertRaises(ValueError, int_from_prvkey, qhex + '00')
        # WIF
        self.assertEqual(q, int_from_prvkey(wif))
        self.assertRaises(ValueError, int_from_prvkey, wif + b'\x00')
        self.assertEqual(q, int_from_prvkey(wif_str))
        self.assertEqual(q, int_from_prvkey(' ' + wif_str + ' '))
        # BIP32
        self.assertEqual(q, int_from_prvkey(xprv))
        self.assertRaises(ValueError, int_from_prvkey, xprv + b'\x00')
        self.assertEqual(q, int_from_prvkey(xprv_str))
        self.assertEqual(q, int_from_prvkey(' ' + xprv_str + ' '))
        self.assertEqual(q, int_from_prvkey(xprv_dict))

        # wrong private key int
        q = ec.n
        self.assertRaises(ValueError, int_from_prvkey, q)
        # bytes
        qbytes = q.to_bytes(32, byteorder='big')
        qhex = qbytes.hex()
        self.assertRaises(ValueError, int_from_prvkey, qbytes)
        self.assertRaises(ValueError, int_from_prvkey, qhex)
        # WIF
        t = b'\x80' + qbytes + b'\x01'
        wif = b58encode(t)
        wif_str = wif.decode('ascii')
        self.assertRaises(ValueError, int_from_prvkey, wif)
        self.assertRaises(ValueError, int_from_prvkey, wif_str)
        # BIP32
        t = xprv_dict['version']
        t += xprv_dict['depth'].to_bytes(1, 'big')
        t += xprv_dict['parent_fingerprint']
        t += xprv_dict['index']
        t += xprv_dict['chain_code']
        t += b'\x00' + qbytes
        xprv = b58encode(t, 78)
        xprv_str = xprv.decode('ascii')
        self.assertRaises(ValueError, int_from_prvkey, xprv)
        self.assertRaises(ValueError, int_from_prvkey, xprv_str)

        # wrong private key int
        q = 0
        self.assertRaises(ValueError, int_from_prvkey, q)
        # bytes
        qbytes = q.to_bytes(32, byteorder='big')
        qhex = qbytes.hex()
        self.assertRaises(ValueError, int_from_prvkey, qbytes)
        self.assertRaises(ValueError, int_from_prvkey, qhex)
        # WIF
        t = b'\x80' + qbytes + b'\x01'
        wif = b58encode(t)
        wif_str = wif.decode('ascii')
        self.assertRaises(ValueError, int_from_prvkey, wif)
        self.assertRaises(ValueError, int_from_prvkey, wif_str)
        # BIP32
        t = xprv_dict['version']
        t += xprv_dict['depth'].to_bytes(1, 'big')
        t += xprv_dict['parent_fingerprint']
        t += xprv_dict['index']
        t += xprv_dict['chain_code']
        t += b'\x00' + qbytes
        xprv = b58encode(t, 78)
        xprv_str = xprv.decode('ascii')
        self.assertRaises(ValueError, int_from_prvkey, xprv)
        self.assertRaises(ValueError, int_from_prvkey, xprv_str)

        # pub key
        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        self.assertRaises(ValueError, int_from_prvkey, xpub)

    def test_info_from_prvkey(self):

        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode('ascii')
        xprv_dict = bip32.deserialize(xprv)
        wif = wif_from_prvkey(xprv)
        wif_str = wif.decode('ascii')
        ref_tuple = (xprv_dict['q'], 'mainnet', True)

        # BIP32
        self.assertEqual(ref_tuple, prvkeyinfo_from_prvkey(xprv, 'mainnet'))
        self.assertEqual(ref_tuple, prvkeyinfo_from_prvkey(xprv))
        self.assertEqual(ref_tuple, prvkeyinfo_from_prvkey(xprv_str))
        self.assertEqual(ref_tuple,
                         prvkeyinfo_from_prvkey(' ' + xprv_str + ' '))
        self.assertEqual(ref_tuple, prvkeyinfo_from_prvkey(xprv_dict))

        # Invalid decoded size: 6 bytes instead of 82
        xpub = 'notakey'
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey, xpub)
        # prvkeyinfo_from_prvkey(xpub)

        # xkey is not a private one
        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey, xpub)
        # prvkeyinfo_from_prvkey(xpub)

        # xkey is not a private one
        xpub_dict = bip32.deserialize(xpub)
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey, xpub_dict)
        # prvkeyinfo_from_prvkey(xpub_dict)

        # WIF keys (bytes or string)
        self.assertEqual(ref_tuple, prvkeyinfo_from_prvkey(wif))
        self.assertEqual(ref_tuple, prvkeyinfo_from_prvkey(wif_str))
        self.assertEqual(
            ref_tuple, prvkeyinfo_from_prvkey(' ' + wif_str + ' '))

    def test_exceptions(self):

        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprvd = bip32.deserialize(xprv)

        # Compressed key provided, uncompressed key requested
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey,
                          xprvd, 'mainnet', False)
        # prvkeyinfo_from_prvkey(xprvd, 'mainnet', False)

        # Mainnet key provided, testnet key requested
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey,
                          xprvd, 'testnet', True)
        # prvkeyinfo_from_prvkey(xprvd, 'testnet', True)

        # Compression requirement mismatch
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey,
                          xprv, 'mainnet', False)
        # prvkeyinfo_from_prvkey(xprv, 'mainnet', False)

        # Mainnet key provided, testnet key requested
        self.assertRaises(ValueError, prvkeyinfo_from_prvkey,
                          xprv, 'testnet', True)
        # prvkeyinfo_from_prvkey(xprv, 'testnet', True)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
