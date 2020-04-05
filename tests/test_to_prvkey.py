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
from btclib.base58 import b58decode, b58encode
from btclib.base58wif import wif_from_xprv
from btclib.curves import secp256k1 as ec
from btclib.to_prvkey import to_prvkey_int


class TestToPrvKey(unittest.TestCase):

    def test_to_prvkey_int(self):

        # BIP32
        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode('ascii')
        xprv_dict = bip32.deserialize(xprv)
        # WIF
        wif = wif_from_xprv(xprv)
        wif_str = wif.decode('ascii')
        # bytes
        qbytes = xprv_dict['key'][1:]
        qhex = qbytes.hex()
        # int
        q = xprv_dict['q']
        self.assertEqual(q, to_prvkey_int(q))
        # bytes
        self.assertEqual(q, to_prvkey_int(qbytes))
        self.assertRaises(ValueError, to_prvkey_int, b'\x00' + qbytes)
        self.assertEqual(q, to_prvkey_int(qhex))
        self.assertEqual(q, to_prvkey_int(' ' + qhex + ' '))
        self.assertRaises(ValueError, to_prvkey_int, qhex + '00')
        # WIF
        self.assertEqual(q, to_prvkey_int(wif))
        self.assertRaises(ValueError, to_prvkey_int, wif + b'\x00')
        self.assertEqual(q, to_prvkey_int(wif_str))
        self.assertEqual(q, to_prvkey_int(' ' + wif_str + ' '))
        # BIP32
        self.assertEqual(q, to_prvkey_int(xprv))
        self.assertRaises(ValueError, to_prvkey_int, xprv + b'\x00')
        self.assertEqual(q, to_prvkey_int(xprv_str))
        self.assertEqual(q, to_prvkey_int(' ' + xprv_str + ' '))
        self.assertEqual(q, to_prvkey_int(xprv_dict))

        # wrong private key int
        q = ec.n
        self.assertRaises(ValueError, to_prvkey_int, q)
        # bytes
        qbytes = q.to_bytes(32, byteorder='big')
        qhex = qbytes.hex()
        self.assertRaises(ValueError, to_prvkey_int, qbytes)
        self.assertRaises(ValueError, to_prvkey_int, qhex)
        # WIF
        t = b'\x80' + qbytes + b'\x01'
        wif = b58encode(t)
        wif_str = wif.decode('ascii')
        self.assertRaises(ValueError, to_prvkey_int, wif)
        self.assertRaises(ValueError, to_prvkey_int, wif_str)
        # BIP32
        t = xprv_dict['version']
        t += xprv_dict['depth'].to_bytes(1, 'big')
        t += xprv_dict['parent_fingerprint']
        t += xprv_dict['index']
        t += xprv_dict['chain_code']
        t += b'\x00' + qbytes
        xprv = b58encode(t)
        xprv_str = xprv.decode('ascii')
        self.assertRaises(ValueError, to_prvkey_int, xprv)
        self.assertRaises(ValueError, to_prvkey_int, xprv_str)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
