#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import bip32, slip32
from btclib.base58 import b58decode, b58encode
from btclib.curves import secp256k1 as ec
from btclib.utils import bytes_from_hexstring, octets_from_int
from btclib.base58wif import (prvkey_from_wif, to_prv_int, wif_from_prvkey,
                        wif_from_xprv)
from btclib.base58address import p2pkh_from_wif


class TestWif(unittest.TestCase):

    def test_wif(self):
        q = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'
        # compressed WIF
        wif = b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'
        self.assertEqual(wif, wif_from_prvkey(q, True))
        prvkey, compressed, _ = prvkey_from_wif(wif)
        self.assertEqual(prvkey, int(q, 16))
        self.assertEqual(compressed, True)

        q = bytes_from_hexstring(q, 32)
        # compressed WIF (testnet)
        wif = b'cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx'
        self.assertEqual(wif, wif_from_prvkey(q, True, 'testnet'))
        prvkey, compressed, _ = prvkey_from_wif(wif)
        self.assertEqual(prvkey, int.from_bytes(q, byteorder='big'))
        self.assertEqual(compressed, True)

        q = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        # uncompressed WIF
        wif = b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        self.assertEqual(wif, wif_from_prvkey(q, False))
        prvkey, compressed, _ = prvkey_from_wif(wif)
        self.assertEqual(prvkey, q)
        self.assertEqual(compressed, False)

        # uncompressed WIF (testnet)
        wif = b'91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2'
        self.assertEqual(wif, wif_from_prvkey(q, False, 'testnet'))
        prvkey, compressed, _ = prvkey_from_wif(wif)
        self.assertEqual(prvkey, q)
        self.assertEqual(compressed, False)

        # WIF as string with leading spaces
        wif = '  KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'
        prvkey, compressed, _ = prvkey_from_wif(wif)
        self.assertEqual(prvkey, q)
        self.assertEqual(compressed, True)

        # WIF as string with trailing spaces
        wif = 'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617  '
        prvkey, compressed, _ = prvkey_from_wif(wif)
        self.assertEqual(prvkey, q)
        self.assertEqual(compressed, True)

    def test_wif_exceptions(self):

        # not a 32-bytes private key
        badq = 33 * b'\x02'
        self.assertRaises(ValueError, wif_from_prvkey, badq, True)
        #wif_from_prvkey(badq, True)

        # private key not in (0, n)
        badq = ec.n
        self.assertRaises(ValueError, wif_from_prvkey, badq, True)
        #wif_from_prvkey(badq, True)

        # Not a private key WIF: missing leading 0x80
        payload = b'\x81' + octets_from_int(badq, ec.psize)
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

        # Not a compressed WIF: missing trailing 0x01
        payload = b'\x80' + octets_from_int(badq, ec.psize) + b'\x00'
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

        # Not a WIF: wrong size (35)
        payload = b'\x80' + octets_from_int(badq, ec.psize) + b'\x01\x00'
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

        # Not a WIF: private key not in (0, n)
        payload = b'\x80' + octets_from_int(badq, ec.psize)
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

    def test_wif_address_from_xkey(self):
        seed = b"00"*32  # better be random
        rxprv = bip32.rootxprv_from_seed(seed)
        path = "m/0h/0h/12"
        xprv = bip32.derive(rxprv, path)
        wif = wif_from_xprv(xprv)
        self.assertEqual(wif, b'KyLk7s6Z1FtgYEVp3bPckPVnXvLUWNCcVL6wNt3gaT96EmzTKZwP')
        address = p2pkh_from_wif(wif)
        xpub = bip32.xpub_from_xprv(xprv)
        address2 = slip32.address_from_xpub(xpub)
        self.assertEqual(address, address2)

        self.assertRaises(ValueError, wif_from_xprv, xpub)

    def test_to_prv_int(self):

        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode()
        xprv_dict = bip32.deserialize(xprv)
        wif = wif_from_xprv(xprv)
        wif_str = wif.decode()
        q = xprv_dict['prvkey']
        qb = xprv_dict['key'][1:]
        q_hexstr = qb.hex()

        # BIP32
        self.assertEqual(to_prv_int(xprv), (q, True, 'mainnet'))
        self.assertEqual(to_prv_int(xprv_str), (q, True, 'mainnet'))
        self.assertEqual(to_prv_int(' ' + xprv_str + ' '), (q, True, 'mainnet'))
        self.assertEqual(to_prv_int(xprv_dict), (q, True, 'mainnet'))

        # WIF keys (bytes or string)
        self.assertEqual(to_prv_int(wif), (q, True, 'mainnet'))
        self.assertEqual(to_prv_int(wif_str), (q, True, 'mainnet'))
        self.assertEqual(to_prv_int(' ' + wif_str + ' '), (q, True, 'mainnet'))

        # Octets (bytes or hex-string)
        self.assertEqual(to_prv_int(qb), (q, None, None))
        self.assertRaises(ValueError, to_prv_int, b'\x00' + qb)
        self.assertEqual(to_prv_int(q_hexstr), (q, None, None))
        self.assertEqual(to_prv_int(' ' + q_hexstr + ' '), (q, None, None))
        self.assertRaises(ValueError, to_prv_int, q_hexstr + '00')

        # native int
        self.assertEqual(to_prv_int(q), (q, None, None))


        q = ec.n
        self.assertRaises(ValueError, to_prv_int, q)
        qb = q.to_bytes(32, byteorder='big')
        self.assertRaises(ValueError, to_prv_int, qb)
        q_hexstr = qb.hex()
        self.assertRaises(ValueError, to_prv_int, q_hexstr)

        self.assertRaises(ValueError, to_prv_int, "not a key")
        #to_prv_int("not a key")

        # prvkey input
        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        self.assertRaises(ValueError, to_prv_int, xpub)
        xpub_dict = bip32.deserialize(xpub)
        self.assertRaises(ValueError, to_prv_int, xpub_dict)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
