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
from btclib.base58wif import wif_from_prvkey, wif_from_xprv
from btclib.curves import secp256k1 as ec
from btclib.to_prvkey import prvkey_info_from_wif, prvkey_info_from_xprvwif


class TestWif(unittest.TestCase):

    # TODO: add test_wif_from_xprv

    def test_wif_from_prvkey(self):
        prvkey = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'
        test_vectors = [
            ['KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', True, 'mainnet'],
            ['cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx', True, 'testnet'],
            ['5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ', False, 'mainnet'],
            ['91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2', False, 'testnet'],
            [' KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', True, 'mainnet'],
            ['KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 ', True, 'mainnet']
        ]
        for v in test_vectors:
            wif = wif_from_prvkey(prvkey, v[1], v[2])
            self.assertEqual(v[0].strip(), wif.decode('ascii'))
            q, compressed, network = prvkey_info_from_wif(v[0])
            self.assertEqual(q, int(prvkey, 16))
            self.assertEqual(compressed, v[1])
            self.assertEqual(network, v[2])


        # not a 32-bytes private key
        badq = 33 * b'\x02'
        self.assertRaises(ValueError, wif_from_prvkey, badq, True)
        #wif_from_prvkey(badq, True)

        # private key not in (0, n)
        badq = ec.n
        self.assertRaises(ValueError, wif_from_prvkey, badq, True)
        #wif_from_prvkey(badq, True)

        # Not a private key WIF: missing leading 0x80
        payload = b'\x81' + badq.to_bytes(ec.psize, 'big')
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_wif, badwif)
        #prvkey_info_from_wif(badwif)

        # Not a compressed WIF: missing trailing 0x01
        payload = b'\x80' + badq.to_bytes(ec.psize, 'big') + b'\x00'
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_wif, badwif)
        #prvkey_info_from_wif(badwif)

        # Not a WIF: wrong size (35)
        payload = b'\x80' + badq.to_bytes(ec.psize, 'big') + b'\x01\x00'
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_wif, badwif)
        #prvkey_info_from_wif(badwif)

        # Not a WIF: private key not in (0, n)
        payload = b'\x80' + badq.to_bytes(ec.psize, 'big')
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_wif, badwif)
        #prvkey_info_from_wif(badwif)

    def test_info_from_xprvwif(self):

        xprv = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xprv_str = xprv.decode('ascii')
        xprv_dict = bip32.deserialize(xprv)
        wif = wif_from_xprv(xprv)
        wif_str = wif.decode('ascii')
        ref_tuple = (xprv_dict['q'], True, 'mainnet')

        # BIP32
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(xprv))
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(xprv_str))
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(' ' + xprv_str + ' '))
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(xprv_dict))

        # Invalid decoded size: 6 bytes instead of 82
        xpub = 'notakey'
        self.assertRaises(ValueError, prvkey_info_from_xprvwif, xpub)
        #prvkey_info_from_xprvwif(xpub)

        # xkey is not a private one
        xpub = b'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
        self.assertRaises(ValueError, prvkey_info_from_xprvwif, xpub)
        #prvkey_info_from_xprvwif(xpub)

        # xkey is not a private one
        xpub_dict = bip32.deserialize(xpub)
        self.assertRaises(ValueError, prvkey_info_from_xprvwif, xpub_dict)
        #prvkey_info_from_xprvwif(xpub_dict)

        # WIF keys (bytes or string)
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(wif))
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(wif_str))
        self.assertEqual(ref_tuple, prvkey_info_from_xprvwif(' ' + wif_str + ' '))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
