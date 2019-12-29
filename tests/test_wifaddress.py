#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.curve import mult
from btclib.curves import secp256k1 as ec
from btclib.utils import octets_from_int, point_from_octets
from btclib import base58
from btclib.wifaddress import wif_from_prvkey, \
    prvkey_from_wif, p2pkh_address, _h160_from_address, \
    address_from_wif


class TestKeys(unittest.TestCase):

    def test_wif_from_prvkey(self):
        q = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

        # compressed WIF
        wif = wif_from_prvkey(q, True)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        q2 = prvkey_from_wif(wif)
        self.assertEqual(q2[0], q)
        self.assertEqual(q2[1], True)

        # compressed WIF (testnet)
        wif = wif_from_prvkey(q, True, True)
        self.assertEqual(wif, b'cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx')
        q2 = prvkey_from_wif(wif)
        self.assertEqual(q2[0], q)
        self.assertEqual(q2[1], True)

        # uncompressed WIF
        wif = wif_from_prvkey(q, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        q3 = prvkey_from_wif(wif)
        self.assertEqual(q3[0], q)
        self.assertEqual(q3[1], False)

        # uncompressed WIF (testnet)
        wif = wif_from_prvkey(q, False, True)
        self.assertEqual(wif, b'91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2')
        q3 = prvkey_from_wif(wif)
        self.assertEqual(q3[0], q)
        self.assertEqual(q3[1], False)

        # private key not in (0, n)
        badq = ec.n
        self.assertRaises(ValueError, wif_from_prvkey, badq, True)
        #wif = wif_from_prvkey(badq, True)
        
        # Not a private key WIF: missing leading 0x80
        payload = b'\x81' + octets_from_int(badq, ec.psize)
        badwif = base58.encode_check(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

        # Not a compressed WIF: missing trailing 0x01
        payload = b'\x80' + octets_from_int(badq, ec.psize) + b'\x00'
        badwif = base58.encode_check(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        # prvkey_from_wif(badwif)

        # Not a WIF: wrong size (35)
        payload = b'\x80' + octets_from_int(badq, ec.psize) + b'\x01\x00'
        badwif = base58.encode_check(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

        # Not a WIF: private key not in (0, n)
        payload = b'\x80' + octets_from_int(badq, ec.psize)
        badwif = base58.encode_check(payload)
        self.assertRaises(ValueError, prvkey_from_wif, badwif)
        #prvkey_from_wif(badwif)

    def test_address_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        prv = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
        pub = mult(ec, prv)
        self.assertEqual(pub, point_from_octets(ec, '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'))

        addr = p2pkh_address(pub, True)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        _h160_from_address(addr)

        addr = p2pkh_address(pub, False)
        self.assertEqual(addr, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        _h160_from_address(addr)

        # not a mainnet address
        addr = p2pkh_address(pub, False, b'\x80')
        self.assertRaises(ValueError, _h160_from_address, addr)
        #_h160_from_address(addr)

    def test_address_from_wif(self):
        wif1 = b"5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
        a = address_from_wif(wif1)
        self.assertEqual(a, b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig')

        wif2 = b"Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162"
        a = address_from_wif(wif2)
        self.assertEqual(a, b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB')

        self.assertEqual(prvkey_from_wif(wif1)[0], prvkey_from_wif(wif2)[0])

        # testnet
        wif1 = b"91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2"
        a = address_from_wif(wif1)
        self.assertEqual(a, b'mvgbzkCSgKbYgaeG38auUzR7otscEGi8U7')

        wif2 = b"cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx"
        a = address_from_wif(wif2)
        self.assertEqual(a, b'n1KSZGmQgB8iSZqv6UVhGkCGUbEdw8Lm3Q')

        self.assertEqual(prvkey_from_wif(wif1)[0], prvkey_from_wif(wif2)[0])

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
