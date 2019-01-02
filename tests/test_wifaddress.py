#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.ec import secp256k1 as ec, pointMult
from btclib.ecutils import int2octets, octets2point
from btclib.wifaddress import b58encode_check, wif_from_prvkey, \
    prvkey_from_wif, address_from_pubkey, hash160_from_address, \
    address_from_wif


class TestKeys(unittest.TestCase):

    def test_wif_from_prvkey(self):
        p_num = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

        # private key as number
        wif = wif_from_prvkey(p_num, True)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p2 = prvkey_from_wif(wif)
        self.assertEqual(p2[0], p_num)
        self.assertEqual(p2[1], True)
        wif = wif_from_prvkey(p_num, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p3 = prvkey_from_wif(wif)
        self.assertEqual(p3[0], p_num)
        self.assertEqual(p3[1], False)


        p_bytes = int2octets(p_num, ec.bytesize)
        payload = b'\x80' + p_bytes + b'\x01\x01'
        wif = b58encode_check(payload)
        self.assertRaises(ValueError, prvkey_from_wif, wif)

    def test_address_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        prv = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
        pub = pointMult(ec, prv, ec.G)
        self.assertEqual(pub, octets2point(ec, '0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352'))

        addr = address_from_pubkey(pub, True)
        self.assertEqual(addr, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        hash160_from_address(addr)

        addr = address_from_pubkey(pub, False)
        self.assertEqual(addr, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        hash160_from_address(addr)

    def test_address_from_wif(self):
        wif1 = b"5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
        a = address_from_wif(wif1)
        self.assertEqual(a, b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig')

        wif2 = b"Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162"
        a = address_from_wif(wif2)
        self.assertEqual(a, b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB')

        self.assertEqual(prvkey_from_wif(wif1)[0], prvkey_from_wif(wif2)[0])


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
