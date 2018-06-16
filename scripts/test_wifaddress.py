#!/usr/bin/env python3

import unittest
from wifaddress import ec, \
                       wif_from_prvkey, prvkey_from_wif, \
                       address_from_pubkey, hash160_from_address, \
                       pubkey_from_prvkey

class TestKeys(unittest.TestCase):

    def test_wif_from_prvkey(self):
        p_num = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        p_bytes = bytes_from_prvkey(p_num)
        p_hex = p_bytes.hex()

        # private key as number
        wif = wif_from_prvkey(p_num)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p2 = prvkey_from_wif(wif)
        self.assertEqual(p2[0], p_bytes)
        self.assertEqual(p2[1], True)
        wif = wif_from_prvkey(p_num, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p3 = prvkey_from_wif(wif)
        self.assertEqual(p3[0], p_bytes)
        self.assertEqual(p3[1], False)

        # private key as bytes, i.e. the preferred format
        wif = wif_from_prvkey(p_bytes)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p4 = prvkey_from_wif(wif)
        self.assertEqual(p4[0], p_bytes)
        self.assertEqual(p4[1], True)
        wif = wif_from_prvkey(p_bytes, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p5 = prvkey_from_wif(wif)
        self.assertEqual(p5[0], p_bytes)
        self.assertEqual(p5[1], False)

        # private key as hex string
        wif = wif_from_prvkey(p_hex)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p6 = prvkey_from_wif(wif)
        self.assertEqual(p6[0], p_bytes)
        self.assertEqual(p6[1], True)
        wif = wif_from_prvkey(p_hex, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p7 = prvkey_from_wif(wif)
        self.assertEqual(p7[0], p_bytes)
        self.assertEqual(p7[1], False)

    def test_address_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
        p = p % ec.order
        a = address_from_pubkey(pubkey_from_prvkey(p, False))
        self.assertEqual(a, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        hash160_from_address(a)
        a = address_from_pubkey(pubkey_from_prvkey(p, True))
        self.assertEqual(a, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        hash160_from_address(a)
  
    def test_address_from_wif(self):
        wif1 = "5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
        a = address_from_pubkey(pubkey_from_prvkey(*prvkey_from_wif(wif1)))
        self.assertEqual(a, b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig')

        wif2 = "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162"
        a = address_from_pubkey(pubkey_from_prvkey(*prvkey_from_wif(wif2)))
        self.assertEqual(a, b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB')

        self.assertEqual(prvkey_from_wif(wif1)[0], prvkey_from_wif(wif2)[0])
  
if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
