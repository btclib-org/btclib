#!/usr/bin/env python3

import unittest
from btclib.base58 import b58encode, b58encode_check, b58decode, b58decode_check

class TestBase58CheckEncoding(unittest.TestCase):
    def test_b58_encode_decode(self):
        self.assertEqual(b58encode(b'hello world'), b'StV1DL6CwTryKyV')
        self.assertEqual(b58decode(b'StV1DL6CwTryKyV'), b'hello world')
        self.assertEqual(b58decode(b58encode(b'hello world')), b'hello world')
        self.assertEqual(b58encode(b58decode(b'StV1DL6CwTryKyV')), b'StV1DL6CwTryKyV')

        self.assertEqual(b58encode("hello world"), b'StV1DL6CwTryKyV')
        self.assertEqual(b58decode("StV1DL6CwTryKyV"), b'hello world')
        self.assertEqual(b58decode(b58encode("hello world")), b'hello world')
        self.assertEqual(b58encode(b58decode("StV1DL6CwTryKyV")), b'StV1DL6CwTryKyV')

        self.assertEqual(b58encode(b'\x00\x00hello world'), b'11StV1DL6CwTryKyV')
        self.assertEqual(b58decode(b'11StV1DL6CwTryKyV'), b'\x00\x00hello world')
        self.assertEqual(b58decode(b58encode(b'\0\0hello world')), b'\x00\x00hello world')
        self.assertEqual(b58encode(b58decode(b'11StV1DL6CwTryKyV')), b'11StV1DL6CwTryKyV')

        self.assertEqual(b58encode("\x00\x00hello world"), b'11StV1DL6CwTryKyV')
        self.assertEqual(b58decode("11StV1DL6CwTryKyV"), b'\x00\x00hello world')
        self.assertEqual(b58decode(b58encode("\x00\x00hello world")), b'\x00\x00hello world')
        self.assertEqual(b58encode(b58decode("11StV1DL6CwTryKyV")), b'11StV1DL6CwTryKyV')

    def test_wif(self):
        # https://en.bitcoin.it/wiki/Wallet_import_format
        prvkey = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

        uncompressedKey = b'\x80' + prvkey.to_bytes(32, byteorder='big')
        uncompressedWIF = b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        wif = b58encode_check(uncompressedKey)
        self.assertEqual(wif, uncompressedWIF)
        key = b58decode_check(uncompressedWIF)
        self.assertEqual(key, uncompressedKey)

        compressedKey = b'\x80' + prvkey.to_bytes(32, byteorder='big') + b'\x01'
        compressedWIF = b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'
        wif = b58encode_check(compressedKey)
        self.assertEqual(wif, compressedWIF)
        key = b58decode_check(compressedWIF)
        self.assertEqual(key, compressedKey)
    
if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
