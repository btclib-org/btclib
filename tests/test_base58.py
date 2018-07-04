#!/usr/bin/env python3

import unittest
from btclib.base58 import b58encode, b58encode_check, \
                          b58decode, b58decode_check, \
                          b58encode_int, b58decode_int

class TestBase58CheckEncoding(unittest.TestCase):
    def test_b58_empty(self):
        self.assertEqual(b58encode(b''), b'')
        self.assertEqual(b58decode(b''), b'')
        self.assertEqual(b58decode(b58encode(b'')), b'')
        self.assertEqual(b58encode(b58decode(b'')), b'')

        self.assertEqual(b58encode(''), b'')
        self.assertEqual(b58decode(''), b'')
        self.assertEqual(b58decode(b58encode('')), b'')
        self.assertEqual(b58encode(b58decode('')), b'')

    def test_b58_hello_world(self):
        self.assertEqual(b58encode(b'hello world'), b'StV1DL6CwTryKyV')
        self.assertEqual(b58decode(b'StV1DL6CwTryKyV'), b'hello world')
        self.assertEqual(b58decode(b58encode(b'hello world')), b'hello world')
        self.assertEqual(b58encode(b58decode(b'StV1DL6CwTryKyV')), b'StV1DL6CwTryKyV')

        self.assertEqual(b58encode("hello world"), b'StV1DL6CwTryKyV')
        self.assertEqual(b58decode("StV1DL6CwTryKyV"), b'hello world')
        self.assertEqual(b58decode(b58encode("hello world")), b'hello world')
        self.assertEqual(b58encode(b58decode("StV1DL6CwTryKyV")), b'StV1DL6CwTryKyV')

    def test_b58_trailing_zeros(self):
        self.assertEqual(b58encode(b'\x00\x00hello world'), b'11StV1DL6CwTryKyV')
        self.assertEqual(b58decode(b'11StV1DL6CwTryKyV'), b'\x00\x00hello world')
        self.assertEqual(b58decode(b58encode(b'\0\0hello world')), b'\x00\x00hello world')
        self.assertEqual(b58encode(b58decode(b'11StV1DL6CwTryKyV')), b'11StV1DL6CwTryKyV')

        self.assertEqual(b58encode("\x00\x00hello world"), b'11StV1DL6CwTryKyV')
        self.assertEqual(b58decode("11StV1DL6CwTryKyV"), b'\x00\x00hello world')
        self.assertEqual(b58decode(b58encode("\x00\x00hello world")), b'\x00\x00hello world')
        self.assertEqual(b58encode(b58decode("11StV1DL6CwTryKyV")), b'11StV1DL6CwTryKyV')

    def test_b58_integers(self):
        digits = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        for i in range(len(digits)):
            char = digits[i:i+1]
            self.assertEqual(b58decode_int(char), i)
            self.assertEqual(b58encode_int(i), char)
        number = 0x111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5  # noqa
        self.assertEqual(b58decode_int(digits), number)
        self.assertEqual(b58encode_int(number), digits[1:])            

    def test_b58_exceptions(self):
        # int is not str ot bytes
        self.assertRaises(TypeError, b58encode_check, 3)

        encoded = b58encode_check("test")

        # decoded length must be 4, not 3
        self.assertRaises(ValueError, b58decode_check, encoded, 3)

        # checksum is invalid
        invalidChecksum = encoded[:-4] + bytes(3) + encoded[-3:]
        self.assertRaises(ValueError, b58decode_check, invalidChecksum, 4)

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
