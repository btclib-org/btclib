#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import base58


class TestBase58CheckEncoding(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(base58._encode(b''), b'')
        self.assertEqual(base58._decode(''), b'')
        self.assertEqual(base58._decode(base58._encode(b'')), b'')
        self.assertEqual(base58._encode(base58._decode('')), b'')

    def test_hello_world(self):
        self.assertEqual(base58._encode(b'hello world'), b'StV1DL6CwTryKyV')
        self.assertEqual(base58._decode('StV1DL6CwTryKyV'), b'hello world')
        self.assertEqual(base58._decode(
            base58._encode(b'hello world')), b'hello world')
        self.assertEqual(
            base58._encode(base58._decode('StV1DL6CwTryKyV')), b'StV1DL6CwTryKyV')

    def test_trailing_zeros(self):
        self.assertEqual(base58._encode(b'\x00\x00hello world'), b'11StV1DL6CwTryKyV')
        self.assertEqual(base58._decode('11StV1DL6CwTryKyV'), b'\x00\x00hello world')
        self.assertEqual(base58._decode(base58._encode(b'\0\0hello world')), b'\x00\x00hello world')
        self.assertEqual(base58._encode(base58._decode('11StV1DL6CwTryKyV')), b'11StV1DL6CwTryKyV')

    def test_integers(self):
        digits = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        for i in range(len(digits)):
            char = digits[i:i+1]
            self.assertEqual(base58._decode_to_int(char), i)
            self.assertEqual(base58._encode_from_int(i), char)
        number = 0x111d38e5fc9071ffcd20b4a763cc9ae4f252bb4e48fd66a835e252ada93ff480d6dd43dc62a641155a5
        self.assertEqual(base58._decode_to_int(digits), number)
        self.assertEqual(base58._encode_from_int(number), digits[1:])

    def test_exceptions(self):
        # int is not hex-string or bytes
        self.assertRaises(TypeError, base58.encode, 3)

        encoded = base58.encode(b"test")

        # unexpected decoded length
        wrong_length = len(encoded)-1
        self.assertRaises(ValueError, base58.decode,
                          encoded, wrong_length)

        # checksum is invalid
        invalidChecksum = encoded[:-4] + b'1111'
        self.assertRaises(ValueError, base58.decode, invalidChecksum, 4)

        # non-ascii character
        self.assertRaises(ValueError, base58.decode, "hèllo world")
        # base58.decode("hèllo world")

    def test_wif(self):
        # https://en.bitcoin.it/wiki/Wallet_import_format
        prvkey = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D

        uncompressedKey = b'\x80' + prvkey.to_bytes(32, byteorder='big')
        uncompressedWIF = b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ'
        wif = base58.encode(uncompressedKey)
        self.assertEqual(wif, uncompressedWIF)
        key = base58.decode(uncompressedWIF)
        self.assertEqual(key, uncompressedKey)

        compressedKey = b'\x80' + \
            prvkey.to_bytes(32, byteorder='big') + b'\x01'
        compressedWIF = b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'
        wif = base58.encode(compressedKey)
        self.assertEqual(wif, compressedWIF)
        key = base58.decode(compressedWIF)
        self.assertEqual(key, compressedKey)

        # string
        compressedWIF = b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617'
        key = base58.decode(compressedWIF)
        self.assertEqual(key, compressedKey)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
