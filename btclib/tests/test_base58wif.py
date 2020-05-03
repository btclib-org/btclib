#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.base58 import b58encode
from btclib.base58wif import wif_from_prvkey
from btclib.curves import secp256k1 as ec
from btclib.to_prvkey import prvkey_info_from_prvkey


class TestWif(unittest.TestCase):

    def test_wif_from_prvkey(self):
        prvkey = '0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D'
        test_vectors = [
            [
                'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617',
                'mainnet', True
            ], [
                'cMzLdeGd5vEqxB8B6VFQoRopQ3sLAAvEzDAoQgvX54xwofSWj1fx',
                'testnet', True
            ], [
                '5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ',
                'mainnet', False
            ], [
                '91gGn1HgSap6CbU12F6z3pJri26xzp7Ay1VW6NHCoEayNXwRpu2',
                'testnet', False
            ], [
                ' KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617',
                'mainnet', True
            ], [
                'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617 ',
                'mainnet', True
            ]
        ]
        for v in test_vectors:
            wif = wif_from_prvkey(prvkey, v[1], v[2])
            self.assertEqual(v[0].strip(), wif.decode('ascii'))
            q, network, compressed = prvkey_info_from_prvkey(v[0])
            self.assertEqual(q, int(prvkey, 16))
            self.assertEqual(network, v[1])
            self.assertEqual(compressed, v[2])

        # not a 32-bytes private key
        badq = 33 * b'\x02'
        self.assertRaises(ValueError, wif_from_prvkey, badq, 'mainnet', True)
        # wif_from_prvkey(badq, 'mainnet', True)

        # private key not in (0, n)
        badq = ec.n
        self.assertRaises(ValueError, wif_from_prvkey, badq, 'mainnet', True)
        # wif_from_prvkey(badq, 'mainnet', True)

        # Not a private key WIF: missing leading 0x80
        payload = b'\x81' + badq.to_bytes(ec.nsize, 'big')
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_prvkey, badwif)
        # prvkey_info_from_prvkey(badwif)

        # Not a compressed WIF: missing trailing 0x01
        payload = b'\x80' + badq.to_bytes(ec.nsize, 'big') + b'\x00'
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_prvkey, badwif)
        # prvkey_info_from_prvkey(badwif)

        # Not a WIF: wrong size (35)
        payload = b'\x80' + badq.to_bytes(ec.nsize, 'big') + b'\x01\x00'
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_prvkey, badwif)
        # prvkey_info_from_prvkey(badwif)

        # Not a WIF: private key not in (0, n)
        payload = b'\x80' + badq.to_bytes(ec.nsize, 'big')
        badwif = b58encode(payload)
        self.assertRaises(ValueError, prvkey_info_from_prvkey, badwif)
        # prvkey_info_from_prvkey(badwif)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
