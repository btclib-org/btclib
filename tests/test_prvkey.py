#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.bip32 import wif_from_xprv
from btclib.prvkey import prvkey_int
from btclib.wif import prvkey_from_wif
from btclib.curves import secp256k1 as ec


class TestPrvKey(unittest.TestCase):

    def test_prvkey(self):
        
        xkey = b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        xkey_str = xkey.decode()
        wif = wif_from_xprv(xkey)
        wif_str = wif.decode()
        q, _, _ = prvkey_from_wif(wif)
        qb = q.to_bytes(32, byteorder='big')
        q_hexstr = qb.hex()

        self.assertEqual(prvkey_int(q), q)
        self.assertEqual(prvkey_int(wif), q)
        self.assertEqual(prvkey_int(wif_str), q)
        self.assertEqual(prvkey_int(xkey), q)
        self.assertEqual(prvkey_int(xkey_str), q)
        self.assertEqual(prvkey_int(qb), q)
        self.assertEqual(prvkey_int(q_hexstr), q)
        self.assertRaises(ValueError, prvkey_int, q_hexstr + "00")

        q = ec.n
        self.assertRaises(ValueError, prvkey_int, q)
        qb = q.to_bytes(32, byteorder='big')
        self.assertRaises(ValueError, prvkey_int, qb)
        q_hexstr = qb.hex()
        self.assertRaises(ValueError, prvkey_int, q_hexstr)

        self.assertRaises(ValueError, prvkey_int, "not a key")
        #prvkey_int("not a key")

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
