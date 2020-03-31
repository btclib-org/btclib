#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.utils import hash160, hash256, int_from_prvkey
from btclib.curves import secp256k1 as ec

class TestUtils(unittest.TestCase):

    def test_utils(self):
        s = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
        self.assertEqual(hash160(s), hash160(bytes.fromhex(s)))
        self.assertEqual(hash256(s), hash256(bytes.fromhex(s)))

    def test_int_from_prvkey(self):

        # Octets (bytes or hex-string)
        qhex = 'e8f32e723decf405 1aefac8e2c93c9c5 b214313817cdb01a 1494b917c8436b35'
        qbytes = bytes.fromhex(qhex)
        q = int.from_bytes(qbytes, 'big')

        self.assertEqual(q, int_from_prvkey(qbytes))
        self.assertEqual(q, int_from_prvkey(qhex))
        self.assertEqual(q, int_from_prvkey(' ' + qhex + ' '))
        self.assertEqual(q, int_from_prvkey(q))

        self.assertRaises(ValueError, int_from_prvkey, b'\x00' + qbytes)
        self.assertRaises(ValueError, int_from_prvkey, qhex + '00')

        q = ec.n
        qbytes = q.to_bytes(32, byteorder='big')
        qhex = qbytes.hex()
        self.assertRaises(ValueError, int_from_prvkey, q)
        self.assertRaises(ValueError, int_from_prvkey, qbytes)
        self.assertRaises(ValueError, int_from_prvkey, qhex)
        int_from_prvkey,(q)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
