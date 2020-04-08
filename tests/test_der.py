#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.curves import secp256k1 as ec
from btclib.der import _deserialize, _serialize


class TestDER(unittest.TestCase):

    def test_der(self):

        sighash_all = b'\x01'

        sig73  =   ec.n - 1,   ec.n - 1
        sig72  = 2**255 - 1,   ec.n - 1
        sig71  = 2**255 - 1, 2**255 - 1
        sig71b = 2**255 - 1, 2**248 - 1
        sig70  = 2**255 - 1, 2**247 - 1
        sig69  = 2**247 - 1, 2**247 - 1
        sig9   =          1,          1
        sigs = [sig73, sig72, sig71, sig71b, sig70, sig69]
        lenghts = [73, 72, 71, 71, 70, 69, 9]

        for lenght, sig in zip(lenghts, sigs):
            dersig = _serialize(*sig, sighash_all)
            r, s, sighash_all2 = _deserialize(dersig)
            self.assertEqual(sig, (r, s))
            self.assertEqual(sighash_all, sighash_all2)
            self.assertEqual(len(dersig), lenght)
            # without sighash
            r, s, sighash_all2 = _deserialize(dersig[:-1])
            self.assertEqual(sig, (r, s))
            self.assertIsNone(sighash_all2)

        # with the last one

        # DER signature size should be in [9, 73]
        dersig2 = dersig + b'\x00' * 70
        self.assertRaises(ValueError, _deserialize, dersig2)

        # DER signature must be of type 0x30 (compound)
        dersig2 = b'\x00' + dersig[1:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Declared signature size does not match with size
        dersig2 = dersig[:1] + b'\x00' + dersig[2:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        Rsize = dersig[3]
        # Zero-size integers are not allowed for r
        dersig2 = dersig[:3] + b'\x00' + dersig[4:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Length of the s scalar must be inside the signature
        dersig2 = dersig[:3] + b'\x80' + dersig[4:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Zero-size integers are not allowed for s
        dersig2 = dersig[:Rsize+5] + b'\x00' + dersig[Rsize+6:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Signature size does not match with scalars
        dersig2 = dersig[:Rsize+5] + b'\x4f' + dersig[Rsize+6:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # r scalar must be an integer
        dersig2 = dersig[:2] + b'\x00' + dersig[3:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Negative numbers are not allowed for r
        dersig2 = dersig[:4] + b'\x80' + dersig[5:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Invalid null bytes at the start of r
        dersig2 = dersig[:4] + b'\x00\x00' + dersig[6:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # s scalar must be an integer
        dersig2 = dersig[:Rsize+4] + b'\x00' + dersig[Rsize+5:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Negative numbers are not allowed for s
        dersig2 = dersig[:Rsize+6] + b'\x80' + dersig[Rsize+7:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # Invalid null bytes at the start of s
        dersig2 = dersig[:Rsize+6] + b'\x00\x00' + dersig[Rsize+8:]
        self.assertRaises(ValueError, _deserialize, dersig2)

        # sighash size > 1
        self.assertRaises(ValueError, _serialize, *sig, sighash_all + b'\x01')

        # negative signature scalar
        sig2 = -1, sig[1]
        self.assertRaises(ValueError, _serialize, *sig2, sighash_all)

        # Invalid sighash type b'\x00'
        self.assertRaises(ValueError, _deserialize, dersig[:-1] + b'\x00')
        #_deserialize(dersig[:-1] + b'\x00')

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
