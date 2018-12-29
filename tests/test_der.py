#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from btclib.der import DER_encode, DER_decode


class TestDER(unittest.TestCase):
    def test_der(self):

        sighash_all = b'\x01'

        sig73 = 2**256 - 1, 2**256 - 1
        sig72 = 2**255 - 1, 2**256 - 1
        sig71 = 2**255 - 1, 2**255 - 1
        sig71b = 2**255 - 1, 2**248 - 1
        sig70 = 2**255 - 1, 2**247 - 1
        sig69 = 2**247 - 1, 2**247 - 1
        sigs = [sig73, sig72, sig71, sig71b, sig70, sig69]

        for sig in sigs:
            DER = DER_encode(sig, sighash_all)
            sig2, sighash_all2 = DER_decode(DER)
            self.assertEqual(sig, sig2)
            self.assertEqual(sighash_all, sighash_all2)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
