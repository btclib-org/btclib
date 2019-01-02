#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from hashlib import sha256 as hf

from btclib.ecurves import secp256k1 as ec
from btclib.rfc6979 import rfc6979


class Testrfc6979(unittest.TestCase):
    def test_rfc6979(self):
        # source: https://bitcointalk.org/index.php?topic=285142.40
        msg = hf(b'Satoshi Nakamoto').digest()
        x = 0x1
        k = rfc6979(ec, hf, msg, x)
        expected = 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
        self.assertEqual(k, expected)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
