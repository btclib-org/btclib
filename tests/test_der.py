#!/usr/bin/env python3

# Copyright (C) 2017-2019 The bbtlib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
from btclib.der import encode_DER_sig, check_DER_sig


class TestDER(unittest.TestCase):
    def test_der(self):
        DER73 = encode_DER_sig(2**256 - 1, 2**256 - 1)
        DER72 = encode_DER_sig(2**255 - 1, 2**256 - 1)
        DER71 = encode_DER_sig(2**255 - 1, 2**255 - 1)
        DER71b = encode_DER_sig(2**255 - 1, 2**248 - 1)
        DER70 = encode_DER_sig(2**255 - 1, 2**247 - 1)
        DER69 = encode_DER_sig(2**247 - 1, 2**247 - 1)
        self.assertTrue(check_DER_sig(DER73))
        self.assertTrue(check_DER_sig(DER72))
        self.assertTrue(check_DER_sig(DER71))
        self.assertTrue(check_DER_sig(DER71b))
        self.assertTrue(check_DER_sig(DER70))
        self.assertTrue(check_DER_sig(DER69))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
