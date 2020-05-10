#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import amount


class TestAmount(unittest.TestCase):
    def test_conversion(self):
        v1 = 1.1
        v2 = 2.2
        vtot = v1 + v2
        self.assertNotEqual(vtot, 3.3)  # _NOT_ equal !!
        s1 = amount.sat_from_float(v1)
        s2 = amount.sat_from_float(v2)
        stot = s1 + s2
        self.assertEqual(stot, 330000000)
        vtot = amount.float_from_sat(stot)
        self.assertEqual(vtot, 3.3)  # equal !!


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
