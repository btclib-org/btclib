#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib.utils import bytes_from_octets, hash160, hash256


class TestUtils(unittest.TestCase):

    def test_utils(self):
        s_spaces = " 0C 28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D  "
        b = bytes_from_octets(s_spaces)
        s = b.hex()  # lower case, no spaces
        self.assertNotEqual(s, s_spaces)
        self.assertEqual(hash160(s_spaces), hash160(bytes_from_octets(s)))
        self.assertEqual(hash256(s_spaces), hash256(bytes_from_octets(s)))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
