#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import secrets
import unittest

from btclib.utils import bytes_from_octets, hash160, hash256, int_from_integer

int_with_whitespaces = (
    " 0C 28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D  "
)


class TestUtils(unittest.TestCase):
    def test_utils(self):
        b = bytes_from_octets(int_with_whitespaces)
        s = b.hex()  # lower case, no spaces
        self.assertNotEqual(int_with_whitespaces, s)
        self.assertEqual(hash160(int_with_whitespaces), hash160(s))
        self.assertEqual(hash256(int_with_whitespaces), hash256(s))

        i = secrets.randbits(256)
        self.assertEqual(i, int_from_integer(i))
        self.assertEqual(i, int_from_integer(i.to_bytes(32, "big")))
        self.assertEqual(i, int_from_integer(hex(i)))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
