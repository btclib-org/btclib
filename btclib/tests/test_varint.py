#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest

from btclib import varint

class TestVarInt(unittest.TestCase):

    def test_conversion(self):

        i = 0xfc
        b = varint.encode(i)
        self.assertEqual(len(b), 1)
        self.assertEqual(varint.decode(b), i)

        i += 1
        b = varint.encode(i)
        self.assertEqual(len(b), 3)
        self.assertEqual(varint.decode(b), i)

        i = 0xffff
        b = varint.encode(i)
        self.assertEqual(len(b), 3)
        self.assertEqual(varint.decode(b), i)

        i += 1
        b = varint.encode(i)
        self.assertEqual(len(b), 5)
        self.assertEqual(varint.decode(b), i)

        i = 0xffffffff
        b = varint.encode(i)
        self.assertEqual(len(b), 5)
        self.assertEqual(varint.decode(b), i)

        i += 1
        b = varint.encode(i)
        self.assertEqual(len(b), 9)
        self.assertEqual(varint.decode(b), i)

        i = 0xffffffffffffffff
        b = varint.encode(i)
        self.assertEqual(len(b), 9)
        self.assertEqual(varint.decode(b), i)

        # integer too large (0x10000000000000000) for varint encoding
        i += 1
        self.assertRaises(ValueError, varint.encode, i)
        #varint.encode(i)

        self.assertEqual(varint.decode('6a'), 106)
        self.assertEqual(varint.decode('fd2602'), 550)
        self.assertEqual(varint.decode('fe703a0f00'), 998000)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()  # pragma: no cover
