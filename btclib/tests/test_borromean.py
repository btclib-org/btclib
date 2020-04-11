#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

import unittest
import random

from btclib.curvemult import mult
from btclib.curves import secp256k1 as ec
from btclib import borromean

random.seed(42)


class TestBorromeanRingSignature(unittest.TestCase):
    def test_borromean(self):
        ring_number = 4
        ring_dim = [random.randint(1, 4) for ring in range(ring_number)]
        signing_indexes = [random.randrange(ring_dim[ring])
                           for ring in range(ring_number)]
        priv_keys = {}
        Pub_keys = {}
        signing_keys = []
        for i in range(ring_number):
            priv_keys[i] = [0]*ring_dim[i]
            Pub_keys[i] = [0]*ring_dim[i]
            for j in range(ring_dim[i]):
                priv_keys[i][j] = j+1
                Pub_keys[i][j] = mult(priv_keys[i][j], ec.G, ec)
            signing_keys.append(priv_keys[i][signing_indexes[i]])
        msg = 'Borromean ring signature'
        sig = borromean.sign(msg, list(range(1, 5)),
                             signing_indexes, signing_keys, Pub_keys)
        self.assertTrue(borromean.verify(msg, sig[0], sig[1], Pub_keys))

        self.assertFalse(borromean.verify(0, sig[0], sig[1], Pub_keys))


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
