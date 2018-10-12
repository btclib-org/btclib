#!/usr/bin/env python3

import unittest
import os
from random import SystemRandom 
from btclib.ellipticcurves import secp256k1 as ec, pointMultiply
from btclib.borromean_ringsign import borromean_sign, borromean_verify

prng = SystemRandom()

class TestBorromeanRingSignature(unittest.TestCase):
    def test_borromean(self):
        ring_number = 4
        ring_dim = [prng.randint(1, 4) for ring in range(ring_number)]
        signing_indexes = [prng.randrange(ring_dim[ring]) for ring in range(ring_number)]
        priv_keys = {}
        Pub_keys = {}
        signing_keys = []
        for i in range(ring_number):
            priv_keys[i] = [0]*ring_dim[i]
            Pub_keys[i] = [0]*ring_dim[i]
            for j in range(ring_dim[i]):
                priv_keys[i][j] = os.urandom(32)
                Pub_keys[i][j] = pointMultiply(ec, priv_keys[i][j], ec.G)
            signing_keys.append(priv_keys[i][signing_indexes[i]])
        msg = 'Borromean ring signature'
        sig = borromean_sign(msg, signing_indexes, signing_keys, Pub_keys)
        self.assertTrue(borromean_verify(msg, sig[0], sig[1], Pub_keys))
