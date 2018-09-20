#!/usr/bin/env python3

import unittest
import random
from btclib.ellipticcurves import Point, secp256k1 as ec
from btclib.pedersen_commitment import coerce_hash_to_point, pedersen_commit, pedersen_open

rand = random.SystemRandom()

class TestPedersenCommitment(unittest.TestCase):
    def test_pedersen(self):
        G = ec.G
        H = coerce_hash_to_point(ec.G)
        r = 0x1
        v = 0x2
        C = pedersen_commit(r, G, v, H)
        self.assertTrue(pedersen_open(r, G, v, H, C))

    def test_pedersen_commitment(self):
        #------------------------------------------------------------------------------
        # Reproduce Confidential Tx on the slides. Omit fees for now.
        #------------------------------------------------------------------------------
        # Picking additional generator H for the group.
        H = coerce_hash_to_point(ec.G)
        # Picking random blinding factors (private key) - Alice will pick these up.
        r1 = rand.randint(1,ec.order-1)
        r2 = rand.randint(1,ec.order-1)
        r3 = rand.randint(1,ec.order-1)
        # Tx amounts
        v1 = 533
        v2 = 1478
        v3 = 10
        v4 = 2001
        # Pedersen Commitments
        self.assertEqual(v1 + v2, v3 + v4)
        C_inp1 = pedersen_commit(r1, ec.G, v1, H)
        C_inp2 = pedersen_commit(r2, ec.G, v2, H)
        C_inp = ec.pointAdd(C_inp1, C_inp2)
        # Bob will receive the following blinding factors: r3, r4 = r1+r2-r3 (the sum 
        # w/o single factors being disclosed).
        C_out1 = pedersen_commit(r3, ec.G, v3, H)          
        C_out2 = pedersen_commit(r1+r2-r3, ec.G, v4, H)
        C_out = ec.pointAdd(C_out1, C_out2)
        self.assertEqual(C_inp, C_out)

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()