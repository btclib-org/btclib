#!/usr/bin/env python3

import unittest
import random
from btclib.ellipticcurves import Point, secp256k1 as ec
from btclib.pedersen_commitment import second_generator_secp256k1, pedersen_commit_raw

rand = random.SystemRandom()

class TestPedersenCommitment(unittest.TestCase):
    def test_ped_commitment(self):
        """
        Reproduce Confidential Tx on the slides. Omit fees for now.
        """
        G = ec.G
        # Picking additional generator H for the group.
        H = second_generator_secp256k1(G)
        # Retrieving these blinding factors from a previous output.
        r1 = rand.randint(1,ec.order-1)
        r2 = rand.randint(1,ec.order-1)
        # Picking random blinding factors - Alice will pick this up.
        r3 = rand.randint(1,ec.order-1)
        # Tx amounts
        v1 = 533
        v2 = 1478
        v3 = 10
        v4 = 2001
        # Pedersen Commitments
        self.assertEqual(v1 + v2, v3 + v4)
        C_inp1 = pedersen_commit_raw(r1, G, v1, H)
        C_inp2 = pedersen_commit_raw(r2, G, v2, H)
        C_inp = ec.pointAdd(C_inp1, C_inp2)
        # Bob will receive the following blinding factors: r3, r4 = r1+r2-r3 (the sum 
        # w/o single factors being disclosed).
        C_out1 = pedersen_commit_raw(r3, G, v3, H)          
        C_out2 = pedersen_commit_raw(r1+r2-r3, G, v4, H)
        C_out = ec.pointAdd(C_out1, C_out2)
        self.assertEqual(C_inp, C_out)
        
if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()