#!/usr/bin/env python3

import unittest
from btclib.ellipticcurves import Point, secp256k1 as ec
from btclib.pedersen_commitment import second_generator_secp256k1, pedersen_commit, pedersen_open

class TestPedersenCommitment(unittest.TestCase):
    def test_pedersen_commitment(self):
        G = ec.G
        H = second_generator_secp256k1(G)
        r = 0x1
        v = 0x2
        C = pedersen_commit(r, G, v, H)
        self.assertTrue(pedersen_open(r, G, v, H, C))
    
    def test_pedersen_commitment_sum(self):
        G = ec.G
        H = second_generator_secp256k1(G)
        r1 = 0x1
        r2 = 0x0
        r_sum = 0x1
        v1 = 0x5
        v2 = -0x5
        v_sum = 0x0
        C_sum = pedersen_commit(r_sum, G, v_sum, H)
        self.assertTrue(pedersen_open(r1 + r2 , G, v1 + v2, H, C_sum))

    def test_pedersen_commitment_oddeven(self):
        G = ec.G
        H = second_generator_secp256k1(G)
        r = 0x0
        v = 0x5
        C_1 = pedersen_commit(r, G, v, H)
        C_2 = pedersen_commit(r, G, -v, H)
        self.assertEqual(C_1[0], C_2[0])
        self.assertEqual(C_1[1], ec.y(C_2[0], True))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()