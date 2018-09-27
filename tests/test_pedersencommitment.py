#!/usr/bin/env python3

import unittest
from btclib.ellipticcurves import secp256k1 as ec
from btclib.pedersen_commitment import pedersen_commit, pedersen_open

class TestPedersenCommitment(unittest.TestCase):
    def test_pedersen_commitment(self):
        r = 0x1
        v = 0x2
        C = pedersen_commit(ec, r, v)
        self.assertTrue(pedersen_open(ec, r, v, C))

    def test_pedersen_commitment_sum(self):
        r1 = 0x1
        r2 = 0x2
        r_sum = 0x3
        v1 = 0x4
        v2 = 0x5
        v_sum = 0x9
        C_sum = pedersen_commit(ec, r_sum, v_sum)
        self.assertTrue(pedersen_open(ec, r1 + r2 , v1 + v2, C_sum))

    def test_pedersen_commitment_oddeven(self):
        r = 0x0
        v = 0x5
        C_1 = pedersen_commit(ec, r, v)
        C_2 = pedersen_commit(ec, r, -v)
        self.assertTrue(C_1[0] == C_2[0])
        self.assertTrue(C_1[1] == ec.y(C_2[0], True) or C_1[1] == ec.y(C_2[0], False))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()