#!/usr/bin/env python3

import unittest
from btclib.ellipticcurves import Point, secp256k1 as ec, bytes_from_Point
from btclib.pedersen_commitment import second_generator_secp256k1, pedersen_commit_raw, pedersen_open_raw

class TestPedersenCommitment(unittest.TestCase):
    def test_second_generator_secp256k1_hardcoded(self):
        """
        source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
        important remark on secp256-zkp prefix for compressed encoding of points:
        https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment
        """
        G = ec.G
        H_hardcoded = '0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
        H = second_generator_secp256k1(G)
        H_bytes = bytes_from_Point(ec, H, True)
        self.assertTrue(H_bytes == bytes.fromhex(H_hardcoded))

    def test_pedersen_commitment(self):
        G = ec.G
        H = second_generator_secp256k1(G)
        r = 0x1
        v = 0x2
        C = pedersen_commit_raw(r, G, v, H)
        self.assertTrue(pedersen_open_raw(r, G, v, H, C))
    
    def test_pedersen_commitment_sum(self):
        G = ec.G
        H = second_generator_secp256k1(G)
        r1 = 0x1
        r2 = 0x2
        r_sum = 0x3
        v1 = 0x4
        v2 = 0x5
        v_sum = 0x9
        C_sum = pedersen_commit_raw(r_sum, G, v_sum, H)
        self.assertTrue(pedersen_open_raw(r1 + r2 , G, v1 + v2, H, C_sum))

    def test_pedersen_commitment_oddeven(self):
        G = ec.G
        H = second_generator_secp256k1(G)
        r = 0x0
        v = 0x5
        C_1 = pedersen_commit_raw(r, G, v, H)
        C_2 = pedersen_commit_raw(r, G, -v, H)
        self.assertTrue(C_1[0] == C_2[0])
        self.assertTrue(C_1[1] == ec.y(C_2[0], True) or C_1[1] == ec.y(C_2[0], False))

if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()