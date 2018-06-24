#!/usr/bin/env python3

import unittest
from btclib.ellipticcurves import secp256k1, \
                                  ec11_13, ec79_43, \
                                  ec263_269, ec263_270, ec263_280

class Testsecp256k1(unittest.TestCase):
    def test_all_curves(self):
        for ec in (secp256k1, ec11_13, ec79_43, ec263_269, ec263_270, ec263_280):
            infinity = None
            self.assertEqual(ec.pointMultiply(0, ec.G), infinity)

            G = ec.pointMultiply(1, ec.G)
            self.assertEqual(G, ec.G)

            Gy = ec.y(G[0], True)
            self.assertEqual(Gy % 2, 1)
            Gy = ec.y(G[0], False)
            self.assertEqual(Gy % 2, 0)

            P = ec.pointAdd(infinity, G)
            self.assertEqual(P, G)
            P = ec.pointAdd(G, infinity)
            self.assertEqual(P, G)

            P = ec.pointDouble(G)
            self.assertEqual(P, ec.pointMultiply(2, ec.G))

            P = ec.pointAdd(G, G)
            self.assertEqual(P, ec.pointMultiply(2, ec.G))

            P = ec.pointMultiply(ec.order-1, ec.G)
            self.assertEqual(ec.pointAdd(P, G), infinity)
            self.assertEqual(ec.pointMultiply(ec.order, ec.G), infinity)

            self.assertEqual(ec.pointMultiply(0, infinity), infinity)
            self.assertEqual(ec.pointMultiply(1, infinity), infinity)
            self.assertEqual(ec.pointMultiply(25, infinity), infinity)

            if (ec.order % 2 == 0):
                P = ec.pointMultiply(ec.order//2, ec.G)
                self.assertEqual(P[1], 0)
                self.assertEqual(ec.pointDouble(P), infinity)

    def test_tuple_from_point(self):
        prv = 0xc28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
        Pub = secp256k1.pointMultiply(prv, secp256k1.G)
        
        Pub_bytes = b'\x02' + Pub[0].to_bytes(32, "big")
        p2 = secp256k1.tuple_from_point(Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = secp256k1.tuple_from_point(Pub_hex_str)
        self.assertEqual(p2, Pub)

        Pub_bytes = b'\x04' + Pub[0].to_bytes(32, "big") + Pub[1].to_bytes(32, "big")
        p2 = secp256k1.tuple_from_point(Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = secp256k1.tuple_from_point(Pub_hex_str)
        self.assertEqual(p2, Pub)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
