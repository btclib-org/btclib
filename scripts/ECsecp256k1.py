#!/usr/bin/python3

from EllipticCurve import EllipticCurve

# secp256k1
ec = EllipticCurve( \
  0, 7, 2**256 - 2**32 - 977,
  (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, \
   0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8), \
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

import unittest

class Testsecp256k1(unittest.TestCase):
    def test_tuple_from_point(self):
        prv = 0xc28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
        Pub = ec.pointMultiply(prv)
        
        Pub_bytes = b'\x02' + Pub[0].to_bytes(32, "big")
        p2 = ec.tuple_from_point(Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = ec.tuple_from_point(Pub_hex_str)
        self.assertEqual(p2, Pub)

        Pub_bytes = b'\x04' + Pub[0].to_bytes(32, "big") + Pub[1].to_bytes(32, "big")
        p2 = ec.tuple_from_point(Pub_bytes)
        self.assertEqual(p2, Pub)

        Pub_hex_str = Pub_bytes.hex()
        p2 = ec.tuple_from_point(Pub_hex_str)
        self.assertEqual(p2, Pub)


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
