#!/usr/bin/python3

# secp256k1
a = 0; b = 7
prime = 2**256 - 2**32 -977
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

from EllipticCurve import EllipticCurve
ec = EllipticCurve(a, b, prime, (gx, gy), order)

def main():
  G = (gx, gy)
  ec.checkPoint(G)
  print(ec.G)
  print(ec.pointAdd(G, G))
  print(ec.pointDouble(G))
  print(ec.pointMultiply(2, G))
  print(ec.pointMultiply(order, G))
  print(ec.pointMultiply(order+1, G))
  print(ec.pointMultiply(order+2, G))

if __name__ == "__main__":
  # execute only if run as a script
  main()
