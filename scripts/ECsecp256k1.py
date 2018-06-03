#!/usr/bin/python3

from EllipticCurve import EllipticCurve

# secp256k1
ec = EllipticCurve( \
  0, 7, 2**256 - 2**32 - 977,
  (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, \
   0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8), \
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


def main():
  print(ec)

  G = ec.pointMultiply(1)
  
  i = 0
  P = (None, None)
  ec.scrub_point(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  i = 1
  P = G
  ec.scrub_point(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  i = 2
  P = ec.pointDouble(P)
  ec.scrub_point(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  P = ec.pointMultiply(ec.order-1)
  for i in range(ec.order, ec.order+1):
    P = ec.pointAdd(P, G)
    ec.scrub_point(P)
    print(i % ec.order, P)
    assert P == ec.pointMultiply(i)

if __name__ == "__main__":
  # execute only if run as a script
  main()
