#!/usr/bin/python3

# secp256k1
__a = 0; __b = 7
__prime = 2**256 - 2**32 - 977
__gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
__gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
__G = (__gx, __gy)
__order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

from EllipticCurve import EllipticCurve
ec = EllipticCurve(__a, __b, __prime, __G, __order)

def main():
  print(ec)
  
  i = 0
  P = (None, None)
  ec.scrub_point(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  i = 1
  P = __G
  ec.scrub_point(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  i = 2
  P = ec.pointDouble(P)
  ec.scrub_point(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  P = ec.pointMultiply(__order-1)
  for i in range(__order, __order+1):
    P = ec.pointAdd(P, __G)
    ec.scrub_point(P)
    print(i % __order, P)
    assert P == ec.pointMultiply(i)

if __name__ == "__main__":
  # execute only if run as a script
  main()
