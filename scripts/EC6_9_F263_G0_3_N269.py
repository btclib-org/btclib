#!/usr/bin/python3

# elliptic curve y^2 = x^3 + a * x + b
__a = 6; __b = 9

# over prime finite field
__prime = 263;

# a given generator specifies the group order
__G = (0, 3)

# must be a prime for the cyclic group not to have subgroups
__order = 269

from EllipticCurve import EllipticCurve
ec = EllipticCurve(__a, __b, __prime, __G, __order)

def main():
  print(ec)
  
  i = 0
  P = (None, None)
  ec.checkPoint(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  i = 1
  P = __G
  ec.checkPoint(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  i = 2
  P = ec.pointDouble(P)
  ec.checkPoint(P)
  print(i, P)
  assert P == ec.pointMultiply(i)

  for i in range(3, __order+1):
    P = ec.pointAdd(P, __G)
    ec.checkPoint(P)
    print(i, P)
    assert P == ec.pointMultiply(i)

if __name__ == "__main__":
  # execute only if run as a script
  main()
