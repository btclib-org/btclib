#!/usr/bin/python3

# elliptic curve y^2 = x^3 + a * x + b
a = -1; b = 1

# over prime finite field
prime = 79;

# a given generator specifies the group order
G = (0, 1)

# must be a prime for the cyclic group not to have subgroups
order = 43

from EllipticCurve import EllipticCurve, pointAdd, pointDouble, pointMultiply, modInv
ec = EllipticCurve(a, b, prime, G, order)

def main():
  i = 1
  P = G
  ec.checkPoint(P)
  print(i, P)
  assert P == pointMultiply(i, G, ec)

  i = 2
  P = pointDouble(G, ec)
  ec.checkPoint(P)
  print(i, P)
  assert P == pointMultiply(i, G, ec)

  for i in range(3, order+2):
    P = pointAdd(P, G, ec)
    ec.checkPoint(P)
    print(i, P)
    assert P == pointMultiply(i, G, ec)

if __name__ == "__main__":
  # execute only if run as a script
  main()
