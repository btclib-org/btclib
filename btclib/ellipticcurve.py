#!/usr/bin/env python3

"""
Elliptic curve class

TODO: document duck-typing and static typing design choices
"""

from math import sqrt
from typing import Tuple, Union, Optional, NewType

from btclib.numbertheory import mod_inv, mod_sqrt, legendre_symbol
#from btclib.ellipticcurves import pointMultiply

Point = Tuple[int, int]
JacPoint = Tuple[int, int, int] 
# infinity point being represented by None,
# Optional[Point] does include the infinity point

def jac_from_affine(Q: Optional[Point]) -> JacPoint:
    if Q is None:
        return (1, 1, 0)
    if len(Q) != 2:
        raise ValueError("input point not in affine coordinates")
    return (Q[0], Q[1], 1)

# elliptic curve y^2 = x^3 + a*x + b
class EllipticCurve:
    """Elliptic curve over Fp group"""

    def __init__(self,
                 a: int,
                 b: int,
                 p: int,
                 G: Point,
                 n: int) -> None:
        """EllipticCurve instantiation

        Parameters are checked according to SEC2 3.1.1.2.1
        """

        # 1) check that p is an odd prime
        if p % 2 == 0:
            raise ValueError("p %s is not odd" % p)
        # Fermat test will do as _probabilistic_ primality test...
        if not pow(2, p-1, p) == 1:
            raise ValueError("p %s is not prime" % p)
        self._p = p
        self.bytesize = (p.bit_length() + 7) // 8

        # 1. check that security level is as required
        # missing for the time being

        # must be true to break simmetry using quadratic residue
        self.pIsThreeModFour = (self._p % 4 == 3)

        # 2. check that a and b are integers in the interval [0, p−1]
        self.checkCoordinate(a)
        self.checkCoordinate(b)

        # 3. Check that 4*a^3 + 27*b^2 ≠ 0 (mod p).
        if 4*a*a*a+27*b*b % p == 0:
            raise ValueError("zero discriminant")
        self._a = a
        self._b = b

        # 2. check that xG and yG are integers in the interval [0, p−1]
        if len(G) != 2:
            raise ValueError("Generator must a be a Tuple[int, int]")
        if not self.areValidCoordinates(G[0], G[1]):
            raise ValueError("Generator is not on the 'x^3 + a*x + b' curve")
        self.G = int(G[0]), int(G[1])

        # 4. Check that n is prime.
        if n < 2 or (n > 2 and not pow(2, n-1, n) == 1):
            raise ValueError("n %s is not prime" % n)
        # also check n with Hasse Theorem
        t = int(2 * sqrt(p))
        if not (p+1 - t <= n <= p+1 + t):
            raise ValueError("n %s not in [p+1 - t, p+1 + t]" % n)
        
        # 7. Check that nG = Inf.
        #Inf = pointMultiply(self, n, self.G)
        #if Inf is not None:
        #    raise ValueError("n is not the group order")
        self.n = n

        # 6. Check cofactor
        # missing for the time being
        
    def __str__(self) -> str:
        result  = "EllipticCurve(a=%s, b=%s)" % (self._a, self._b)
        result += "\n p = 0x%032x" % (self._p)
        result += "\n G =(0x%032x,\n         0x%032x)" % (self.G)
        result += "\n n = 0x%032x" % (self.n)
        return result

    def __repr__(self) -> str:
        result  = "EllipticCurve(%s, %s" % (self._a, self._b)
        result += ", 0x%032x" % (self._p)
        result += ", (0x%032x,0x%032x)" % (self.G)
        result += ", 0x%032x)" % (self.n)
        return result

    # p

    def checkCoordinate(self, c: int) -> None:
        """check that coordinate is in [0, p-1]"""
        if not (0 <= c < self._p):
            raise ValueError("coordinate %s not in [0, p-1]" % c)

    def opposite(self, Q: Optional[Point]) -> Optional[Point]:
        if Q is None: 
            return None
        else:
            return (Q[0], self._p - Q[1])

    def affine_from_jac(self, Q: JacPoint) -> Optional[Point]:
        if not (isinstance(Q, tuple) and len(Q)==3):
            raise ValueError("point is not in Jacobian coordinates")
        if Q[2] == 0:
            return None
        else:
            x = (Q[0]*mod_inv(Q[2]*Q[2], self._p)) % self._p
            y = (Q[1]*mod_inv(Q[2]*Q[2]*Q[2], self._p)) % self._p
            return x, y

    # _a, _b, _p

    def pointAddJacobian(self, Q: JacPoint, R: JacPoint) -> JacPoint:
        if Q[2] == 0:
            return R
        if R[2] == 0:
            return Q
        
        if Q[0]*R[2]*R[2] % self._p == R[0]*Q[2]*Q[2] % self._p: # same affine x coordinate
            if Q[1]*R[2]*R[2]*R[2] % self._p != R[1]*Q[2]*Q[2]*Q[2] % self._p or Q[1] % self._p == 0:    # opposite points or degenerate case
                return 1, 1, 0
            else:                            # point doubling
                W = (3*Q[0]*Q[0] + self._a*Q[2]*Q[2]*Q[2]*Q[2]) % self._p
                V = (4*Q[0]*Q[1]*Q[1]) % self._p
                X = (W*W - 2*V) % self._p
                Y = (W*(V - X) - 8*Q[1]*Q[1]*Q[1]*Q[1]) % self._p
                Z = (2*Q[1]*Q[2]) % self._p
                return X, Y, Z
        else:
            T = (Q[1]*R[2]*R[2]*R[2]) % self._p
            U = (R[1]*Q[2]*Q[2]*Q[2]) % self._p
            W = (U - T) % self._p
            M = (Q[0]*R[2]*R[2]) % self._p
            N = (R[0]*Q[2]*Q[2]) % self._p
            V = (N - M) % self._p
                
            X = (W*W - V*V*V - 2*M*V*V) % self._p
            Y = (W*(M*V*V - X) - T*V*V*V) % self._p
            Z = (V*Q[2]*R[2]) % self._p
            return X, Y, Z

    def pointAdd(self, Q: Optional[Point], R: Optional[Point]) -> Optional[Point]:
        if R is None:
            return Q
        if Q is None:
            return R
        if R[0] == Q[0]:
            if R[1] != Q[1] or Q[1] == 0: # opposite points
                return None
            else: # point doubling
                lam = ((3*Q[0]*Q[0]+self._a)*mod_inv(2*Q[1], self._p)) % self._p
        else:
            lam = ((R[1]-Q[1]) * mod_inv(R[0]-Q[0], self._p)) % self._p
        x = (lam*lam-Q[0]-R[0]) % self._p
        y = (lam*(Q[0]-x)-Q[1]) % self._p
        return x, y

    def _y2(self, x: int) -> int:
        self.checkCoordinate(x)
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to keep this method private
        return ((x*x + self._a)*x + self._b) % self._p

    def y(self, x: int) -> int:
        y2 = self._y2(x)
        if y2 == 0:
            return 0 # impossible if n is prime
        # mod_sqrt will raise a ValueError if root does not exist
        return mod_sqrt(y2, self._p)

    def areValidCoordinates(self, x: int, y: int) -> bool:
        self.checkCoordinate(y)
        return self._y2(x) == (y*y % self._p)

    # break the y simmetry: even/odd, low/high, or quadratic residue criteria

    def yOdd(self, x: int, odd1even0: int) -> int:
        """return the odd (even) y coordinate associated to x"""
        if odd1even0 not in (0, 1):
            raise ValueError("odd1even0 must be bool or 0/1")
        root = self.y(x)
        # switch even/odd root when needed
        return root if (root % 2 + odd1even0) != 1 else self._p - root

    def yLow(self, x: int, low1high0: int) -> int:
        """return the low (high) y coordinate associated to x"""
        if low1high0 not in (0, 1):
            raise ValueError("low1high0 must be bool or 0/1")
        root = self.y(x)
        # switch low/high root when needed
        return root if (root < self._p/2) else self._p - root

    def yQuadraticResidue(self, x: int, quadRes: int) -> int:
        """return the quadratic residue y coordinate associated to x"""
        if not self.pIsThreeModFour:
            raise ValueError("this method works only when p = 3 (mod 4)")
        if quadRes not in (0, 1):
            raise ValueError("quadRes must be bool or 0/1")
        root = self.y(x)
        # switch to the quadratic residue root when needed
        if quadRes:
            return self._p - root if (legendre_symbol(root, self._p) != 1) else root
        else:
            return root if (legendre_symbol(root, self._p) != 1) else self._p - root
