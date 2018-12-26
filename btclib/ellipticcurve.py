#!/usr/bin/env python3

"""
Elliptic curve class

TODO: document duck-typing and static typing design choices
"""

from math import sqrt
from typing import Tuple, Union, Optional, NewType

from btclib.numbertheory import mod_inv, mod_sqrt, legendre_symbol

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
        assert 4*a*a*a+27*b*b !=0, "zero discriminant"
        self._a = a
        self._b = b

        self._p = p
        self.bytesize = (p.bit_length() + 7) // 8

        # to break simmetry using quadratic residue
        self.pIsThreeModFour = (self._p % 4 == 3)

        # check n with Hasse Theorem
        t = int(2 * sqrt(p))
        assert n <= p + 1 + t, "order %s too high for prime %s" % (n, p)
        # the following assertion would fail for subgroups
        assert p + 1 - t <= n, "order %s too low for prime %s" % (n, p)
        self.n = n

        if len(G) != 2:
            raise ValueError("Generator must a be a Tuple[int, int]")
        self.G = int(G[0]), int(G[1])
        if not self.areValidCoordinates(self.G[0], self.G[1]):
            raise ValueError("Generator is not on the 'x^3 + a*x + b' curve")

        # check (n-1)*G + G = Inf
        T = self.pointMultiply(n-1, self.G)
        Inf = self.pointAdd(T, self.G)
        assert Inf is None, "wrong order"

    # methods using self.a and self.b


    def checkCoordinate(self, c: int) -> None:
        """check that coordinate is in [0, p-1]"""
        if not (0 <= c < self._p):
            raise ValueError("coordinate %s not in [0, p-1]" % c)

    def _y2(self, x: int) -> int:
        self.checkCoordinate(x)
        # skipping a crucial check here:
        # if sqrt(y*y) does not exist, then x is not valid.
        # This is a good reason to keep this method private
        return ((x*x + self._a)*x + self._b) % self._p

    def y(self, x: int) -> int:
        y2 = self._y2(x)
        if y2 == 0: return 0 # impossible if n is prime
        # mod_sqrt will raise a ValueError if root does not exist
        return mod_sqrt(y2, self._p)

    def areValidCoordinates(self, x: int, y: int) -> bool:
        self.checkCoordinate(y)
        return self._y2(x) == (y*y % self._p)

    # break the y simmetry: even/odd, low/high, or quadratic residue criteria

    def yOdd(self, x: int, odd1even0: int) -> int:
        """return the odd (even) y coordinate associated to x"""
        assert odd1even0 in (0, 1), "must be bool or 0/1"
        root = self.y(x)
        # switch even/odd root when needed
        return root if (root % 2 + odd1even0) != 1 else self._p - root

    def yLow(self, x: int, low1high0: int) -> int:
        """return the low (high) y coordinate associated to x"""
        assert low1high0 in (0, 1), "must be bool or 0/1"
        root = self.y(x)
        # switch low/high root when needed
        return root if (root < self._p/2) else self._p - root

    def yQuadraticResidue(self, x: int, quadRes: int) -> int:
        """return the quadratic residue y coordinate associated to x"""
        assert self.pIsThreeModFour, "this method works only when p = 3 (mod 4)"
        assert quadRes in (0, 1), "must be bool or 0/1"
        root = self.y(x)
        # switch to the quadratic residue root when needed
        if quadRes:
            return self._p - root if (legendre_symbol(root, self._p) != 1) else root
        else:
            return root if (legendre_symbol(root, self._p) != 1) else self._p - root

    def opposite(self, Q: Optional[Point]) -> Optional[Point]:
        if Q is None: 
            return None
        else:
            return (Q[0], self._p - Q[1])

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

    def affine_from_jac(self, Q: JacPoint) -> Optional[Point]:
        assert isinstance(Q, tuple) and len(Q) == 3, "point not in Jacobian coordinates"
        if Q[2] == 0:
            return None
        else:
            x = (Q[0]*mod_inv(Q[2]*Q[2], self._p)) % self._p
            y = (Q[1]*mod_inv(Q[2]*Q[2]*Q[2], self._p)) % self._p
            return x, y

    def pointAddJacobian(self, Q: JacPoint, R: JacPoint) -> JacPoint:
        if Q[2] == 0: return R
        if R[2] == 0: return Q
        
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

    # double & add, using binary decomposition of n
    def pointMultiply(self, n: int, Q: Optional[Point]) -> Optional[Point]:
        if Q is None: return Q
        n = n % self.n # the group is cyclic
        r = None       # initialized to infinity point
        while n > 0:   # use binary representation of n
            if n & 1:  # if least significant bit is 1 then add current Q
                r = self.pointAdd(r, Q)
            n = n>>1   # right shift removes the bit just accounted for
                       # double Q for next step
            Q = self.pointAdd(Q, Q)
        return r

    def pointMultiplyJacobian(self, n: int, Q: JacPoint) -> Optional[Point]:
        if Q[2] == 0: return None
        n = n % self.n # the group is cyclic
        r = (1, 1, 0)  # initialized to infinity point
        while n > 0:   # use binary representation of n
            if n & 1:  # if least significant bit is 1 then add current Q
                r = self.pointAddJacobian(r, Q)
            n = n>>1   # right shift removes the bit just accounted for
                       # double Q for next step:
            Q = self.pointAddJacobian(Q, Q)
        return self.affine_from_jac(r)

