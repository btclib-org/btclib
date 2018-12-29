#!/usr/bin/env python3

"""Modular algebra functions

   Implementations are from the web with minor modifications.
"""


def mod_inv(a: int, m: int) -> int:
    """ Return the inverse of 'a' (mod m). m does not have to be a prime.
    """
    a = a % m
    # From Ferguson and Schneier, roughly:
    c, d = a, m
    uc, vc, ud, vd = 1, 0, 0, 1
    while c != 0:
        q, c, d = divmod(d, c) + (c, )
        uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

    # At this point, d is the GCD, and ud*a+vd*m = d.
    # If d == 1, this means that ud is a inverse.
    assert d == 1, "failure: [inv(0) does not exists]"
    if ud > 0:
        return ud
    else:
        return ud + m

def mod_inv2(a: int, p: int) -> int:
    """ Return the inverse of 'a' (mod p). p must be a prime.

        Much more elegant than Ferguson and Schneier, but 50 times slower.
    """
    return pow(a, p-2, p)

def mod_sqrt(a: int, p: int) -> int:
    """ Return a quadratic residue (mod p) of 'a'. p must be a prime.

        Solve the congruence of the form:
            x^2 = a (mod p)
        And returns x. Note that p - x is also a root.
        The Tonelli-Shanks algorithm is used (except for some simple
        cases in which the solution is known from an identity).
        This algorithm runs in polynomial time (unless the generalized
        Riemann hypothesis is false).
    """
    # Simple cases
    if p % 4 == 3:  # secp256k1 case
        x = pow(a, (p + 1) // 4, p)  # inverse candidate
        if x*x % p == a:
            return x
        raise ValueError("no root (mod %s) exists for %s" % (p, a))
    elif a == 0 or p == 2:
        return a

    # check for root existence
    if legendre_symbol(a, p) != 1:
        raise ValueError("no root (mod %s) exists for %s" % (p, a))

    # Partition p-1 to s * 2^e for an odd s (i.e.
    # reduce all the powers of 2 from p-1)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    # Find some 'n' with a legendre symbol n|p = -1.
    # Shouldn't take long.
    n = 1
    while legendre_symbol(n, p) != -1:
        n += 1

    # Here be dragons!
    # Read the paper "Square roots from 1; 24, 51,
    # 10 to Dan Shanks" by Ezra Brown for more
    # information

    # x is a guess of the square root that gets better
    # with each iteration.
    # b is the "fudge factor" - by how much we're off
    # with the guess. The invariant x^2 = ab (mod p)
    # is maintained throughout the loop.
    # g is used for successive powers of n to update
    # both a and b
    # r is the exponent - decreases with each update
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):
    """ Compute the Legendre symbol a|p using Euler's criterion.

        p is a prime, a is relatively prime to p (if p divides a, then a|p = 0)
        Returns 1 if a has a square root modulo p, -1 otherwise.
    """
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls
