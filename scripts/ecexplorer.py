#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from numbertheory import mod_sqrt

def isprime(n):
    """Returns True if n is prime."""
    if n == 2:
        return True
    if n == 3:
        return True
    if n % 2 == 0:
        return False
    if n % 3 == 0:
        return False

    i = 5
    w = 2

    while i * i <= n:
        if n % i == 0:
            return False

        i += w
        w = 6 - w

    return True
    
primes = [11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293]
for prime in primes:
    maxorder = 0
    maxordera = -1
    maxorderb = -1
    maxorderlessthanprime = 0
    maxorderlessthanprimea = -1
    maxorderlessthanprimeb = -1
    for a in range(200):
        for b in range(200):
            order = 0
            for x in range(prime):
                y2 = ((x*x + a)*x + b) % prime
                if y2 == 0:
                    order += 1
                    #print("#", order+1, " ", x, ", ", 0, "  #####", sep="")
                    continue
                try:
                    y = mod_sqrt(y2, prime)
                    assert (y*y) % prime == y2
                    #print("#", order+1, " ", x, ",", y, sep="")
                    #print("#", order+2, " ", x, ",", prime-y, sep="")
                    order += 2
                except:
                    continue
            order += 1
            if isprime(order):
                #print(a, b, prime, "gen", order)
                if order > maxorder:
                    maxorder = order
                    maxordera = a
                    maxorderb = b
                if order > maxorderlessthanprime and order < prime:
                    maxorderlessthanprime = order
                    maxorderlessthanprimea = a
                    maxorderlessthanprimeb = b

    if (maxorderlessthanprimea != -1):
        gx = 0
        gy = -1
        while gy == -1:
            y2 = ((gx*gx + maxorderlessthanprimea)*gx + maxorderlessthanprimeb) % prime
            try:
                y = mod_sqrt(y2, prime)
                assert (y*y) % prime == y2
                gy = y 
            except:
                gx += 1
        print("ec", prime, "_", maxorderlessthanprime, " = ", "EllipticCurve(", maxorderlessthanprimea, ", ", maxorderlessthanprimeb, ", ", prime, ", ", "(", gx, ",", gy, ")", ", ", maxorderlessthanprime, ")", sep="")
    if (maxordera != -1):
        gx = 0
        gy = -1
        while gy == -1:
            y2 = ((gx*gx + maxordera)*gx + maxorderb) % prime
            try:
                y = mod_sqrt(y2, prime)
                assert (y*y) % prime == y2
                gy = y 
            except:
                gx += 1
        print("ec", prime, "_", maxorder, " = ", "EllipticCurve(", maxordera, ", ", maxorderb, ", ", prime, ", ", "(", gx, ",", gy, ")", ", ", maxorder, ")", sep="")
