#!/usr/bin/env python3

from hashlib import sha256
from btclib.ellipticcurves import Point, secp256k1 as ec, \
                                  bytes_from_Point

def coerce_hash_to_point(G: Point) -> Point:
    """ Function needed to construct a suitable Nothing-Up-My-Sleeve (NUMS) 
    generator H wrt G.
    Possible to accomplish it by using the cryptographic hash of G to pick H
    (Maxwell). Need a function to construct the point from the randomized
    hashvalue, i.e. that enables coercing the hash to a curve point.
    
    IDEA: (https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve)
    As just hashing the x-coordinate could possibly result not in obtaining 
    a curvepoint (while a generator has to be a curvepoint), keep on incrementing
    x until you get a valid curve point H = (hx,hy).
    
    INPUT:  - G: generator point G
    OUTPUT: - H : (additional) NUMS generator point wrt G
    """
    G_bytes = bytes_from_Point(ec, G, False)
    hx_temp = sha256(G_bytes[:ec.bytesize+1]).digest()
    hx = int.from_bytes(hx_temp, 'big') % ec._EllipticCurve__prime # (possible) x-component for H - as long as together w/ hy it gives a valid curve point) 
    count = 0 # count how many increments are needed to get a valid curvepoint 
    while True:
        try:
            hy = ec.y(hx, True) # (possible) y-component for H - as long as together w/ hx it gives a valid curve point) 
            break
        except AssertionError: # incrementing hx (to get a new hy as well) if H is not a valid curvepoint
            hx += 1
            count += 1
    return  hx, hy

def pedersen_commit(r: int, G: Point, v: int, H: Point) -> Point:
    if (v == 0):
        raise 'Error: v must be different from 0'
    rG = ec.pointMultiply(r, G)
    vH = ec.pointMultiply(v, H)
    C = ec.pointAdd(rG, vH)
    return C

def pedersen_open(r: int, G: Point, v: int, H: Point, C: Point) -> Point:
    return C == pedersen_commit(r, G, v, H)
