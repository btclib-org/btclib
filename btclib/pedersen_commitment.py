#!/usr/bin/env python3

from hashlib import sha256
from btclib.ellipticcurves import Point, secp256k1 as ec, \
                                  bytes_from_Point, int_from_Scalar

def second_generator_secp256k1(G: Point) -> Point:
    """ Function needed to construct a suitable Nothing-Up-My-Sleeve (NUMS) 
    generator H wrt G. Possible to accomplish it by using the cryptographic
    hash of G to pick H.

    source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    IDEA: (https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve)
    - Coerce the hash to a point:
    as just hashing the point could possibly result not in obtaining 
    a curvepoint, keep on incrementing the hash of the x-coordinate 
    until you get a valid curve point H = (hx,hy).
    """
    G_bytes = bytes_from_Point(ec, G, False)
    hx_temp = sha256(G_bytes).digest()
    hx = int_from_Scalar(ec, hx_temp)
    while True:
        try:
            hy = ec.y(hx, False) 
            break
        except ValueError: 
            hx += 1
    return hx, hy

def pedersen_commit(r: int, G: Point, v: int, H: Point) -> Point:
    rG = ec.pointMultiply(r, G)
    vH = ec.pointMultiply(v, H)
    C = ec.pointAdd(rG, vH)
    return C

def pedersen_open(r: int, G: Point, v: int, H: Point, C: Point) -> bool:
    return C == pedersen_commit(r, G, v, H)
