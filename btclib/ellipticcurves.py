#!/usr/bin/env python3

"""
EllipticCurve functions and instances of SEC2 elliptic curves
"""

from hashlib import sha256
from typing import Tuple, NewType, Union

from btclib.ellipticcurve import Point, GenericPoint, \
                                 JacPoint, jac_from_affine, \
                                 EllipticCurve, to_Point

def bytes_from_Point(ec: EllipticCurve,
                     Q: GenericPoint,
                     compressed: bool) -> bytes:
    """
    Return a compressed (0x02, 0x03) or uncompressed (0x04)
    point ensuring it belongs to the curve
    """
    # enforce self-consistency with whatever
    # policy is implemented by to_Point
    Q = to_Point(ec, Q)

    if Q[1] == 0: # infinity point in affine coordinates
        return b'\x00'

    bPx = Q[0].to_bytes(ec.bytesize, byteorder='big')
    if compressed:
        return (b'\x03' if (Q[1] & 1) else b'\x02') + bPx

    return b'\x04' + bPx + Q[1].to_bytes(ec.bytesize, byteorder='big')

Scalar = Union[str, bytes, int]

def int_from_Scalar(ec: EllipticCurve, n: Scalar) -> int:
    if isinstance(n, str): # hex string
        n = bytes.fromhex(n)

    if isinstance(n, bytes):
        # FIXME: asses if must be <= or ec.bytesize should be revised
        assert len(n) <= ec.bytesize, "wrong lenght"
        n = int.from_bytes(n, 'big')

    return n % ec.n

def bytes_from_Scalar(ec: EllipticCurve, n: Scalar) -> bytes:
    # enforce self-consistency with whatever
    # policy is implemented by int_from_Scalar
    n = int_from_Scalar(ec, n)
    return n.to_bytes(ec.bytesize, 'big')

def pointMultiply(ec: EllipticCurve,
                  n: Scalar,
                  Q: GenericPoint) -> Point:
    """double & add in affine coordinates, using binary decomposition of n"""
    n = int_from_Scalar(ec, n)
    Q = to_Point(ec, Q)
    
    if Q[1] == 0: # Infinity point in affine coordinates
        return Q
    R = 1, 0      # initialize as infinity point
    while n > 0:  # use binary representation of n
        if n & 1: # if least significant bit is 1 then add current Q
            R = ec.pointAdd(R, Q)
        n = n>>1  # right shift removes the bit just accounted for
                  # double Q for next step
        Q = ec.pointAdd(Q, Q)
    return R

def pointMultiplyJacobian(ec: EllipticCurve,
                          n: Scalar,
                          Q: JacPoint) -> JacPoint:
    """double & add in jacobian coordinates, using binary decomposition of n"""
    n = int_from_Scalar(ec, n)
    if len(Q) != 3:
        raise ValueError("input point not in Jacobian coordinates")

    if Q[2] == 0: # Infinity point in Jacobian coordinates
        return 1, 1, 0
    R = 1, 1, 0   # initialize as infinity point
    while n > 0:  # use binary representation of n
        if n & 1: # if least significant bit is 1 then add current Q
            R = ec.pointAddJacobian(R, Q)
        n = n>>1  # right shift removes the bit just accounted for
                  # double Q for next step:
        Q = ec.pointAddJacobian(Q, Q)
    return R

def DoubleScalarMultiplication(ec: EllipticCurve,
                               k1: Scalar,
                               Q1: GenericPoint,
                               k2: Scalar,
                               Q2: GenericPoint) -> Point:
    """Shamir trick for efficient computation of k1*Q1 + k2*Q2"""

    r1 = int_from_Scalar(ec, k1)
    Q1 = to_Point(ec, Q1)
    R1 = jac_from_affine(Q1)

    r2 = int_from_Scalar(ec, k2)
    Q2 = to_Point(ec, Q2)
    R2 = jac_from_affine(Q2)

    if R1[2] == 0:
        R = pointMultiplyJacobian(ec, r2, R2)
    elif R2[2] == 0:
        R = pointMultiplyJacobian(ec, r1, R1)
    else:
        R = 1, 1, 0 # initialize as infinity point
        msb = max(r1.bit_length(), r2.bit_length())
        while msb > 0:
            if r1 >> (msb - 1): # checking msb
                R = ec.pointAddJacobian(R, R1)
                r1 -= pow(2, r1.bit_length() - 1)
            if r2 >> (msb - 1): # checking msb
                R = ec.pointAddJacobian(R, R2)
                r2 -= pow(2, r2.bit_length() - 1)
            if msb > 1:
                R = ec.pointAddJacobian(R, R)
            msb -= 1

    return ec.affine_from_jac(R)

def secondGenerator(ec: EllipticCurve,
                    Hash = sha256) -> Point:
    """ Function needed to construct a suitable Nothing-Up-My-Sleeve (NUMS) 
    generator H wrt G. 

    source: https://github.com/ElementsProject/secp256k1-zkp/blob/secp256k1-zkp/src/modules/rangeproof/main_impl.h
    idea: (https://crypto.stackexchange.com/questions/25581/second-generator-for-secp256k1-curve)
    Possible to accomplish it by using the cryptographic hash of G 
    to pick H. Then coerce the hash to a point:
    as just hashing the point could possibly result not in obtaining 
    a curvepoint, keep on incrementing the hash of the x-coordinate 
    until you get a valid curve point H = (hx, hy).
    """
    G_bytes = bytes_from_Point(ec, ec.G, False)
    h = Hash(G_bytes).digest() 
    hx = int_from_Scalar(ec, h)
    isCurvePoint = False
    while not isCurvePoint:
        try:
            hy = ec.yOdd(hx, False)
            isCurvePoint = True
        except:
            hx += 1
    return hx, hy

# http://www.secg.org/sec2-v2.pdf
__p = 2**160 - 2**31 - 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
__b = 0x1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45
__Gx = 0x4A96B5688EF573284664698968C38BB913CBFC82
__Gy = 0x23A628553168947D59DCC912042351377AC5FB32
__n = 0x0100000000000000000001F4C8F927AED3CA752257
secp160r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**192 - 2**32 - 2**12 - 2**8 - 2**7 - 2**6 - 2**3 - 1
__a = 0
__b = 3
__Gx = 0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D
__Gy = 0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D
secp192k1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**192 - 2**64 - 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
__b = 0X64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1
__Gx = 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
__Gy = 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831
secp192r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**224 - 2**32 - 2**12 - 2**11 - 2**9 - 2**7 - 2**4 - 2 - 1
__a = 0
__b = 5
__Gx    = 0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C
__Gy    = 0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5
__n = 0x010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7
secp224k1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**224 - 2**96 + 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
__b = 0XB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
__Gx    = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
__Gy    = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
secp224r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

# bitcoin curve
__p = 2**256 - 2**32 - 977
__a = 0
__b = 7
__Gx    = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
__Gy    = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
secp256k1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**256 - 2**224 + 2**192 + 2**96 - 1
__a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
__b = 0X5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
__Gx    = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
__Gy    = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
__n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
secp256r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**384 - 2**128 - 2**96 + 2**32 - 1
__a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
__b = 0XB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
__Gx    = 0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
__Gy    = 0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
__n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
secp384r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

__p = 2**521 - 1
__a = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
__b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
__Gx    = 0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
__Gy    = 0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
__n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
secp521r1 = EllipticCurve(__p, __a, __b, (__Gx, __Gy), __n)

SEC_curves = [
    secp160r1,
    secp192k1, secp192r1, secp224k1, secp224r1,
    secp256k1, secp256r1, secp384r1, secp521r1
]
