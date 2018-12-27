#!/usr/bin/env python3

import os
from hashlib import sha256
from typing import List, Dict
from btclib.ellipticcurves import secp256k1 as ec, Scalar, Tuple, \
                                  pointMultiply, DoubleScalarMultiplication, \
                                  bytes_from_Point, to_Point, \
                                  int_from_Scalar, bytes_from_Scalar
from btclib.ecsignutils import int_from_hash

Signature = Tuple[bytes, ...]

# source: https://github.com/ElementsProject/borromean-signatures-writeup

def borromean_hash(msg: bytes,
                   R: bytes,
                   i: int,
                   j: int) -> bytes:
    temp = msg + R + i.to_bytes(4, 'big') + j.to_bytes(4, 'big')
    return sha256(temp).digest()

def get_msg_format(msg: bytes,
                   pubk_rings: Dict[int,
                   List[bytes]]) -> bytes:
    hash_argument = msg
    for i in range(len(pubk_rings)):
        for j in range(len(pubk_rings[i])):
            if type(pubk_rings[i][j]) != bytes: pubk_rings[i][j] = bytes_from_Point(ec, pubk_rings[i][j], True)
            hash_argument += pubk_rings[i][j]
    return sha256(hash_argument).digest()

def borromean_sign(msg: bytes,
                   sign_key_idx: List[int],
                   sign_keys: List[Scalar],
                   pubk_rings: Dict[int,
                   List[bytes]]) -> Signature:
    """ Borromean ring signature - signing algorithm

    inputs:
    - msg: msg to be signed (bytes)
    - sign_key_idx: list of indexes representing each signing key per ring
    - sign_keys: list containing the whole set of signing keys (one per ring)
    - pubk_rings: dictionary of lists where internal lists represent single rings of pubkeys
    """
    ring_number = len(pubk_rings)
    # step 1
    m = get_msg_format(msg, pubk_rings)
    k = [int_from_Scalar(ec, os.urandom(32)) for i in range(0, ring_number)]
    sign_keys = [int_from_Scalar(ec, sign_keys[i]) for i in range(len(sign_keys))]
    s = {}
    e = {}
    last_R = m
    for i in range(0, ring_number):
        s[i] = [0]*len(pubk_rings[i])
        e[i] = [0]*len(pubk_rings[i])
        j_star = sign_key_idx[i]
        start_idx = (j_star + 1) % len(pubk_rings[i])
        R = bytes_from_Point(ec, pointMultiply(ec, k[i], ec.G), True)
        if start_idx == 0:
            last_R += R
        else:
            for j in range(start_idx, len(pubk_rings[i])):
                s[i][j] = os.urandom(32)
                e[i][j] = int_from_hash(borromean_hash(m, R, i, j), ec, sha256)
                assert e[i][j] != 0 and e[i][j] < ec.n, "sign fail"
                T = DoubleScalarMultiplication(ec, s[i][j], ec.G, ec.n - e[i][j], to_Point(ec, pubk_rings[i][j]))
                R = bytes_from_Point(ec, T, True)
            last_R += R
    e_0 = sha256(last_R).digest()
    # step 2
    for i in range(0, ring_number):
        j_star = sign_key_idx[i]
        e[i][0] = int_from_hash(borromean_hash(m, e_0, i, 0), ec, sha256)
        assert e[i][0] != 0 and e[i][0] < ec.n, "sign fail"
        for j in range(1, j_star+1):
            s[i][j-1] = os.urandom(32)
            T = DoubleScalarMultiplication(ec, s[i][j-1], ec.G, ec.n - e[i][j-1], to_Point(ec, pubk_rings[i][j-1]))
            R = bytes_from_Point(ec, T, True)
            e[i][j] = int_from_hash(borromean_hash(m, R, i, j), ec, sha256)
            assert e[i][j] != 0 and e[i][j] < ec.n, "sign fail"
        s[i][j_star] = bytes_from_Scalar(ec, k[i] + sign_keys[i]*e[i][j_star])
    return (e_0, s)

def borromean_verify(msg: bytes, e_0: bytes, s: Dict[int, List[Scalar]],\
                     pubk_rings: Dict[int, List[bytes]]) -> bool:
    """ Borromean ring signature - verification algorithm

    inputs: 
    - msg: msg to be signed (bytes)
    - e_0: pinned e-value needed to start the verification algorithm
    - s: s-values, both real (one per ring) and forged
    - pubk_rings: dictionary of lists where internal lists represent single rings of pubkeys
    """
    ring_number = len(pubk_rings)
    m = get_msg_format(msg, pubk_rings)
    e = {}
    last_R = m
    for i in range(0, ring_number):
        e[i] = [0]*len(pubk_rings[i])
        e[i][0] = int_from_hash(borromean_hash(m, e_0, i, 0), ec, sha256)
        if e[i][0] == 0 or e[i][0] >= ec.n:
            return False
        for j in range(0, len(pubk_rings[i])):
            T = DoubleScalarMultiplication(ec, s[i][j], ec.G, ec.n - e[i][j], to_Point(ec, pubk_rings[i][j]))
            R = bytes_from_Point(ec, T, True)
            if j != len(pubk_rings[i])-1:
                e[i][j+1] = int_from_hash(borromean_hash(m, R, i, j+1), ec, sha256)
                if e[i][j+1] == 0 or e[i][j+1] >= ec.n:
                    return False
            else:
                last_R += R
    e_0_prime = (sha256(last_R).digest())
    return e_0_prime == e_0
    