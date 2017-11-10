# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo
"""

### imports

from hashlib import sha256
from base58 import b58decode_check, __chars as b58digits
from secp256k1 import pointAdd, pointMultiply, \
                      order as ec_order, prime as ec_prime, G as ec_G, \
                      a as ec_a, b as ec_b
from FiniteFields import modInv, modular_sqrt
from string import hexdigits
from rfc6979 import deterministic_generate_k, deterministic_generate_k_raw


### checks
         
def check_ec_str(ec_str):
    assert all(c in hexdigits for c in ec_str), "an EC point in string must have only hex digits"
    assert len(ec_str) in (66,130), "an EC point in string must have 66 or 130 hex digits"
    assert ec_str[:2] in ("02","03","04"), "an EC point in string must start with 02, 03 or 04"
    
def check_ec_point(ec_point):
    assert type(ec_point) == tuple and \
           len(ec_point) == 2 and \
           type(ec_point[0]) == int and type(ec_point[1]) == int, \
           "ec_point must be a tuple of 2 int"
    assert 0 < ec_point[0] and ec_point[0] < ec_prime and \
           0 < ec_point[1] and ec_point[1] < ec_prime, \
           "ec_point must have integer coordinates in [0, ec_prime)"
    assert (ec_point[1]**2 % ec_prime) == \
           (ec_point[0]**3 + ec_a * ec_point[0] + ec_b) % ec_prime, \
           "ec_point must satisfy the curve equation"

def check_dsasig_format(dsasig):
    assert type(dsasig) == tuple and \
           len(dsasig) == 2 and \
           type(dsasig[0]) == int and type(dsasig[1]) == int, \
           "dsasig must be a tuple of 2 int"
    assert 0 < dsasig[0] and dsasig[0] < ec_order and \
           0 < dsasig[1] and dsasig[1] < ec_order, \
           "dsasig must have coordinates in (0, order)"

def check_ssasig_format(ssasig):
    assert type(ssasig) == tuple and \
           len(ssasig) == 3 and \
           type(ssasig[0]) == int and type(ssasig[1]) == int and type(ssasig[2]) == int, \
           "ssasig must be a tuple of 3 int"
    assert ssasig[0] in (0,1), "ssasig 1st element must be 0 or 1"
    assert 0 < ssasig[1] and ssasig[1] < ec_prime, "ssasig 2nd element must be in (0, prime)" 
    assert 0 < ssasig[2] and ssasig[2] < ec_order, "ssasig 3rd element must be in (0, order)" 


### decodes

def decode_prv(prv):
    assert type(prv) in (str, bytes, int), "private key should be a string, bytes or int"
    if type(prv) == str:
        if prv[:2] == "0x": prv = prv[2:]
        if all(c in hexdigits for c in prv) and len(prv) == 64: prv = int(prv, 16) # hex
        elif all(c in b58digits for c in prv): prv = b58decode_check(prv)[2:] # Wif
        # may it happen that a str may represent both a wif and a hex?
        # should check in a better way, e.g. wif starts with a key
        else: assert 0, "if private key is a string, it must be hex or Wif"
    if type(prv) == bytes: prv = int.from_bytes(prv, "big")
    assert 0 < prv and prv < ec_order, "private key must be between 1 and "+ str(ec_order - 1)
    return prv
    
def decode_pub(pub):
    if type(pub) == str: pub = str_to_ec_point(pub)
    # if type(pub) == bytes: (what I accept as valid ?? )
    check_ec_point(pub)
    return pub


# ec manipulations

def ec_point_x_to_y(x, y_mod_2):
    assert type(x) == int, "x must be an int"
    assert 0 < x and x < ec_prime, "ec_point must have integer coordinates in [0, ec_prime)"
    y = modular_sqrt((x**3 + ec_a * x + ec_b) % ec_prime, ec_prime)
    check_ec_point((x, y)) # eventually check only y!=0
    change_parity = ((y % 2) + y_mod_2) == 1
    return (ec_prime - y) if change_parity else y
    
def str_to_ec_point(ec_str):
    check_ec_str(ec_str)
    if ec_str[:2] == "04": 
        return (int(ec_str[2:66], 16), int(ec_str[66:], 16))
    else:
        x = int(ec_str[2:], 16)
        y = ec_point_x_to_y(x, 0 if ec_str[:2] == "02" else 1)
        return x, y
    
def ec_point_to_bytes(ec_point, compressed = True):
    check_ec_point(ec_point)
    if compressed: return (b'\x02' if ec_point[1] % 2 == 0 else b'\x03') + ec_point[0].to_bytes(32, "big")
    else: return b'\x04' + ec_point[0].to_bytes(32, "big") + ec_point[1].to_bytes(32, "big")
# the EC points are forced to be 32 bytes long. Can they be shorter?    
def ec_point_to_str(ec_point, compressed = True):
    check_ec_point(ec_point)
    if compressed: return ("02" if ec_point[1] % 2 == 0 else "03") + hex(ec_point[0])[2:]
    else: return "04" + hex(ec_point[0])[2:] + hex(ec_point[1])[2:]
# ec_point_to_bytes((3, ec_point_x_to_y(3, 1))) gives opinable results


### hash manipulations

def dsha256(inp_bytes):
    return sha256(sha256(inp_bytes).digest())

def hash_to_int(h):
    h_len = h.digest_size * 8
    L_n = ec_order.bit_length() # use the L_n leftmost bits of the hash
    n = (h_len - L_n) if h_len >= L_n else 0
    return int.from_bytes(h.digest(), "big") >> n

def str_to_hash(string, hasher):
    assert type(string) == str
    return hasher(string.encode())


### ecdsa sign

def ecdsa_sign(msg, prv, eph_prv = None, hasher = sha256):
    hashmsg = str_to_hash(msg, hasher)
    prv = decode_prv(prv)
    if eph_prv != None: eph_prv = decode_prv(eph_prv)
    return ecdsa_sign_raw(hashmsg, prv, eph_prv)
    # return the sign in a different way? (like vbuterin)
    
def ecdsa_sign_raw(hashmsg, prv, eph_prv = None):
    h = hash_to_int(hashmsg)
    if eph_prv == None: 
        eph_prv = deterministic_generate_k_raw(prv, hashmsg, hasher = sha256)
    R = pointMultiply(eph_prv, ec_G)
    r = R[0] % ec_order
    s = modInv(eph_prv, ec_order) * (h + prv * r) % ec_order
    assert r != 0 and s != 0, "failed to sign" # this should be checked inside deterministic_generate_k
    return r, s
    
def ecdsa_verify(msg, dsasig, pub, hasher = sha256):
    hashmsg = str_to_hash(msg, hasher)
    pub = decode_pub(pub) 
    check_dsasig_format(dsasig)
    return ecdsa_verify_raw(hashmsg, dsasig, pub)

def ecdsa_verify_raw(hashmsg, dsasig, pub):
    h = hash_to_int(hashmsg)
    s1 = modInv(dsasig[1], ec_order)
    if h != 0:
        R_recomputed = pointAdd(pointMultiply(h * s1 % ec_order, ec_G),
                                pointMultiply(dsasig[0] * s1 % ec_order, pub))
    else:
        R_recomputed = pointMultiply(dsasig[0] * s1 % ec_order, pub)
    return dsasig[0] == R_recomputed[0] % ec_order

def ecdsa_recover(msg, dsasig, y_mod_2, hasher = sha256):
    hashmsg = str_to_hash(msg, hasher)
    check_dsasig_format(dsasig)
    assert y_mod_2 in (0, 1)
    return ecdsa_recover_raw(hashmsg, dsasig, y_mod_2)
    
def ecdsa_recover_raw(hashmsg, dsasig, y_mod_2):
    h = hash_to_int(hashmsg)
    r1 = modInv(dsasig[0], ec_order)
    R = (dsasig[0], ec_point_x_to_y(dsasig[0], y_mod_2))
    if h != 0: 
        return pointAdd(pointMultiply(-h * r1 % ec_order, ec_G), \
                        pointMultiply(dsasig[1] * r1 % ec_order, R))
    else: return pointMultiply(dsasig[1] * r1 % ec_order, R)


### ecssa sign

# REMARK:
# ecssa_sign use h=(msg||R) so the hashmsg cannot be generated 
# if the eph_prv or R are not known!

# k = h_rfc6979(msg||prv)
# ! msg is not the hashmsg that is signed!

def ecssa_sign(msg, prv, eph_prv = None, hasher = sha256):
    assert type(msg) == str
    prv = decode_prv(prv)
    if eph_prv == None: 
        eph_prv = deterministic_generate_k(prv, msg)
    else:
        eph_prv = decode_prv(eph_prv)
    R = pointMultiply(eph_prv, ec_G)
    hashmsg = str_to_hash(msg + ec_point_to_str(R), hasher)
    return ecssa_sign_raw(hashmsg, prv, eph_prv)

def ecssa_sign_raw(hashmsg, prv, eph_prv):
    h = hash_to_int(hashmsg)
    assert h != 0, "invalid message, hash of msg cannot be 0"
    R = pointMultiply(eph_prv, ec_G)
    r, y = R[0], R[1] % 2
    s = (eph_prv - h * prv) % ec_order                            
    assert r != 0 and s != 0, "failed to sign" # this should be checked inside deterministic_generate_k
    return y, r, s

def ecssa_verify(msg, ssasig, pub, hasher = sha256):
    check_ssasig_format(ssasig)
    R = (ssasig[1], ec_point_x_to_y(ssasig[1], ssasig[0]))
    hashmsg = str_to_hash(msg + ec_point_to_str(R), hasher)
    pub = decode_pub(pub)
    return ecssa_verify_raw(hashmsg, ssasig, pub)

def ecssa_verify_raw(hashmsg, ssasig, pub):
    h = hash_to_int(hashmsg)
    assert h != 0, "hash of msg must be != 0"
    R = (ssasig[1], ec_point_x_to_y(ssasig[1], ssasig[0]))
    return R == pointAdd(pointMultiply(ssasig[2], ec_G),
                         pointMultiply(h % ec_order, pub))

# R = kG; h = hash(msg||R)
# s = k - h*prv <=> sG = R - hP <=> hP = R - sG <=> P = (R - sG)*h^-1
def ecssa_recover(msg, ssasig, hasher = sha256):
    R = (ssasig[1], ec_point_x_to_y(ssasig[1], ssasig[0]))
    hashmsg = str_to_hash(msg + ec_point_to_str(R), hasher)
    check_ssasig_format(ssasig)
    return ecssa_recover_raw(hashmsg, ssasig)

def ecssa_recover_raw(hashmsg, ssasig):
    h = hash_to_int(hashmsg)
    assert h != 0, "invalid message, hash of msg cannot be 0"
    h1 = modInv(h, ec_order)    
    R = (ssasig[1], ec_point_x_to_y(ssasig[1], ssasig[0]))
    return pointAdd(pointMultiply(h1, R),
                    pointMultiply(-h1 * ssasig[2] % ec_order, ec_G))    


### sign to contract

def check_receipt(receipt):
    assert type(receipt[0]) == int and \
           0 < receipt[0] and receipt[0] < ec_prime, \
           "1st part of the receipt must be an int in (0, ec_prime)"
    check_ec_point(receipt[1])

def ecdsa_sign_and_commit(msg, prv, commit, eph_prv = None, hasher = sha256):
    hashmsg = str_to_hash(msg, hasher)
    prv = decode_prv(prv)
    if eph_prv == None: 
        eph_prv = deterministic_generate_k_raw(prv, hashmsg, sha256)
    else: 
        eph_prv = decode_prv(eph_prv)
    R = pointMultiply(eph_prv, ec_G)
    e = hash_to_int(str_to_hash(commit + ec_point_to_str(R), hasher))
    eph_prv = (eph_prv + e) % ec_order
    sig = ecdsa_sign_raw(hashmsg, prv, eph_prv)
    receipt = (sig[0], R)
    return sig, receipt

def ecssa_sign_and_commit(msg, prv, commit, eph_prv = None, hasher = sha256):
    prv = decode_prv(prv)
    if eph_prv == None: 
        eph_prv = deterministic_generate_k(prv, msg, sha256)
    else: 
        eph_prv = decode_prv(eph_prv)
    R = pointMultiply(eph_prv, ec_G)
    e = hash_to_int(str_to_hash(commit + ec_point_to_str(R), hasher))
    eph_prv = (eph_prv + e) % ec_order
    W = pointMultiply(eph_prv, ec_G)
    hashmsg = str_to_hash(msg + ec_point_to_str(W), hasher)
    sig = ecssa_sign_raw(hashmsg, prv, eph_prv)
    receipt = (sig[1], R)
    return sig, receipt
    
def ec_verify_commit(receipt, commit, hasher = sha256):
    check_receipt(receipt)
    e_recomputed = hash_to_int(str_to_hash(commit + ec_point_to_str(receipt[1]), hasher))
    W_recomputed = pointAdd(receipt[1], pointMultiply(e_recomputed, ec_G))
    return receipt[0] == W_recomputed[0] % ec_order


### tests

def test_sign():
    print("\n std sign with ecdsa")
    msg = "hello world"
    prv = 1
    r, s = ecdsa_sign(msg, prv)
    pub = pointMultiply(prv, ec_G)
    assert ecdsa_verify(msg, (r, s), pub), "invalid ecdsa sig"
    # pubkey recover
    assert pub in (ecdsa_recover(msg, (r,s), 0), ecdsa_recover(msg, (r,s), 1))
    # sign and commit
    commit = "sign to contract"
    dsasig_commit, receipt = ecdsa_sign_and_commit(msg, prv, commit)
    assert ecdsa_verify(msg, dsasig_commit, pub), "invalid sig"
    assert ec_verify_commit(receipt, commit), "invalid commit"
    print("\n std sign with ecssa")
    y, r, s = ecssa_sign(msg, prv)
    assert ecssa_verify(msg, (y, r, s), pub), "invalid ecssa sig"
    # pubkey recover
    assert pub == ecssa_recover(msg, (y, r, s)), "pubkey recover failed"
    # sign and commit
    ssasig_commit, receipt = ecssa_sign_and_commit(msg, prv, commit)
    assert ecssa_verify(msg, ssasig_commit, pub), "invalid sig"
    assert ec_verify_commit(receipt, commit), "invalid commit"
    # some more tests should be done!

# test_sign()