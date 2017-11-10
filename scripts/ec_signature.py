# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo
"""

# import - check - decode - from/to ec_point - from/to int
# ecdsa - ecssa - sign-to-contract - test

# %% import

from hashlib import sha256
from base58 import b58decode_check, __chars as b58digits
from secp256k1 import pointAdd, pointMultiply, \
                      order as ec_order, prime as ec_prime, G as ec_G, \
                      a as ec_a, b as ec_b
from FiniteFields import modInv, modular_sqrt
from string import hexdigits
from rfc6979 import deterministic_generate_k, deterministic_generate_k_raw


# %% check
         
def check_ec_str(ec_str):
    assert all(c in hexdigits for c in ec_str), \
           "an EC point in string must have only hex digits"
    assert (0 < len(ec_str) and len(ec_str) % 2 == 0 and len(ec_str) <= 66) \
           or len(ec_str) == 130, \
           "an EC point in string must have 2, 4, 6, ..., 66, or 130 hex digits"
    assert ec_str[:2] in ("02","03","04"), \
           "an EC point in string must start with 02, 03 or 04"
    
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

def check_dsasig(dsasig):
    assert type(dsasig) == tuple and \
           len(dsasig) == 2 and \
           type(dsasig[0]) == int and type(dsasig[1]) == int, \
           "dsasig must be a tuple of 2 int"
    assert 0 < dsasig[0] and dsasig[0] < ec_order and \
           0 < dsasig[1] and dsasig[1] < ec_order, \
           "r and s must be in [1..order]"

def check_ssasig(ssasig):
    assert type(ssasig) == tuple and len(ssasig) == 2 and \
           type(ssasig[0]) == int and type(ssasig[1]) == int, \
           "ssasig must be a tuple of 2 int"
    assert 0 < ssasig[0] and ssasig[0] < ec_prime, "R.x must be in [1..prime]"
    assert 0 < ssasig[1] and ssasig[1] < ec_order, "s must be in [1..order]"
    

# %% decode

def decode_prv(prv):
    assert type(prv) in (str, bytes, int), "private key should be a string, bytes or int"
    if type(prv) == str:
        if prv[:2] == "0x": prv = prv[2:]
        if all(c in hexdigits for c in prv) and len(prv) == 64: prv = int(prv, 16) # hex
        elif all(c in b58digits for c in prv): prv = b58decode_check(prv)[2:] # Wif
        # may it happen that a str may represent both a wif and a hex?
        # should check in a better way, e.g. wif starts with a digit
        else: assert 0, "if private key is a string, it must be hex or Wif"
    if type(prv) == bytes: prv = int.from_bytes(prv, "big")
    assert 0 < prv and prv < ec_order, "private key must be between 1 and "+ str(ec_order - 1)
    return prv
    
def decode_pub(pub):
    assert type(pub) in (str, bytes, tuple), "invalid format for ec_point"
    if type(pub) == str: pub = str_to_ec_point(pub)
    if type(pub) == bytes: pub = bytes_to_ec_point(pub)
    check_ec_point(pub)
    return pub

def decode_msg(msg):
    assert type(msg) in (str, bytes), "msg must be string or bytes"
    if type(msg) == str: msg = msg.encode()
    return msg


# %% from/to ec_point

def ec_x_to_y(x, y_mod_2):
    assert type(x) == int, "x must be an int"
    assert 0 < x and x < ec_prime, "ec_point must have integer coordinates in [0, ec_prime)"
    y = modular_sqrt((x**3 + ec_a * x + ec_b) % ec_prime, ec_prime)
    check_ec_point((x, y)) # <=> y!=0
    change_parity = ((y % 2) + y_mod_2) == 1
    return (ec_prime - y) if change_parity else y
    
def str_to_ec_point(ec_str):
    check_ec_str(ec_str)
    if ec_str[:2] == "04": 
        return (int(ec_str[2:66], 16), int(ec_str[66:], 16))
    else:
        x = int(ec_str[2:], 16)
        y = ec_x_to_y(x, 0 if ec_str[:2] == "02" else 1)
        return x, y
    
def bytes_to_ec_point(b):
    assert type(b) == bytes and len(b) > 0
    assert b[0] in (2, 3, 4), "pubkey must start with 02, 03 or 04"
    if b[0] == 4:
        assert len(b) == 65, "ext pubkey has 65 bytes" 
        # otherwise it is impossible to understand when the second coord starts
        return (int.from_bytes(b[1:33], "big"), int.from_bytes(b[33:], "big"))
    else:
        x = int.from_bytes(b[1:], "big")
        return (x, ec_x_to_y(x, 0 if b[0] == 2 else 1))        

def ec_point_to_bytes(ec_point, compressed = True):
    check_ec_point(ec_point)
    if compressed: 
        return (b'\x02' if ec_point[1] % 2 == 0 else b'\x03') + \
               int_to_bytes(ec_point[0])
    else: 
        return b'\x04' + int_to_bytes(ec_point[0], 32) + int_to_bytes(ec_point[0], 32)


# %% from/to int

def hash_to_int(h):
    h_len = h.digest_size * 8
    L_n = ec_order.bit_length() # use the L_n leftmost bits of the hash
    n = (h_len - L_n) if h_len >= L_n else 0
    return int.from_bytes(h.digest(), "big") >> n
    
def int_to_bytes(n, byte_len = None):
    if byte_len == None: byte_len = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_len, "big")


# %% ecdsa sign

def ecdsa_sign(msg, prv, eph_prv = None, hasher = sha256):
    msg = decode_msg(msg)
    prv = decode_prv(prv)
    if eph_prv == None: eph_prv = deterministic_generate_k(prv, msg)
    else: eph_prv = decode_prv(eph_prv)
    hashmsg = hasher(msg).digest()
    return ecdsa_sign_raw(hashmsg, prv, eph_prv, hasher)
    # return the sign in a different way? (like vbuterin)
    
def ecdsa_sign_raw(hashmsg, prv, eph_prv, hasher):
    h = hash_to_int(hasher(hashmsg))
    if eph_prv == None: eph_prv = deterministic_generate_k_raw(prv, hashmsg, hasher)
    R = pointMultiply(eph_prv, ec_G)
    r = R[0] % ec_order
    s = modInv(eph_prv, ec_order) * (h + prv * r) % ec_order
    assert r != 0 and s != 0, "failed to sign" # this should be checked inside deterministic_generate_k
    return r, s

def ecdsa_verify(msg, dsasig, pub, hasher = sha256):
    msg = decode_msg(msg)
    check_dsasig(dsasig)
    pub = decode_pub(pub)
    hashmsg = hasher(msg).digest()
    return ecdsa_verify_raw(hashmsg, dsasig, pub, hasher)

def ecdsa_verify_raw(hashmsg, dsasig, pub, hasher):
    h = hash_to_int(hasher(hashmsg)) 
    r, s = dsasig
    s1 = modInv(s, ec_order)
    add1 = pointMultiply(r * s1 % ec_order, pub)
    if h != 0: 
        add2 = pointMultiply(h * s1 % ec_order, ec_G)
        assert add1[0] != add2[0]
        R_rec = pointAdd(add1, add2)
    else:
        R_rec = add1
    return R_rec[0] == r

def ecdsa_recover(msg, dsasig, y_mod_2, hasher = sha256):
    msg = decode_msg(msg)
    check_ssasig(dsasig)
    assert y_mod_2 in (0, 1)
    hashmsg = hasher(msg).digest()
    return ecdsa_recover_raw(hashmsg, dsasig, y_mod_2, hasher)

def ecdsa_recover_raw(hashmsg, dsasig, y_mod_2, hasher):
    r, s = dsasig
    h = hash_to_int(hasher(hashmsg))
    r1 = modInv(r, ec_order)
    R = (r, ec_x_to_y(r, y_mod_2))
    add1 = pointMultiply(dsasig[1] * r1 % ec_order, R) 
    if h!= 0:
        add2 = pointMultiply(-h * r1 % ec_order, ec_G)
        assert add1[0] != add2[0], "fail, the recovered pubkey is the point at infinity"
        return pointAdd(add1, add2)
    else:
        return add1


# %% ecssa sign
# source:
# https://github.com/sipa/secp256k1/blob/968e2f415a5e764d159ee03e95815ea11460854e/src/modules/schnorr/schnorr.md

def ecssa_sign(msg, prv, eph_prv = None, hasher = sha256):
    msg = decode_msg(msg)
    prv = decode_prv(prv)
    if eph_prv == None: eph_prv = deterministic_generate_k(prv, msg)
    else: eph_prv = decode_prv(eph_prv)
    hashmsg = hasher(msg).digest()
    return ecssa_sign_raw(hashmsg, prv, eph_prv, hasher)

def ecssa_sign_raw(hashmsg, prv, eph_prv, hasher):
    R = pointMultiply(eph_prv, ec_G)
    if R[1] % 2 == 1: 
        eph_prv = ec_order - eph_prv # <=> R_y = ec_prime - R_y
    R_x = int_to_bytes(R[0], 32)
    e = hash_to_int(hasher(R_x + hashmsg))
    assert e != 0 and e < ec_order, "sign fail"
    s = (eph_prv - e*prv) % ec_order
    return R[0], s

def ecssa_verify(msg, ssasig, pub, hasher = sha256):
    msg = decode_msg(msg)
    check_ssasig(ssasig)
    pub = decode_pub(pub)
    hashmsg = hasher(msg).digest()
    return ecssa_verify_raw(hashmsg, ssasig, pub, hasher)

def ecssa_verify_raw(hashmsg, ssasig, pub, hasher):
    R_x, s = int_to_bytes(ssasig[0], 32), ssasig[1]
    e = hash_to_int(hasher(R_x + hashmsg))
    assert e != 0 and e < ec_order, "sign fail, invalid e value"
    add1, add2 = pointMultiply(e, pub), pointMultiply(s, ec_G)
    assert add1[0] != add2[0], "sign fail, point at infinity"
    R_rec = pointAdd(add1, add2)
    assert R_rec[1] % 2 == 0, "sign fail, R.y odd"
    return R_rec[0] == ssasig[0]

def ecssa_recover(msg, ssasig, hasher = sha256):
    msg = decode_msg(msg)
    check_ssasig(ssasig)
    hashmsg = hasher(msg).digest()
    return ecssa_recover_raw(hashmsg, ssasig, hasher)

def ecssa_recover_raw(hashmsg, ssasig, hasher):
    R_x, s = ssasig
    R = (R_x, ec_x_to_y(R_x, 0))
    R_x = int_to_bytes(R_x, 32)
    e = hash_to_int(hasher(R_x + hashmsg))
    assert e != 0 and e < ec_order, "invalid e value"
    e1 = modInv(e, ec_order)
    add1, add2 = pointMultiply(e1, R), pointMultiply(-e1 * s % ec_order, ec_G)
    assert add1[0] != add2[0], "fail, pub is the point at infinity"
    return pointAdd(add1, add2)

# %% sign to contract
# IDEA: 
#    insert a commitment in a signature (singing something else!)
#    using this valid commitment operation:
#    R -> hash(R||c)G + R  (R ec point, G generator, c commit)
# HOW: 
#    when you sign you generate a nonce (k) and compute a ec point (R = kG)
#    instead of proceeding using (k,R) you compute a value (e) that embed the 
#    commitment: e = hash(R.x||commit)
#    you substitute the nonce with k+e and R with R+eG, and proceed signing
#    in the standard way using instead (k+e,R+eG)
# VERIFICATION: 
#    the verifier can see W.x (W = R+eG) on the signature
#    the signer (and committer) provides R and commit
#    the verifier checks that:   W.x = (R+eG).x  
#                               (with e = hash(R.x||commit))

def check_receipt(receipt):
    assert type(receipt[0]) == int and \
           0 < receipt[0] and receipt[0] < ec_prime, \
           "1st part of the receipt must be an int in (0, ec_prime)"
    check_ec_point(receipt[1])

def ecdsa_sign_and_commit(msg, prv, commit, eph_prv = None, hasher = sha256):
    msg = decode_msg(msg)
    prv = decode_prv(prv)
    if eph_prv == None: eph_prv = deterministic_generate_k(prv, msg)
    else: eph_prv = decode_prv(eph_prv)
    hashmsg = hasher(msg).digest()
    # insert the commit in the ec_point
    commit = decode_msg(commit)
    R = pointMultiply(eph_prv, ec_G)
    R_x = int_to_bytes(R[0], 32)
    e = hash_to_int(hasher(R_x + commit))
    eph_prv = (eph_prv + e) % ec_order
    sig = ecdsa_sign_raw(hashmsg, prv, eph_prv, hasher)
    receipt = (sig[0], R)
    return sig, receipt

def ecssa_sign_and_commit(msg, prv, commit, eph_prv = None, hasher = sha256):
    msg = decode_msg(msg)
    prv = decode_prv(prv)
    if eph_prv == None: eph_prv = deterministic_generate_k(prv, msg)
    else: eph_prv = decode_prv(eph_prv)
    hashmsg = hasher(msg).digest()
    # insert the commit in the ec_point
    commit = decode_msg(commit)
    R = pointMultiply(eph_prv, ec_G)
    R_x = int_to_bytes(R[0], 32)
    e = hash_to_int(hasher(R_x + commit))
    eph_prv = (eph_prv + e) % ec_order
    sig = ecssa_sign_raw(hashmsg, prv, eph_prv, hasher)
    receipt = (sig[0], R)
    return sig, receipt
    
def ec_verify_commit(receipt, commit, hasher = sha256):
    check_receipt(receipt)
    commit = decode_msg(commit)
    R_x = int_to_bytes(receipt[1][0], 32)
    e_rec = hash_to_int(hasher(R_x + commit))
    W_rec = pointAdd(receipt[1], pointMultiply(e_rec, ec_G))
    return receipt[0] == W_rec[0] % ec_order


# %% tests

def test_all(ecdsa = True, ecssa = True, \
             verify = True, recover = True, verify_commit = True):
    msg = "hello world"
    prv = 1
    commit = "sign to contract"
    param = msg, prv, commit
    if ecdsa:
        test_ecdsa(param, verify, recover, verify_commit)
    if ecssa:
        test_ecssa(param, verify, recover, verify_commit)

def test_ecdsa(param, verify = True, recover = True, verify_commit = True):
    print("*** testing ecdsa")
    msg, prv, commit = param
    sig = ecdsa_sign(msg, prv)
    pub = pointMultiply(prv, ec_G)
    if verify: 
        assert ecdsa_verify(msg, sig, pub), "invalid sig"
    if recover: 
        assert pub in (ecdsa_recover(msg, sig, 0), ecdsa_recover(msg, sig, 1)),\
        "the recovered pubkey is not correct"
    if verify_commit:
        sig_commit, receipt = ecdsa_sign_and_commit(msg, prv, commit)
        assert ecdsa_verify(msg, sig_commit, pub), "sig verification failed"
        assert ec_verify_commit(receipt, commit), "commit verification failed"
    print("ecdsa tests passed")

def test_ecssa(param, verify = True, recover = True, verify_commit = True):
    print("*** testing ecssa")
    msg, prv, commit = param
    sig = ecssa_sign(msg, prv)
    pub = pointMultiply(prv, ec_G)
    if verify: 
        assert ecssa_verify(msg, sig, pub), "invalid sig"
    if recover: 
        assert pub == ecssa_recover(msg, sig), \
        "the recovered pubkey is not correct"
    if verify_commit:
        sig_commit, receipt = ecssa_sign_and_commit(msg, prv, commit)
        assert ecssa_verify(msg, sig_commit, pub), "sig verification failed"
        assert ec_verify_commit(receipt, commit), "commit verification failed"
    print("ecssa tests passed")