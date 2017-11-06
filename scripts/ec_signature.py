# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo
"""

# get_valid_*** : return a valid *** and perform some checks
# check_***     : perform some assert about ***

# DOUBTS:
# in case of switching from secp256k1 to a smaller curve should priv and pub
# keys be stored in something less than 32 bytes?
# if yes how to manage that?

from hashlib import sha256
from base58 import b58decode_check
from secp256k1 import pointAdd, pointMultiply, \
                      order as ec_order, prime as ec_prime, G as ec_G, \
                      a as ec_a, b as ec_b
L_n = ec_order.bit_length()
L_n_bytes = (L_n - 1) // 8 + 1
# L_n is the bit length of the group order 
# source: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm  
# consider inserting L_n in secp256k1 
# however unuseful for secp256k1, since L_n = 256 = size of sha256 output
# but useful for some other curves parameters
from FiniteFields import modInv, modular_sqrt
#source https://stackoverflow.com/questions/11592261/check-if-a-string-is-hexadecimal/11592279#11592279
from string import hexdigits
from base58 import __chars as b58digits


def check_msg(msg):
    assert type(msg) in (str, bytes), "message must be a string or bytes"
         
def check_ec_str(ec_str):
    assert all(c in hexdigits for c in ec_str), "an EC point in string must have only hex digits"
    assert len(ec_str) in (66,130), "an EC point in string must have 66 or 130 hex digits"
    assert ec_str[:2] in ("02","03","04"), "an EC point in string must start with 02, 03 or 04"
    
def check_ec_point(ec_point):
    assert type(ec_point) == tuple and \
           len(ec_point) == 2 and \
           type(ec_point[0]) == int and type(ec_point[0]) == int, \
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
           type(dsasig[0]) == int and type(dsasig[0]) == int, \
           "dsasig must be a tuple of 2 int"
    assert 0 < dsasig[0] and dsasig[0] < ec_order and \
           0 < dsasig[1] and dsasig[1] < ec_order, \
           "dsasig must have coordinates in (0, order)"

# many doubts, should accept a format in input? 
# how i distinguish hex, wif and others?
# for consistency should I have check_prv(prv) ?
def get_valid_prv(prv):
    assert type(prv) in (str, bytes, int), "private key should be a string, bytes or int"
    if type(prv) == str:
        if prv[:2] == "0x": prv = prv[2:]
        if all(c in hexdigits for c in prv) and len(prv) == 64: prv = int(prv, 16) # hex
        elif all(c in b58digits for c in prv): prv = b58decode_check(prv)[2:] # Wif
        # may it happen that a str may represent both a wif and a hex?
        # should check in a better way, e.g. wif starts with a key
        else: assert 0, "if private key is a string, it must be hex or Wif"
    if type(prv) == bytes: prv = int.from_bytes(prv, "big")
    assert 0 < prv and prv < ec_order, "private key must be between 0 and ec_order"
    # or prv %= ec_order ??
    return prv
    
def get_valid_pub(pub):
    if type(pub) == str: pub = str_to_ec_point(pub)
    # if type(pub) == bytes: (what I accept as valid ?? )
    check_ec_point(pub)
    return pub

def determinstic_eph_prv_from_prv(prv):
    # attach a salting value? if yes why?
    eph_prv = int.from_bytes(sha256(prv.to_bytes(32, "big")).digest(), "big")
    if eph_prv == 0 or eph_prv > ec_order: 
        eph_prv = determinstic_eph_prv_from_prv(prv + 1) # is the +1 legit?
    return eph_prv

def ec_point_x_to_y(x,y_mod_2):
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
def dsha256(inp_bytes):
    return sha256(sha256(inp_bytes).digest()).digest()

def get_hash(msg, hash_type = "double256"):
    check_msg(msg)
    if type(msg) == str: msg = msg.encode()
    if hash_type == "double256": return int.from_bytes(dsha256(msg)[:L_n_bytes], "big")
    else: return int.from_bytes(sha256(msg).digest()[:L_n_bytes], "big") # does this the same job as btc core?
    
def ecdsa_sign(msg, prv, eph_prv = None):
    h = get_hash(msg)
    # should h = 0 be accepted? and h >= ec_order? 
    # should this be treated in get_hash or after?
    prv = get_valid_prv(prv)
    if eph_prv == None: eph_prv = determinstic_eph_prv_from_prv(prv)
    else: eph_prv = get_valid_prv(eph_prv)
    R = pointMultiply(eph_prv, ec_G)
    r = R[0] % ec_order
    s = modInv(eph_prv, ec_order) * (h + prv * r) % ec_order
    if r == 0 or s == 0: return ecdsa_sign(msg, prv, eph_prv + 1) # is the + 1 safe? should I check R?
    else: return r, s
    
def ecdsa_verify(msg, dsasig, pubkey):
    h = get_hash(msg)
    pubkey = get_valid_pub(pubkey) 
    check_dsasig_format(dsasig)
    s1 = modInv(dsasig[1], ec_order)
    R_recomputed = pointAdd(pointMultiply(h * s1 % ec_order, ec_G),
                            pointMultiply(dsasig[0] * s1 % ec_order, pubkey))
    return dsasig[0] == R_recomputed[0] % ec_order

def ecdsa_recover(msg, dsasig, y_mod_2):
    h = get_hash(msg)
    check_dsasig_format(dsasig)
    assert y_mod_2 in (0, 1)
    r1 = modInv(dsasig[0], ec_order)
    R = (dsasig[0], ec_point_x_to_y(dsasig[0], y_mod_2))
    if h != 0: return pointAdd(pointMultiply(-h * r1 % ec_order, ec_G), \
                               pointMultiply(dsasig[1] * r1 % ec_order, R))
    else: return pointMultiply(dsasig[1] * r1 % ec_order, R)

# ---------------------- sign-to-contract

def check_receipt(receipt):
    assert type(receipt[0]) == int and \
           0 < receipt[0] and receipt[0] < ec_prime, \
           "1st part of the receipt must be an int in (0, ec_prime)"
    check_ec_point(receipt[1])
    
def ecdsa_sign_and_commit(msg, prv, commit, eph_prv = None):
    h = get_hash(msg)
    prv = get_valid_prv(prv)
    if eph_prv == None: eph_prv = determinstic_eph_prv_from_prv(prv)
    else: eph_prv = get_valid_prv(eph_prv)
    R = pointMultiply(eph_prv, ec_G)
    assert type(commit) == str, "Commit should be a string" # or as bytes?
    e = get_hash(commit + ec_point_to_str(R, compressed = True))
    eph_prv = get_valid_prv((eph_prv + e) % ec_order) # could be 0
    W = pointMultiply(eph_prv, ec_G)
    w = W[0] % ec_order
    s = modInv(eph_prv, ec_order) * (h + prv * w) % ec_order
    if w == 0 or s == 0: sig = ecdsa_sign_and_commit(msg, prv, eph_prv + 1) # is this safe?
    else: sig = (w, s)
    receipt = (w, R)
    return sig, receipt
    
def ec_verify_commit(receipt, commit):
    check_receipt(receipt)
    e_recomputed = get_hash(commit + ec_point_to_str(receipt[1], compressed = True))
    W_recomputed = pointAdd(receipt[1], pointMultiply(e_recomputed, ec_G))
    return receipt[0] == W_recomputed[0] % ec_order

# ---------------------- ssa
# mimimal changes w.r.t. ecdsa, but I have still some doubts
# 1. h = hash(msg||pubkey) as on https://en.wikipedia.org/wiki/Schnorr_signature
#    or the hash can be computed as in ECDSA (h = hash(msg)) 
#    motivate the choice
# 2. the sig should include the parity of the eph pub key? how?
# 3. s = eph_prv - h*prv   or    s = eph_prv + h*prv

#def ecssa_sig():
#    return y, r, s
#
#def ecssa_verify():
#    return
#
#def ecssa_recover():
#    return
#
#def ecssa_sign_and_commit():
#    return

def test_sign():
    print("\n std sign with ecdsa")
    msg = "hello world"
    prv = 1
    r, s = ecdsa_sign(msg, prv, eph_prv = None)
    pubkey = pointMultiply(prv, ec_G)
    assert ecdsa_verify(msg, (r, s), pubkey)
    assert pubkey in (ecdsa_recover(msg, (r,s), 0), ecdsa_recover(msg, (r,s), 1))
    # some more tests should be done!
    commit = "sign to contract"
    dsasig_commit, receipt = ecdsa_sign_and_commit(msg, prv, commit, eph_prv = None)
    assert ecdsa_verify(msg, dsasig_commit, pubkey), "invalid sig"
    assert ec_verify_commit(receipt, commit), "invalid commit"

# test_sign()