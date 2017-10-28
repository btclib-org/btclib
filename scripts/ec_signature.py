# -*- coding: utf-8 -*-
"""
Created on Sat Oct 28 01:03:03 2017

@author: Leonardo
"""

from hashlib import sha256
from base58 import b58_decode_check
from secp256k1 import order, G, pointMultiply

sha256("ciao".encode()).digest()

#source stackoverflow ... (cell)
import string
def is_str_hex(s):
    return all(c in string.hexdigits for c in s)
#print(is_str_hex("123f"))
#print(is_str_hex("23g"))
#print(is_str_hex(""))

from base58 import __chars as b58digits
def is_str_b58(s):
    return all(c in b58digits for c in s)
#print(is_str_b58("123w"))
#print(is_str_b58("++g"))
#print(is_str_b58(""))


def valid_prv(prv):
    assert type(prv) in (str, bytes, int), "private key should be a string, bytes or int"
    if type(prv) == str:
        if is_str_hex(prv):
            prv = int(prv, 16)
        elif is_str_b58(prv): #Wif
            prv = b58_decode_check(prv)[2:]
            # other assert?
        else: assert 0, "if private key is string use hex or Wif"
    if type(prv) == bytes:
        prv = int.from_bytes(prv, "big")
    assert 0 < prv and prv < order, "private key must be between 0 and order"
    return prv

def is_valid_eph_prv(eph_prv):
    return True 

def ecdsa_sig(msg, prv, eph_prv = None):
    assert type(msg) == str, "message must be a string"
    prv = valid_prv(prv)
    
    
    h = sha256(msg.encode()).digest()
    R = pointMultiply(eph_prv, G)
    s = modInv(eph_prv, order) * (h + prv * R[0]) % order


    return r, s

def ecssa_sig():
    return y, r, s

def ecdsa_verify():
    return

def ecssa_verify():
    return

def commit_to_ec_point():
    return

def ecdsa_sign_and_commit():
    return

def ecssa_sign_and_commit():
    return

def ec_verify_commit():
    return