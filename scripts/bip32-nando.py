# -*- coding: utf-8 -*-
"""
Created on Mon Oct 16 11:16:55 2017

@author: dfornaro
"""
from secp256k1 import order, G, pointMultiply
from hmac import HMAC
from hashlib import sha512, sha256
from base58 import b58encode

def from_hex_to_bytes(value):
    if len(value) % 2 ==1:
        raise TypeError("hex must be composed by a odd number of value")
    value_base10 = [0]*int(len(value)/2)
    for i in range(0,int(len(value)/2)):
        value_base10[i] = int(value[i*2:(i+1)*2],16)
    value_bytes = bytes(value_base10)
    return value_bytes

seed = '000102030405060708090a0b0c0d0e0f'
print("Seed:", seed)
seed_bytes = from_hex_to_bytes(seed)
hashValue = HMAC(key=b"Bitcoin seed", msg=seed_bytes, digestmod=sha512).hexdigest()
# master private Key:
mp = hashValue[:64]
# master chain code
chain_code = hashValue [64:]

# version is needed to obtain xprv when encoded in base 58
version = '0488ade4'
# depth is the level of the tree, for the master key is set to 0
depth = '00'
# fingerprint is set to 0 for the master key
fingerprint  = '00000000'
# child_number is the index of the child, for the master key is set to 0
child_number = '00000000'

extended_pr_key = version + depth + fingerprint + child_number + chain_code + '00' + mp
extended_pr_key_bytes = from_hex_to_bytes(extended_pr_key)
# We need to add a checksum at the end of the extended private key (double sha256)
checksum = sha256(sha256(extended_pr_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pr_key_checked = extended_pr_key + checksum[:8]
extended_pr_key_checked_bytes = from_hex_to_bytes(extended_pr_key_checked)
# We will rapresent the extended private key in base 58
ext_prv = b58encode(extended_pr_key_checked_bytes)

# Obtain a master public Key from a master private key
mp_int = int(mp,16)
MP_int = pointMultiply(mp_int , G)
prefix = b'\x03' if (MP_int[0] % 2 == 0) else b'\x02'
# Master Public Key:
MP = prefix + MP_int[0].to_bytes(32, byteorder='big')
MP_hex = MP.hex()

# in order to obtain the master public key, we will compute the same procedure

# version is needed to obtain xpub when encoded in base 58
version='0488b21e'
# depth is the level of the tree, for the master key is set to 0
depth = '00'
# fingerprint is set to 0 for the master key
fingerprint  = '00000000'
# child_number is the index of the child, for the master key is set to 0
child_number = '00000000'

extended_pub_key = version + depth + fingerprint + child_number + chain_code + MP_hex
extended_pub_key_bytes = from_hex_to_bytes(extended_pub_key)
# We need to add a checksum at the end of the extended public key (double sha256)
checksum = sha256(sha256(extended_pub_key_bytes).digest()).hexdigest()
# We need to add 4 bytes, so we need to add 8 hex
extended_pub_key_checked = extended_pub_key + checksum[0:8]
extended_pub_key_checked_bytes = from_hex_to_bytes(extended_pub_key_checked)
# We will rapresent the extended public key in base 58
ext_pub=b58encode(extended_pub_key_checked_bytes)

print('\nm')
print('ext prv:', ext_prv)
assert ext_prv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "failure"
print('ext pub:', ext_pub)
assert ext_pub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "failure"


