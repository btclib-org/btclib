# -*- coding: utf-8 -*-
"""
Created on Thu Nov  2 12:42:14 2017

@author: Leonardo
"""
# source : 
# https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
#
#  BIP: 66
#  Layer: Consensus (soft fork)
#  Title: Strict DER signatures
#  Author: Pieter Wuille <pieter.wuille@gmail.com>
#  Comments-Summary: No comments yet.
#  Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-0066
#  Status: Final
#  Type: Standards Track
#  Created: 2015-01-10
#  License: BSD-2-Clause
# 
#    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
#    // * total-length: 1-byte length descriptor of everything that follows,
#    //   excluding the sighash byte.
#    // * R-length: 1-byte length descriptor of the R value that follows.
#    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
#    //   possible encoding for a positive integers (which means no null bytes at
#    //   the start, except a single one when the next byte has its highest bit set).
#    // * S-length: 1-byte length descriptor of the S value that follows.
#    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
#    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
#    //   signature)

DER_follows = b'\x30'
int_follows = b'\x02'
double_0 = b'\x00'
mid = b'\x80'

sighash_all = b'\x01'
sighash_none = b'\x02'
sighash_single = b'\x03'
sighash_all_anyonecanpay = b'\x81'
sighash_none_anyonecanpay = b'\x82'
sighash_single_anyonecanpay = b'\x83'

def to_bytes_min_length(n, byteorder = "big"):
    assert type(n) == int and n >= 0, "n must be a positive int"
    return n.to_bytes(n.bit_length() // 8 + 1 , byteorder) # at least 1 byte, even if n = 0

def to_bytes_add00(n):
    n_bytes = to_bytes_min_length(n, "big")
    return (double_0 if n_bytes[:1] >= mid else b'') + n_bytes

# include the sighash here?
def get_DER_sig(r, s, sighash = sighash_all):
    r_DER = to_bytes_add00(r)
    s_DER = to_bytes_add00(s)
    r_len = len(r_DER).to_bytes(1, "big")
    s_len = len(s_DER).to_bytes(1, "big")
    DER_sig = int_follows + r_len + r_DER + int_follows + s_len + s_DER
    total_len = len(DER_sig).to_bytes(1, "big")
    return DER_follows + total_len + DER_sig + sighash

def test_DER():
    DER73 = get_DER_sig(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        sighash_all)
    DER72 = get_DER_sig(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        sighash_all)
    DER71 = get_DER_sig(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        sighash_all)
    DER71b = get_DER_sig(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                         0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                         sighash_all)
    DER70 = get_DER_sig(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        0x007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        sighash_all)
    DER69 = get_DER_sig(0x007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        0x007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,\
                        sighash_all)

    print("\nSig 73 bytes")
    print(DER73.hex(), "  -- len:", len(DER73))
    print("\nSig 72 bytes")
    print(DER72.hex(), "  -- len:", len(DER72))
    print("\nSig 71 bytes")
    print(DER71.hex(), "  -- len:", len(DER71))
    print("\nSig 71b bytes")
    print(DER71b.hex(), "  -- len:", len(DER71b))
    print("\nSig 70 bytes")
    print(DER70.hex(), "  -- len:", len(DER70))
    print("\nSig 69 bytes")
    print(DER69.hex(), "  -- len:", len(DER69))
    
test_DER()