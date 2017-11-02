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

def to_bytes_min_length(n, byteorder = "big"):
    assert type(n) == int and n >= 0, "n must be a positive int"
    return n.to_bytes(n.bit_length() // 8 + 1 , byteorder) # at least 1 byte, even if n = 0

def to_bytes_add00(n):
    n_bytes = to_bytes_min_length(n, "big")
    return (double_0 if n_bytes[:1] >= mid else b'') + n_bytes

# include the sighash? for now the code doesn't do it    
def get_DER_sig(r, s):
    r_DER = to_bytes_add00(r)
    s_DER = to_bytes_add00(s)
    r_len = len(r_DER).to_bytes(1, "big")
    s_len = len(s_DER).to_bytes(1, "big")
    DER_sig = int_follows + r_len + r_DER + int_follows + s_len + s_DER
    total_len = len(DER_sig).to_bytes(1, "big")
    return DER_follows + total_len + DER_sig

def test_DER():
    r, s = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, \
           0x1111887998ffffffffffffffffffffffffffffffffffffffffffffffffffffff
    print(get_DER_sig(r, s).hex())
    
# test_DER()