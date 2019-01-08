#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" 
    ============
    DER encoding
    ============

    Copyright (C) 2017-2019 The btclib developers

    This file is part of btclib. It is subject to the license terms in the
    LICENSE file found in the top-level directory of this distribution.

    No part of btclib including this file, may be copied, modified, propagated,
    or distributed except according to the terms contained in the LICENSE file.

    source : https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

    BIP: 66

    Layer: Consensus (soft fork)

    Title: Strict DER signatures

    Author: Pieter Wuille <pieter.wuille@gmail.com>

    Comments-Summary: No comments yet.

    Comments-URI: https://github.com/bitcoin/bips/wiki/Comments:BIP-0066

    Status: Final

    Type: Standards Track

    Created: 2015-01-10

    License: BSD-2-Clause

    Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    * total-length: 1-byte length descriptor of everything that follows,
      excluding the sighash byte.	
    * R-length: 1-byte length descriptor of the R value that follows.	
    * R: arbitrary-length big-endian encoded R value. It must use the shortest	
      possible encoding for a positive integers (which means no null bytes at	
      the start, except a single one when the next byte has its highest bit set).	
    * S-length: 1-byte length descriptor of the S value that follows.	
    * S: arbitrary-length big-endian encoded S value. The same rules apply.	
    * sighash: 1-byte value indicating what data is hashed (not part of the DER	
      signature)	
"""

from btclib.curves import secp256k1
from btclib.dsa import Tuple, ECDS

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

def bytes_from_element(element: int) -> bytes:
    if element<0:
        raise ValueError(f"negative ({element}) signature element")
    elen = element.bit_length()
    esize = elen // 8 + 1  # not a bug
    # padding for 'highest bit set' is included above
    n_bytes = element.to_bytes(esize, 'big')
    return n_bytes

def encode_element(element: int) -> bytes:
    x = bytes_from_element(element)
    xsize = len(x).to_bytes(1, "big")
    return b'\x02' + xsize + x


def DER_encode(sig: ECDS, sighash: bytes = sighash_all) -> bytes:
    if len(sighash) > 1:
        raise ValueError(f"sighash size {len(sighash)} > 1")
    r, s = sig
    enc = encode_element(int(r))
    enc += encode_element(s) # FIXME
    return b'\x30' + len(enc).to_bytes(1, "big") + enc + sighash

def DER_decode(sig: bytes) -> Tuple[ECDS, bytes]:

    sigsize = len(sig)
    if not 8 < sigsize < 74:
        raise ValueError(f"DER signature size ({sigsize}) must be in [9, 73]")

    if sig[0] != 0x30:
        raise ValueError("DER signature must be of type 0x30 (compound)")

    # sigsize checks
    if sig[1] + 3 != sigsize:
        m = "Declared signature size does not match with actual signature size"
        raise ValueError(m)

    sizeR = sig[3]  # size of the r element
    if sizeR == 0:
        raise ValueError("Zero-size integers are not allowed for r")

    if 5 + sizeR >= sigsize:
        raise ValueError("Size of the s element must be inside the signature")

    sizeS = sig[5 + sizeR]  # size of the s element
    if sizeS == 0:
        raise ValueError("Zero-size integers are not allowed for s")

    if sizeR + sizeS + 7 != sigsize:
        raise ValueError("Signature size does not match with size of elements")

    # element r
    if sig[2] != 0x02:
        raise ValueError("r element must be an integer")
    
    if sig[4] & 0x80:
        raise ValueError("Negative numbers are not allowed for r")

    # Null bytes at the start of an element are not allowed, unless the
    # element would otherwise be interpreted as a negative number
    if sizeR > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        raise ValueError("Invalid null bytes at the start of r")

    r = int.from_bytes(sig[4:4+sizeR], 'big')

    # element s (offset=2+sizeR with respect to r)
    if sig[sizeR + 4] != 0x02:
        raise ValueError("s element must be an integer")

    if sig[sizeR + 6] & 0x80:
        raise ValueError("Negative numbers are not allowed for s")

    if sizeS > 1 and sig[sizeR + 6] == 0x00 and not (sig[sizeR + 7] & 0x80):
        raise ValueError("Invalid null bytes at the start of s")

    s = int.from_bytes(sig[6+sizeR:6+sizeR+sizeS], 'big')

    return (r , s) , sig[sigsize-1:]
