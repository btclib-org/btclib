#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of bbtlib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of bbtlib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""DER encoding

   https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

   Encoding format:
   0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
   * total-length: 1-byte length descriptor of everything that follows,
     excluding the sighash byte.
   * R-length: 1-byte length descriptor of the R value that follows.
   * R: arbitrary-length big-endian encoded R value. It must use the shortest
     possible encoding for a positive integers (which means no null bytes at
     the start, except a single one when the next byte has its highest bit set
     to avoid being interpreted as a negative number).
   * S-length: 1-byte length descriptor of the S value that follows.
   * S: arbitrary-length big-endian encoded S value. The same R rules apply.
   * sighash: 1-byte value indicating what data is hashed (not part of the DER
     signature)
"""

from btclib.ellipticcurves import secp256k1, int_from_Scalar
from btclib.ecdsa import Tuple, ECDS, to_dsasig

sighash_all = b'\x01'
sighash_none = b'\x02'
sighash_single = b'\x03'
sighash_all_anyonecanpay = b'\x81'
sighash_none_anyonecanpay = b'\x82'
sighash_single_anyonecanpay = b'\x83'

def bytes_from_element(n: int) -> bytes:
    if n<0:
        raise ValueError("n must be a positive int")
    n_bytes = n.to_bytes(n.bit_length() // 8 + 1, 'big')
    if n_bytes[0] & 0x80: # highest bit set
        n_bytes = b'\x00' + n_bytes # avoid being interpreted as negative
    return n_bytes

def encode_element(element: int) -> bytes:
    x = bytes_from_element(element)
    x_len = len(x).to_bytes(1, "big")
    return b'\x02' + x_len + x

def DER_encode(sig: ECDS, sighash: bytes = sighash_all) -> bytes:
    if len(sighash) > 1:
        raise ValueError("sighash size %s > 1" % len(sighash))
    r, s = sig
    enc = encode_element(int(r))
    enc += encode_element(s) # FIXME
    return b'\x30' + len(enc).to_bytes(1, "big") + enc + sighash

def DER_decode(sig: bytes) -> Tuple[ECDS, bytes]:

    size = len(sig)
    if not 8 < size < 74:
        raise ValueError("DER signature size (%s) should be in [9, 73]")

    if sig[0] != 0x30:
        raise ValueError("DER signature must be of type 0x30 (compound)")

    # size checks
    if sig[1] + 3 != size:
        raise ValueError("Declared signature length does not match with size")

    lenR = sig[3]  # length of the r element
    if lenR == 0:
        raise ValueError("Zero-length integers are not allowed for r")

    if 5 + lenR >= size:
        raise ValueError("Length of the s element must be inside the signature")

    lenS = sig[5 + lenR]  # length of the s element
    if lenS == 0:
        raise ValueError("Zero-length integers are not allowed for s")

    if lenR + lenS + 7 != size:
        raise ValueError("Signature size does not match with elements")

    # element r
    if sig[2] != 0x02:
        raise ValueError("r element must be an integer")
    
    if sig[4] & 0x80:
        raise ValueError("Negative numbers %s are not allowed for r" % sig[4])

    # Null bytes at the start of an element are not allowed, unless the
    # element would otherwise be interpreted as a negative number
    if lenR > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        raise ValueError("Invalid null bytes at the start of r")

    r = int.from_bytes(sig[4:4+lenR], 'big')

    # element s
    if sig[lenR + 4] != 0x02:
        raise ValueError("s element must be an integer")

    if sig[lenR + 6] & 0x80:
        raise ValueError("Negative numbers %s are not allowed for s" % sig[4])

    if lenS > 1 and sig[lenR + 6] == 0x00 and not (sig[lenR + 7] & 0x80):
        raise ValueError("Invalid null bytes at the start of s")

    s = int.from_bytes(sig[6+lenR:6+lenR+lenS], 'big')

    return (r , s) , sig[size-1:]
