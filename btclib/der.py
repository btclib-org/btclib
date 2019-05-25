#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Strict DER-encoded signature representation.
   
    The original Bitcoin implementation used OpenSSL to verify DER-encoded ASN.1
    signature representation. However, OpenSSL does not do strict validation and
    as long as the signature is not horribly malformed it is accepted.
    E.g. extra padding is ignored and this changes the transaction hash value,
    leading to transaction malleability.
    This was fixed by BIP66, activated on block 363,724.

    source: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

    BIP66 mandates a strict encoding format:

    Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

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

from typing import Tuple

from .curve import Curve
from .dsa import ECDS, _to_sig

sighash_all = b'\x01'
sighash_none = b'\x02'
sighash_single = b'\x03'
sighash_all_anyonecanpay = b'\x81'
sighash_none_anyonecanpay = b'\x82'
sighash_single_anyonecanpay = b'\x83'


def _bytes_from_scalar(scalar: int) -> bytes:
    # scalar is assumed to be in [1, n-1]
    elen = scalar.bit_length()
    esize = elen // 8 + 1  # not a bug: 'highest bit set' padding included here
    n_bytes = scalar.to_bytes(esize, 'big')
    return n_bytes


def _encode_scalar(scalar: int) -> bytes:
    # scalar is assumed to be in [1, n-1]
    x = _bytes_from_scalar(scalar)
    xsize = len(x).to_bytes(1, "big")
    return b'\x02' + xsize + x


def encode(ec: Curve, sig: ECDS, sighash: bytes = sighash_all) -> bytes:
    """Encode a strict DER-encoded signature."""

    if len(sighash) > 1:
        raise ValueError(f"sighash size {len(sighash)} > 1")

    # check that it is a valid signature for the given Curve
    r, s = _to_sig(ec, sig)

    enc = _encode_scalar(r)
    enc += _encode_scalar(s)
    return b'\x30' + len(enc).to_bytes(1, "big") + enc + sighash


def decode(ec: Curve, sig: bytes) -> Tuple[ECDS, bytes]:
    """Decode a strict DER-encoded signature."""

    maxsize = ec.nsize * 2 + 7
    sigsize = len(sig)
    if not 8 < sigsize <= maxsize:
        errmsg = f"DER signature size ({sigsize}) must be in "
        errmsg += f"[9, {maxsize}]"
        raise ValueError(errmsg)

    if sig[0] != 0x30:
        raise ValueError("DER signature must be of type 0x30 (compound)")

    # sigsize checks
    if sig[1] + 3 != sigsize:
        m = "Declared signature size does not match with actual signature size"
        raise ValueError(m)

    sizeR = sig[3]  # size of the r scalar
    if sizeR == 0:
        raise ValueError("Zero-size integers are not allowed for r")

    if 5 + sizeR >= sigsize:
        raise ValueError("Size of the s scalar must be inside the signature")

    sizeS = sig[5 + sizeR]  # size of the s scalar
    if sizeS == 0:
        raise ValueError("Zero-size integers are not allowed for s")

    if sizeR + sizeS + 7 != sigsize:
        raise ValueError("Signature size does not match with size of scalars")

    # scalar r
    if sig[2] != 0x02:
        raise ValueError("r scalar must be an integer")

    if sig[4] & 0x80:
        raise ValueError("Negative numbers are not allowed for r")

    # Null bytes at the start of a scalar are not allowed, unless the
    # scalar would otherwise be interpreted as a negative number
    if sizeR > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        raise ValueError("Invalid null bytes at the start of r")

    r = int.from_bytes(sig[4:4 + sizeR], 'big')

    # scalar s (offset=2+sizeR with respect to r)
    if sig[sizeR + 4] != 0x02:
        raise ValueError("s scalar must be an integer")

    if sig[sizeR + 6] & 0x80:
        raise ValueError("Negative numbers are not allowed for s")

    # Null bytes at the start of a scalar are not allowed, unless the
    # scalar would otherwise be interpreted as a negative number
    if sizeS > 1 and sig[sizeR + 6] == 0x00 and not (sig[sizeR + 7] & 0x80):
        raise ValueError("Invalid null bytes at the start of s")

    s = int.from_bytes(sig[6 + sizeR:6 + sizeR + sizeS], 'big')

    # _to_sig checks that the signature is valid for the given Curve
    return _to_sig(ec, (r, s)), sig[sigsize - 1:]
