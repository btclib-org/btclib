#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Strict ASN.1 DER format for ECDSA signature representation.
   
    The original Bitcoin implementation used OpenSSL to verify
    ECDSA signatures in ASN.1 DER representation.
    However, OpenSSL does not do strict validation and
    as long as the signature is not horribly malformed it is accepted.
    E.g. extra padding is ignored and this changes the transaction hash value,
    leading to transaction malleability.
    This was fixed by BIP66, activated on block 363,724.

    source: https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

    BIP66 mandates a strict DER format:

    Format: 0x30 [length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]

    * 0x30 coumpond DER marker
    * length: 1-byte length descriptor of everything that follows,
      excluding the sighash byte
    * 0x02 integer marker
    * R-length: 1-byte length descriptor of the R value that follows
    * R: arbitrary-length big-endian R value. It must use the shortest
      possible encoding for a positive integers (which means no null bytes at
      the start, except a single one when the next byte has its highest bit set
      to avoid being interpreted as a negative number)
    * 0x02 integer marker
    * S-length: 1-byte length descriptor of the S value that follows
    * S: arbitrary-length big-endian S value. Same rules of the R value apply
    * sighash: 1-byte value indicating what data is hashed (not part of the DER
      signature)
"""

from typing import Tuple, Optional

from .curve import Curve
from .curves import secp256k1
from .dsa import ECDS, _check_sig
from .utils import Octets, bytes_from_hexstring

sighash_all = b'\x01'
sighash_none = b'\x02'
sighash_single = b'\x03'
sighash_all_anyonecanpay = b'\x81'
sighash_none_anyonecanpay = b'\x82'
sighash_single_anyonecanpay = b'\x83'
sighashes = [
    sighash_all,
    sighash_none,
    sighash_single,
    sighash_all_anyonecanpay,
    sighash_none_anyonecanpay,
    sighash_single_anyonecanpay,
]


def _bytes_from_scalar(scalar: int) -> bytes:
    # scalar is assumed to be in [1, n-1]
    elen = scalar.bit_length()
    esize = elen // 8 + 1  # not a bug: 'highest bit set' padding included here
    n_bytes = scalar.to_bytes(esize, byteorder='big')
    return n_bytes


def _serialize_scalar(scalar: int) -> bytes:
    # scalar is assumed to be in [1, n-1]
    x = _bytes_from_scalar(scalar)
    xsize = len(x).to_bytes(1, byteorder='big')
    return b'\x02' + xsize + x


def serialize(sig: ECDS, sighash: Octets = sighash_all, ec: Curve = secp256k1) -> bytes:
    """Serialize an ECDSA signature in strict ASN.1 DER representation."""

    sighash = bytes_from_hexstring(sighash)
    if len(sighash) > 1:
        raise ValueError(f"sighash size {len(sighash)} > 1")

    # check that it is a valid signature for the given Curve
    _check_sig(sig, ec)

    enc = _serialize_scalar(sig[0])
    enc += _serialize_scalar(sig[1])
    return b'\x30' + len(enc).to_bytes(1, byteorder='big') + enc + sighash


def deserialize(sig: Octets, ec: Curve = secp256k1) -> Tuple[ECDS, Optional[bytes]]:
    """Deserialize a strict ASN.1 DER representation of an ECDSA signature."""

    sig = bytes_from_hexstring(sig)

    # 7 bytes of meta-data:
    # compound header, compound length,
    # r value header, r value length,
    # s value header, s value length
    # sighash type (optional)
    #
    # the ECDSA signature (r, s) should be 64 bytes,
    # r and s being 32 bytes integers each;
    # however, integers in DER are signed,
    # so if the value being encoded is greater than 2^128,
    # a 33rd byte is added in front.
    # Bitcoin has a "low s" rule for the s value to be below ec.n,
    # but it is only a standardness rule miners are allowed to ignore.
    # Moreover, no such rule exists for r.

    maxsize = (ec.nsize+1) * 2 + 7  # 73 bytes
    sigsize = len(sig)
    if not 8 < sigsize <= maxsize:
        errmsg = f"DER signature size ({sigsize}) must be in "
        errmsg += f"[9, {maxsize}]"
        raise ValueError(errmsg)

    if sig[0] != 0x30:
        msg = f"DER signature must be of type 0x30 (compound), not {sig[0]}"
        raise ValueError(msg)

    # sigsize checks
    leftover = sigsize - 2 - sig[1]
    if leftover == 0:    # no sighash value
        sighash = None
    elif leftover == 1:  # sighash value
        sighash = sig[sigsize - 1:]
        if sighash not in sighashes:
            raise ValueError(f"Invalid sighash type {sighash!r}")
    else:
        msg = f"Declared length ({sig[1]}) does not "
        msg += f"match with actual signature size ({sigsize}) +2 or +3"
        raise ValueError(msg)

    sizeR = sig[3]  # size of the r scalar
    if sizeR == 0:
        raise ValueError("Zero-size integer is not allowed for r")

    if 5 + sizeR >= sigsize:
        raise ValueError("Size of the s scalar must be inside the signature")

    sizeS = sig[5 + sizeR]  # size of the s scalar
    if sizeS == 0:
        raise ValueError("Zero-size integer is not allowed for s")

    if sigsize - sizeR - sizeS != 6 + leftover:
        raise ValueError("Signature size does not match with size of scalars")

    # scalar r
    if sig[2] != 0x02:
        raise ValueError("r scalar must be an integer")

    if sig[4] & 0x80:
        raise ValueError("Negative number is not allowed for r")

    # Null bytes at the start of a scalar are not allowed, unless the
    # scalar would otherwise be interpreted as a negative number
    if sizeR > 1 and sig[4] == 0x00 and not (sig[5] & 0x80):
        raise ValueError("Invalid null bytes at the start of r")

    r = int.from_bytes(sig[4:4 + sizeR], byteorder='big')

    # scalar s (offset=2+sizeR with respect to r)
    if sig[sizeR + 4] != 0x02:
        raise ValueError("s scalar must be an integer")

    if sig[sizeR + 6] & 0x80:
        raise ValueError("Negative number is not allowed for s")

    # Null bytes at the start of a scalar are not allowed, unless the
    # scalar would otherwise be interpreted as a negative number
    if sizeS > 1 and sig[sizeR + 6] == 0x00 and not (sig[sizeR + 7] & 0x80):
        raise ValueError("Invalid null bytes at the start of s")

    s = int.from_bytes(sig[6 + sizeR:6 + sizeR + sizeS], byteorder='big')

    # checks that the signature is valid for the given Curve
    _check_sig((r, s), ec)
    return (r, s), sighash
