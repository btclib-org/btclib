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
However, OpenSSL does not do strict validation
(e.g. extra padding is ignored) and this changes the transaction
hash value, leading to transaction malleability.
This was fixed by BIP66, activated on block 363,724.

source:
https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

BIP66 mandates a strict DER format:

Format:
[0x30][data-size] [0x02][r-size][r] [0x02][s-size][s] [sighash]

* 0x30 header byte to indicate compound structure
* data-size: 1-byte size descriptor of the following data,
    excluding the sighash byte
* 0x02 header byte indicating an integer
* r-size: 1-byte size descriptor of the r value that follows
* r: arbitrary-size big-endian r value.
    It must use the shortest possible encoding for
    a positive integers (which means no null bytes at the start,
    except a single one when the next byte has its highest bit set
    to avoid being interpreted as a negative number)
* 0x02 header byte indicating an integer
* s-size: 1-byte size descriptor of the s value that follows
* s: arbitrary-size big-endian s value. Same rules as for r apply
* sighash: 1-byte value indicating what data is hashed
    (not part of the DER signature)

There are 7 bytes of meta-data:

* compound header, compound size,
* value header, r-value size,
* value header, s-value size
* sighash type (optional)

The ECDSA signature (r, s) should be 64 bytes,
r and s being 32 bytes integers each;
however, integers in DER are signed,
so if the value being encoded is greater than 2^128,
a 33rd byte is added in front.
Bitcoin has a "low s" rule for the s value to be below ec.n,
but it is only a standardness rule miners are allowed to ignore.
Moreover, no such rule exists for r.
"""

from typing import Optional, Tuple, Union

from .alias import Octets
from .curve import Curve, secp256k1
from .script import SIGHASHES
from .utils import bytes_from_octets, hex_string

# (r, s, sighash)
# r and s are the components of a DSASigTuple
DERSigTuple = Tuple[int, int, Optional[int]]
# DERSigTuple or DER serialization (bytes or hex-string, with sighash)
DERSig = Union[DERSigTuple, Octets]


def _validate_sig(
    r: int, s: int, sighash: Optional[int] = None, ec: Curve = secp256k1
) -> None:
    # check that the DSA/DER signature is correct

    # Fail if r is not [1, n-1]
    if not 0 < r < ec.n:
        err_msg = "scalar r not in 1..n-1: "
        err_msg += f"'{hex_string(r)}'" if r > 0xFFFFFFFF else f"{r}"
        raise ValueError(err_msg)

    # Fail if s is not [1, n-1]
    if not 0 < s < ec.n:
        err_msg = "scalar s not in 1..n-1: "
        err_msg += f"'{hex_string(s)}'" if s > 0xFFFFFFFF else f"{s}"
        raise ValueError(err_msg)

    if sighash is not None and sighash not in SIGHASHES:
        raise ValueError(f"invalid sighash: {hex(sighash)}")


def _check_size_and_type(der_sig: bytes, ec: Curve) -> int:

    der_sig_size = len(der_sig)

    # in the secp256k1 case the DERSig size is
    # between 8 bytes (without sighash) and 73 (with sighash) bytes
    #
    # [0x30][data-size] [0x02][r-size][r] [0x02][s-size][s] [sighash]

    # at least one byte each for r and s ('highest bit set' padding)
    min_size = 2 + (2 + 1) * 2 + 0
    # up to 33 bytes each for r and s ('highest bit set' padding)
    max_size = 2 + (2 + 1 + ec.nsize) * 2 + 1
    if not min_size <= der_sig_size <= max_size:
        m = "invalid DER size: "
        m += f"{der_sig_size}, must be in [{min_size}, {max_size}]"
        raise ValueError(m)

    if der_sig[0] != 0x30:
        m = f"DER type must be 0x30 (compound), not {hex(der_sig[0])}"
        raise ValueError(m)

    # The declared size der_sig[1] does not include:
    # 1. der_sig[0] DER type
    # 2. der_sig[1] itself
    # 3. der_sig[-1] optional sighash
    if der_sig_size - der_sig[1] not in (2, 3):
        msg = "Declared size incompatible with actual size: "
        msg += f"{der_sig[1]} + "
        msg += "{2, 3} is not "
        msg += f"{der_sig_size}"
        raise ValueError(msg)

    return der_sig_size


def _scalar_size(der_sig: bytes, sighash_size: int, offset: int) -> int:

    der_sig_size = len(der_sig)

    if der_sig[offset - 2] != 0x02:
        raise ValueError("scalar must be an integer")
    size = der_sig[offset - 1]

    if size == 0:
        raise ValueError("scalar has size zero")

    if der_sig_size < offset + size + sighash_size:
        m = f"Size of scalar is too large: {size}"
        raise ValueError(m)

    if der_sig[offset] & 0x80:
        raise ValueError("Negative number not allowed for scalar")

    # Null byte at the start of a scalar is not allowed, unless the
    # scalar would otherwise be interpreted as a negative number
    if size > 1 and der_sig[offset] == 0x00 and not (der_sig[offset + 1] & 0x80):
        raise ValueError("invalid null bytes at the start of scalar")

    return size


def _deserialize(der_sig: DERSig, ec: Curve = secp256k1) -> DERSigTuple:
    """Deserialize a strict ASN.1 DER representation of an ECDSA signature.

    Return r, s, sighash; sighash is None if not available.
    """

    if isinstance(der_sig, tuple):
        r, s, sighash = der_sig
    else:
        if isinstance(der_sig, str):
            # hex-string of the DER signature
            sig = bytes.fromhex(der_sig)
        else:
            sig = bytes_from_octets(der_sig)

        sig_size = _check_size_and_type(sig, ec)

        # [0x30][data-size] [0x02][r-size][r] [0x02][s-size][s] [sighash]
        sighash_size = sig_size - 2 - sig[1]
        sighash = sig[-1] if sighash_size else None

        offset = 2 + 2
        r_size = _scalar_size(sig, sighash_size, offset)
        r = int.from_bytes(sig[offset : offset + r_size], byteorder="big")

        offset = 2 + 2 + r_size + 2
        s_size = _scalar_size(sig, sighash_size, offset)
        s = int.from_bytes(sig[offset : offset + s_size], byteorder="big")

        if sig_size != 2 + 2 + r_size + 2 + s_size + sighash_size:
            m = "Too big DER size for (r, s): {sig_size}"
            raise ValueError(m)

    _validate_sig(r, s, sighash, ec)
    return r, s, sighash


def _serialize_scalar(scalar: int) -> bytes:
    # scalar is assumed to be in [1, n-1]
    elen = scalar.bit_length()
    esize = elen // 8 + 1  # not a bug: 'highest bit set' padding included here
    x = scalar.to_bytes(esize, byteorder="big")
    xsize = len(x).to_bytes(1, byteorder="big")
    return b"\x02" + xsize + x


def _serialize(
    r: int, s: int, sighash: Optional[int] = None, ec: Curve = secp256k1
) -> bytes:
    """Serialize an ECDSA signature to strict ASN.1 DER representation.

    Trailing sighash is added if provided.
    """

    # check that it is a valid signature for the given Curve
    _validate_sig(r, s, sighash, ec)
    result = _serialize_scalar(r)
    result += _serialize_scalar(s)
    result = b"\x30" + len(result).to_bytes(1, byteorder="big") + result
    if sighash is None:
        return result

    return result + sighash.to_bytes(1, "big")
