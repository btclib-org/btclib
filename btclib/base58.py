#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Base58 encoding and decoding functions.

Binary-to-text encoding schemes are used to transport binary data across
channels designed to deal with textual data. In Bitcoin they are mostly
used to represent large integers as alphanumeric text.

Base58 is similar to Base64, which uses 10 digits, 26 lowercase characters,
26 uppercase characters, '+' (plus sign), and '/' (forward slash).
Base58 omits the similar-looking letters
0 (zero), O (capital o), I (capital i), and l (lower case L)
to avoid ambiguity when printed; moreover, it removes '+' and '/'
so that a double-click does select the whole string.

Base58Check is the checksummed version of Base58, using
hash256(v)[:4] as checksum suffix before encoding;
at the decoding stage the checksum validity ensure data integrity.

This implementation of Base58 and Base58Check is originally from
https://github.com/keis/base58, with the following modifications:

* type annotated python3
* using native python3 int.from_bytes() and i.to_bytes()
* added optional check on output size for b58decode()
* interface mimics the native python3 base64 interface, i.e.
  it supports encoding bytes-like objects to ASCII bytes,
  and decoding ASCII bytes-like objects or ASCII strings to bytes.
"""

from typing import Optional

from .alias import Octets, String
from .exceptions import BTClibValueError
from .utils import bytes_from_octets, hash256

__ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
__BASE = len(__ALPHABET)


def _b58encode_from_int(i: int) -> bytes:

    result = b""
    while i or len(result) == 0:
        i, idx = divmod(i, __BASE)
        result = __ALPHABET[idx : idx + 1] + result

    return result


def _b58encode(v: bytes) -> bytes:

    # preserve leading-0s
    # leading-0s become base58 leading-1s
    n_pad = len(v)
    v = v.lstrip(b"\0")
    vlen = len(v)
    n_pad -= vlen
    result = __ALPHABET[:1] * n_pad

    if vlen:
        i = int.from_bytes(v, byteorder="big", signed=False)
        result += _b58encode_from_int(i)

    return result


def b58encode(v: Octets, in_size: Optional[int] = None) -> bytes:
    """Encode a bytes-like object using Base58Check."""

    v = bytes_from_octets(v, in_size)
    h256 = hash256(v)
    return _b58encode(v + h256[:4])


def _b58decode_to_int(v: bytes) -> int:

    i = 0
    for char in v:
        i *= __BASE
        i += __ALPHABET.index(char)
    return i


def _b58decode(v: bytes) -> bytes:

    if any(x not in __ALPHABET for x in v):
        msg = "Base58 string contains invalid characters"
        raise BTClibValueError(msg)

    # preserve leading-0s
    # base58 leading-1s become leading-0s
    n_pad = len(v)
    v = v.lstrip(__ALPHABET[:1])
    vlen = len(v)
    n_pad -= vlen
    result = b"\0" * n_pad

    if vlen:
        i = _b58decode_to_int(v)
        nbytes = (i.bit_length() + 7) // 8
        result = result + i.to_bytes(nbytes, byteorder="big", signed=False)

    return result


def b58decode(v: String, out_size: Optional[int] = None) -> bytes:
    """Decode a Base58Check encoded bytes-like object or ASCII string.

    Optionally, it also ensures required output size.
    """

    if isinstance(v, str):
        # do not trim spaces
        v = v.encode("ascii")

    result = _b58decode(v)
    if len(result) < 4:
        m = "not enough bytes for checksum, "
        m += f"invalid base58 decoded size: {len(result)}"
        raise BTClibValueError(m)

    result, checksum = result[:-4], result[-4:]
    h256 = hash256(result)
    if checksum != h256[:4]:
        m = f"invalid checksum: 0x{checksum.hex()} instead of 0x{h256[:4].hex()}"
        raise BTClibValueError(m)

    if out_size is None or len(result) == out_size:
        return result

    m = "valid checksum, invalid decoded size: "
    m += f"{len(result)} bytes instead of {out_size}"
    raise BTClibValueError(m)
