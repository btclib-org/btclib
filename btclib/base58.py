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

from hashlib import sha256
from typing import Optional, Union

from .utils import hash256, Octets, bytes_from_hexstring

__ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__BASE = len(__ALPHABET)


def _b58encode_from_int(i: int) -> bytes:

    if i == 0:
        return __ALPHABET[0:1]

    result = b""
    while i:
        i, idx = divmod(i, __BASE)
        result = __ALPHABET[idx:idx+1] + result

    return result


def _b58encode(v: bytes) -> bytes:

    # preserve leading-0s
    # leading-0s become base58 leading-1s
    nPad = len(v)
    v = v.lstrip(b'\0')
    vlen = len(v)
    nPad -= vlen
    result = __ALPHABET[0:1] * nPad

    if vlen:
        i = int.from_bytes(v, byteorder='big')
        result += _b58encode_from_int(i)

    return result


def b58encode(v: Octets) -> bytes:
    """Encode a bytes-like object using Base58Check."""

    v = bytes_from_hexstring(v)
    h256 = hash256(v)
    return _b58encode(v + h256[:4])


def _b58decode_to_int(v: bytes) -> int:

    i = 0
    for char in v:
        i *= __BASE
        i += __ALPHABET.index(char)
    return i


def _b58decode(v: bytes, out_size: Optional[int]) -> bytes:

    if any(x not in __ALPHABET for x in v):
        msg = "Base58 string contains invalid characters"
        raise ValueError(msg)

    # preserve leading-0s
    # base58 leading-1s become leading-0s
    nPad = len(v)
    v = v.lstrip(__ALPHABET[0:1])
    vlen = len(v)
    nPad -= vlen
    result = b'\0' * nPad

    if vlen:
        i = _b58decode_to_int(v)
        nbytes = (i.bit_length() + 7) // 8
        result = result + i.to_bytes(nbytes, byteorder='big')

    if out_size is not None and len(result) != out_size:
        m = "Invalid decoded size: "
        m += f"{len(result)} bytes instead of {out_size}"
        raise ValueError(m)

    return result


def b58decode(v: Union[bytes, str], out_size: Optional[int] = None) -> bytes:
    """Decode a Base58Check encoded bytes-like object or ASCII string.

    Optionally, it also ensures required output size.
    """

    if isinstance(v, str):
        v = v.encode("ascii")

    if out_size is not None:
        out_size += 4

    result = _b58decode(v, out_size)
    result, checksum = result[:-4], result[-4:]

    h256 = hash256(result)
    if checksum != h256[:4]:
        m = f"Invalid checksum: '{checksum!r}' instead of '{h256[:4]!r}'"
        raise ValueError(m)

    return result
