#!/usr/bin/env python3

"""Base58 encoding

   Implementation of Base58 and Base58Check, originally from
   https://github.com/keis/base58, with the following modifications:
   - type annotated python3,
   - removal of string support (binary and hex-string only)
   - minor improvements
   - added check functionalities
"""

from hashlib import sha256
from typing import Union, Optional

# used digits
__digits = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base = len(__digits)


def double_sha256(s: bytes) -> bytes:
    return sha256(sha256(s).digest()).digest()


def to_bytes(v: Union[str, bytes]) -> bytes:
    '''Return bytes from bytes or hex-string'''
    if isinstance(v, str):
        v = bytes.fromhex(v)
    if not isinstance(v, bytes):
        raise TypeError(
            "a bytes-like object is required (also hex-string), not '%s'" %
            type(v).__name__)
    return v


def b58encode_check(v: Union[str, bytes]) -> bytes:
    '''Encode bytes using Base58 with a 4 character checksum'''

    v = to_bytes(v)

    digest = double_sha256(v)
    result = b58encode(v + digest[:4])
    return result


def b58encode(v: Union[str, bytes]) -> bytes:
    '''Encode bytes using Base58'''

    v = to_bytes(v)

    # preserve leading-0s
    # leading-0s become base58 leading-1s
    nPad = len(v)
    v = v.lstrip(b'\0')
    vlen = len(v)
    nPad -= vlen
    result = __digits[0:1] * nPad

    if vlen:
        i = int.from_bytes(v, 'big')
        result = result + b58encode_int(i)

    return result


def b58encode_int(i: int) -> bytes:
    '''Encode an integer using Base58'''
    if i == 0:
        return __digits[0:1]
    result = b""
    while i > 0:
        i, idx = divmod(i, __base)
        result = __digits[idx:idx+1] + result
    return result


def b58decode_check(v: Union[str, bytes], output_size: Optional[int] = None) -> bytes:
    '''Decode Base58 encoded bytes (or hex-string); also verify checksum and required output length'''

    v = to_bytes(v)

    if output_size is not None:
        output_size += 4
    result = b58decode(v, output_size)
    result, checksum = result[:-4], result[-4:]

    digest = double_sha256(result)
    if checksum != digest[:4]:
        raise ValueError(
            'Invalid checksum: {} {}'.format(checksum, digest[:4]))
    return result


def b58decode(v: Union[str, bytes], output_size: Optional[int] = None) -> bytes:
    '''Decode Base58 encoded bytes (or hex-string) and verify required output length'''

    v = to_bytes(v)

    # preserve leading-0s
    # base58 leading-1s become leading-0s
    nPad = len(v)
    v = v.lstrip(__digits[0:1])
    vlen = len(v)
    nPad -= vlen
    result = b'\0' * nPad

    if vlen:
        i = b58decode_int(v)
        nbytes = (i.bit_length() + 7) // 8
        result = result + i.to_bytes(nbytes, 'big')

    if output_size is not None and len(result) != output_size:
        raise ValueError(
            "Invalid decoded byte length: %s (%s was required instead)" %
            (len(result), output_size))
    return result


def b58decode_int(v: bytes) -> int:
    '''Decode Base58 encoded bytes as integer'''

    i = 0
    for char in v:
        i *= __base
        i += __digits.index(char)
    return i
