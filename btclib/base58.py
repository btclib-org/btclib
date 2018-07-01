#!/usr/bin/env python3

'''Base58 encoding

Implementations of Base58 and Base58Check.
'''

# credit to...

from hashlib import sha256
from typing import Union, Optional

# 58 character alphabet used
base58digits = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base = len(base58digits)

def to_bytes(v: Union[str, bytes]):
    '''Return bytes from bytes or string'''
    if isinstance(v, str): v = v.encode('ascii')
    if not isinstance(v, bytes):
        raise TypeError(
            "a bytes-like object is required (also str), not '%s'" %
            type(v).__name__)
    return v

def b58encode_int(i: int, default_one: bool = True) -> bytes:
    '''Encode an integer using Base58'''
    if not i and default_one:
        return base58digits[0:1]
    string = b""
    while i >= __base:
        i, idx = divmod(i, __base)
        string = base58digits[idx:idx+1] + string
    string = base58digits[i:i+1] + string
    return string

def b58decode_int(v: Union[str, bytes]) -> int:
    '''Decode Base58 encoded bytes (or string) as integer'''

    v = to_bytes(v)

    decimal = 0
    for char in v:
        decimal = decimal * __base + base58digits.index(char)
    return decimal

def b58encode(v: Union[str, bytes]) -> bytes:
    '''Encode bytes (or string) using Base58'''

    v = to_bytes(v)

    # leading-0s will become leading-1s
    nPad = len(v)
    v = v.lstrip(b'\0')
    nPad -= len(v)

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    result = b58encode_int(acc, False)

    # adding leading-1s
    return (base58digits[0:1] * nPad + result)

def b58decode(v: Union[str, bytes], length: Optional[int] = None) -> bytes:
    '''Decode Base58 encoded bytes (or string) and verify required length'''

    v = to_bytes(v)

    # leading-1s will become leading-0s
    nPad = len(v)
    v = v.lstrip(base58digits[0:1])
    nPad -= len(v)

    acc = b58decode_int(v)

    result = []
    while acc >= 256:
        acc, mod = divmod(acc, 256)
        result.append(mod)
    result.append(acc)
    result = bytes(reversed(result))

    # adding leading-0s
    result = b'\0' * nPad + result

    if length is not None and len(result) != length:
        raise ValueError("Invalid length for decoded bytes")
    return result

def b58encode_check(v: bytes) -> bytes:
    '''Encode bytes using Base58 with a 4 character checksum'''

    digest = sha256(sha256(v).digest()).digest()
    result = b58encode(v + digest[:4])
    return result

def b58decode_check(v: bytes, length: Optional[int] = None) -> bytes:
    '''Decode Base58 encoded bytes and verify checksum and length'''

    if length is not None: length += 4
    result = b58decode(v, length)
    result, check = result[:-4], result[-4:]

    digest = sha256(sha256(result).digest()).digest()
    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result
