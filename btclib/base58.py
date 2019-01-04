#!/usr/bin/env python3

"""Base58 encoding

   Implementation of Base58 and Base58Check, originally from
   https://github.com/keis/base58, with the following modifications:
   - type annotated python3
   - using native python3 int.from_bytes() and i.to_bytes()
   - added length check functionalities to b58decode and b58decode_check
"""

from hashlib import sha256
from typing import Union, Optional

# used digits
__digits = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__base = len(__digits)


def double_sha256(s: bytes) -> bytes:
    return sha256(sha256(s).digest()).digest()


def to_bytes(v: Union[str, bytes]) -> bytes:
    """Encode string to bytes, stipping leading/trailing white spaces"""

    if isinstance(v, str):
        v = v.strip()
        v = v.encode()

    return v


def b58encode_int(i: int) -> bytes:
    """Encode an integer using Base58"""

    if i == 0:
        return __digits[0:1]

    result = b""
    while i > 0:
        i, idx = divmod(i, __base)
        result = __digits[idx:idx+1] + result

    return result


def b58encode(v: Union[str, bytes]) -> bytes:
    """Encode bytes using Base58"""

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


def b58encode_check(v: Union[str, bytes]) -> bytes:
    """Encode bytes using Base58 with a 4 character checksum"""

    v = to_bytes(v)

    digest = double_sha256(v)
    result = b58encode(v + digest[:4])
    return result


def b58decode_int(v: Union[str, bytes]) -> int:
    """Decode Base58 encoded bytes as integer"""

    v = to_bytes(v)

    i = 0
    for char in v:
        i *= __base
        i += __digits.index(char)
    return i


def b58decode(v: Union[str, bytes],
              output_size: Optional[int] = None) -> bytes:
    """Decode Base58 encoded bytes, with verified output length"""


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
        m = "Invalid decoded byte length: "
        m += f"{len(result)} instead of {output_size}"
        raise ValueError(m)

    return result


def b58decode_check(v: Union[str, bytes],
                    output_size: Optional[int] = None) -> bytes:
    """Decode Base58 encoded bytes, with verified checksum and output length"""

    if output_size is not None:
        output_size += 4

    result = b58decode(v, output_size)
    result, checksum = result[:-4], result[-4:]

    digest = double_sha256(result)
    if checksum != digest[:4]:
        m = f"Invalid checksum: '{checksum}' instead of '{digest[:4]}'"
        raise ValueError(m)

    return result
