# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Base58 encoding and decoding functions.

**The codec.** This module is base58 itself, with no bitcoin in it: bytes in,
ascii out, a checksum, and nothing that knows what the bytes mean. What gives
them meaning is btclib.b58 -- WIF, p2pkh, p2sh, the version prefixes and the
networks -- and the rule between the two is that direction: b58 imports
base58, never the other way round.

The split is the one the standard library draws between `base64` and whatever
uses it, and the two names are meant to be read as a pair: `base58` the
encoding, `b58` the bitcoin semantics. `bech32` and `b32` are the same pair
for the segwit address encoding.

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

* type annotated Python3
* using native Python3 int.from_bytes() and i.to_bytes()
* added optional check on output size for decode()
* interface mimics the native Python3 base64 interface, i.e.
  it supports encoding bytes-like objects to ASCII bytes,
  and decoding ASCII bytes-like objects or ASCII strings to bytes.
"""

from __future__ import annotations

from btclib.alias import Octets, String
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash256
from btclib.utils import bytes_from_octets, is_integer

__all__ = [
    "MAX_LENGTH",
    "decode",
    "encode",
]

_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
__BASE = len(_ALPHABET)

# a digit for every byte value, and a byte value for every digit, so that
# a whole string is translated in one C pass where reading it character by
# character was a scan of the 58-byte alphabet per character:
# `_ALPHABET.index(char)` for each of them, and `x not in _ALPHABET` for
# each of them again to validate. maketrans leaves every byte it is not
# given alone, which is why the validity check has to come first: a
# character outside the alphabet would otherwise decode as itself
_DIGIT_OF = bytes.maketrans(_ALPHABET, bytes(range(__BASE)))
_CHAR_OF = bytes.maketrans(bytes(range(__BASE)), _ALPHABET)

# how many digits are carried through the big-integer arithmetic at a
# time. 58**10 < 2**64, so a chunk's ten digits come out of an int the
# machine holds in a register, and the multiplication or division that
# costs O(size of the number) is paid once per ten digits instead of once
# per digit. Both loops stay quadratic in the length of the string -- the
# accumulator grows -- with a tenth of the coefficient
_CHUNK = 10
_CHUNK_BASE = __BASE**_CHUNK

# The longest string btclib legitimately decodes is a BIP32 extended
# key: 78 bytes of payload plus 4 of checksum, which base58 writes in at
# most 112 characters (an address takes 35, a WIF 52). The cap is what
# keeps the quadratic accumulation of _b58decode_to_int away from
# attacker-supplied text: measured 2.2 ms at 10k characters, 32 ms at
# 40k and 510 ms at 160k, four times the cost per doubling of the input,
# and the checksum that would reject it is verified only once the
# decoding has been paid for. A sixth of what those three cost before
# the chunking below -- 12.8 ms, 197 ms and 3193 ms -- which is a
# smaller coefficient and the same curve, so the cap answers the same
# argument it always did.
# The encoder is deliberately left uncapped, being quadratic too: what
# it is handed is data the caller already holds, not a string that
# arrived from the network.
MAX_LENGTH = 112


def _b58encode_from_int(i: int) -> bytes:
    # least significant digit first into a bytearray, reversed once at the
    # end, where prepending to a bytes object copied the whole string per
    # digit -- and the digits translated to characters in one pass rather
    # than sliced out of the alphabet one at a time
    digits = bytearray()
    while i >= _CHUNK_BASE:
        # ten digits of a number whose higher part is not zero yet, so all
        # ten are significant and the leading zeros among them are real
        i, chunk = divmod(i, _CHUNK_BASE)
        for _ in range(_CHUNK):
            chunk, digit = divmod(chunk, __BASE)
            digits.append(digit)
    while i or not digits:
        # the most significant digits, and `not digits` is zero itself:
        # base58 writes it as one leading digit rather than as nothing
        i, digit = divmod(i, __BASE)
        digits.append(digit)
    digits.reverse()
    return bytes(digits).translate(_CHAR_OF)


def _b58encode(v: bytes) -> bytes:
    # preserve leading-0s
    # leading-0s become base58 leading-1s
    n_pad = len(v)
    v = v.lstrip(b"\0")
    vlen = len(v)
    n_pad -= vlen
    result = _ALPHABET[:1] * n_pad

    if vlen:
        i = int.from_bytes(v, byteorder="big", signed=False)
        result += _b58encode_from_int(i)

    return result


def encode(v: Octets, in_size: int | None = None) -> bytes:
    """Encode a bytes-like object using Base58Check."""
    v = bytes_from_octets(v, in_size)
    h256 = hash256(v)
    # the concatenation a memoryview has no operator for: what makes it
    # one is `bytes_from_octets` above, where every buffer becomes the
    # `bytes` the payload is built from
    return _b58encode(v + h256[:4])


def _b58decode_to_int(v: bytes) -> int:
    digits = v.translate(_DIGIT_OF)
    i = 0
    for start in range(0, len(digits), _CHUNK):
        chunk = digits[start : start + _CHUNK]
        value = 0
        for digit in chunk:
            value = value * __BASE + digit
        # one multiplication of the accumulator per ten digits, by the
        # power that matches the chunk actually read: the last one is
        # shorter unless the string divides by ten
        i = i * __BASE ** len(chunk) + value
    return i


def _b58decode(v: bytes | bytearray | memoryview) -> bytes:
    # bytes for the buffers that are a String and are not bytes: a
    # memoryview has neither translate nor lstrip, and a bytearray
    # answers both in its own type. Free on the path that matters:
    # `bytes(b)` is `b` itself where `b` is already `bytes`, the same
    # identity `bytes_from_octets` uses for the same reason.
    v = bytes(v)
    # every alphabet byte deleted, so what is left is what is not one:
    # the same question as `any(x not in _ALPHABET for x in v)` asked in
    # one C pass instead of a 58-byte scan per character, and it has to be
    # asked before _DIGIT_OF translates anything
    if v.translate(None, _ALPHABET):
        msg = "Base58 string contains invalid characters"
        raise BTClibValueError(msg)

    # preserve leading-0s
    # base58 leading-1s become leading-0s
    n_pad = len(v)
    v = v.lstrip(_ALPHABET[:1])
    vlen = len(v)
    n_pad -= vlen
    result = b"\0" * n_pad

    if vlen:
        i = _b58decode_to_int(v)
        nbytes = (i.bit_length() + 7) // 8
        result += i.to_bytes(nbytes, byteorder="big", signed=False)

    return result


def decode(v: String, out_size: int | None = None) -> bytes:
    """Decode a Base58Check encoded bytes-like object or ASCII string.

    Optionally, it also ensures required output size.
    """
    if isinstance(v, str):
        # do not trim spaces.
        # A character outside ascii cannot be in the base58 alphabet
        # either, so it is the same error as any other invalid one and
        # gets the same answer: letting the UnicodeEncodeError out would
        # send an address carrying a smart quote or an accented letter
        # past every caller written to catch BTClibValueError
        try:
            v = v.encode("ascii")
        except UnicodeEncodeError as e:
            raise BTClibValueError(f"non-ascii character in base58 string: {e}") from e
    elif not isinstance(v, (bytes, bytearray, memoryview)):
        # what is neither went through untouched and failed on `len` below,
        # which is a TypeError about a builtin rather than about the
        # address that was passed. Every key and address converter in the
        # library decodes here, so this is the one place worth saying it
        # in. Every buffer and not `bytes` alone, as bytes_from_octets
        # takes them
        err_msg = f"invalid base58 string type: {type(v).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)

    if len(v) > MAX_LENGTH:
        err_msg = f"too many base58 characters: {len(v)}, max is {MAX_LENGTH}"
        raise BTClibValueError(err_msg)

    result = _b58decode(v)
    if len(result) < 4:
        err_msg = "not enough bytes for checksum, "
        err_msg += f"invalid base58 decoded size: {len(result)}"
        raise BTClibValueError(err_msg)

    result, checksum = result[:-4], result[-4:]
    h256 = hash256(result)
    if checksum != h256[:4]:
        err_msg = f"invalid checksum: 0x{checksum.hex()} instead of 0x{h256[:4].hex()}"
        raise BTClibValueError(err_msg)

    # the size policy of btclib/utils.py, at the boundary that does its own
    # comparison rather than going through bytes_from_octets: a bool would
    # accept a one-octet payload and call it a checked size
    if out_size is not None and not is_integer(out_size):
        err_msg = f"invalid output size type: {type(out_size).__name__}"
        raise BTClibTypeError(err_msg)

    if out_size is None or len(result) == out_size:
        return result

    err_msg = "valid checksum, invalid decoded size: "
    err_msg += f"{len(result)} bytes instead of {out_size}"
    raise BTClibValueError(err_msg)
