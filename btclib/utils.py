# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Assorted conversion utilities.

Most conversions from SEC 1 v.2 2.3 are included.

https://www.secg.org/sec1-v2.pdf

`read_exactly` and `assert_no_trailing` are the two halves of what every
`parse` in this library owes its caller, and they live here because all of
them owe it:

- a field is as long as its encoding says it is, so a short read is an
  error and not a value. That is structural rather than semantic, so
  `check_validity` does not gate it: skipped, a truncated buffer becomes
  an object that serializes back zero-padded, and two buffers map to the
  one object that serializes to only the longer of them
- octets are one whole object, so bytes after it are refused; a caller's
  stream is not, so parsing consumes the object and leaves the stream on
  the byte after it, which is how a transaction is read out of a block

A fixed-size object read whole -- a 78-byte bip32 key, a 65-byte bms
signature, an 80-byte block header -- reports its own decoded length
instead of naming a field, the buffer being the object and not a part of
one; that check is unconditional for the same reason.

What `check_validity` does gate is the semantic half, and *where* it can
be asked is not the same at the three boundaries the flag appears at.
The object (`serialize`) and the json (`to_dict`/`from_dict`) ask "is
this object well formed"; the octets (`parse`) ask "do these octets
decode into something that is not" -- and for a class whose invariants
are exactly the widths of its fields, nothing can. The decoding enforces
them by construction, so at that boundary the flag is unreachable by
design rather than unchecked, and the class is one in good order rather
than one missing a check. `OutPoint` is such a class: 32 octets of
tx_id and four of vout, every value of which is a valid outpoint since
Bitcoin Core was found to accept the shapes it used to refuse. A class
whose only invalidable child is one -- `TxIn`, whose own fields are of
the same kind -- inherits the property.

The two are not the same question asked twice, which is why an object
can be asked one and not the other: an invalidity of *type* rather than
of value survives the json and not the octets, a bool being an int that
reads back as the number one, while an amount above MoneyRange survives
the octets and not the json, the conversion to BTC asking what
`assert_valid` would ask. `tests/check_validity_test.py` is where the
cases live, one per class and boundary, and this is the rule they are
read under.
"""

from __future__ import annotations

from collections.abc import Iterable
from io import BytesIO
from typing import Any, BinaryIO

from btclib.alias import BinaryData, Integer, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError

__all__ = [
    "NoneOneOrMoreInt",
    "assert_no_trailing",
    "bytes_from_octets",
    "bytesio_from_binarydata",
    "decode_num",
    "encode_num",
    "hex_string",
    "int_from_bits",
    "int_from_integer",
    "int_from_json_number",
    "is_integer",
    "read_exactly",
]

NoneOneOrMoreInt = int | Iterable[int] | None


def bytes_from_octets(octets: Octets, out_size: NoneOneOrMoreInt = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched. Optionally, it
    also ensures required output size: one size, or any iterable of them,
    and a bool is neither -- `out_size=True` would accept a single octet
    and say it had checked a size.
    """
    if isinstance(octets, str):  # hex string
        octets = bytes.fromhex(octets)

    if out_size is None:
        return octets

    # one size or an iterable of them, and nothing else: `tuple()` on
    # whatever is left would refuse a float with a bare TypeError about
    # iteration -- a complaint about the wrong thing, and from underneath
    # the library rather than through its exception contract
    if isinstance(out_size, int):
        sizes: tuple[int, ...] = (out_size,)
    elif isinstance(out_size, Iterable):
        sizes = tuple(out_size)
    else:
        err_msg = f"invalid output size type: {type(out_size).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)

    for size in sizes:
        if not is_integer(size):
            err_msg = f"invalid output size type: {type(size).__name__}"
            raise BTClibTypeError(err_msg)

    if len(octets) in sizes:
        return octets

    err_msg = f"invalid size: {len(octets)} bytes instead of {out_size}"
    raise BTClibValueError(err_msg)


def bytesio_from_binarydata(stream: BinaryData) -> BytesIO:
    """Return a BytesIO stream object from BinaryIO or Octets.

    If the input is not Octets (i.e. str or bytes), then it goes
    untouched.
    """
    if isinstance(stream, str):  # hex string
        stream = bytes_from_octets(stream)

    if isinstance(stream, bytes):
        stream = BytesIO(stream)

    return stream


def read_exactly(stream: BinaryIO, size: int, what: str) -> bytes:
    """Return size octets from the stream, or raise: a short read is truncation.

    `BytesIO.read` answers with whatever is left when the buffer holds
    less than was asked for, and `int.from_bytes` takes the short answer
    without a word. The size is what makes the field boundary, so it is
    checked whatever `check_validity` says: see this module's docstring
    for why that is not the same question.

    `what` names the field in the error message, the caller knowing which
    one it was reading and the stream not.

    `BinaryIO` and not the `BytesIO` of `alias.BinaryData`: `.read` is
    the whole of what a short read is about, so a file object is as much
    an answer here as a buffer, and `btclib.psbt.psbt_view` reads from
    one -- a view over a psbt is the one reader in this library that does
    not consume the stream it is given, so it does not need one the rest
    of the library can also `getbuffer()`.
    """
    data = stream.read(size)
    if len(data) != size:
        err_msg = f"not enough data for the {what}: "
        err_msg += f"{len(data)} bytes instead of {size}"
        raise BTClibValueError(err_msg)
    return data


def assert_no_trailing(data: BinaryData, stream: BytesIO, what: str) -> None:
    """Refuse bytes left over after a complete octet encoding.

    Octets are one whole object, so what follows the object in them is
    malleability: two buffers deserializing to the one object that
    serializes back to only the shorter of them. A caller's stream is the
    other case, and nothing is checked there -- what follows in it is the
    caller's, a transaction inside a block being read from the very stream
    the block is read from -- so `parse` leaves the stream on the byte
    after the object.

    Bitcoin Core splits the two the same way, between `Unserialize` and
    `DecodeRawPSBT`'s "extra data after PSBT".
    """
    if isinstance(data, BytesIO):
        return

    trailing = stream.read()
    if trailing:
        raise BTClibValueError(f"{len(trailing)} bytes after the {what}")


def is_integer(value: Any) -> bool:
    """Return whether the value is an integer, a bool not being one.

    `isinstance(x, int)` is True for `True` and `False`, `bool` being a
    subclass of `int` -- so every field of this library whose contract is
    an integer quantity accepted a boolean as the number one or zero, and
    `int(True) == True` slips through a conversion-and-equality check as
    well. What makes that worth a refusal rather than a shrug is the json
    boundary: `true` decodes to `True`, so a schema mistake became one
    satoshi, one virtual byte, one index or a one-sat/kvB fee rate instead
    of failing next to the input that caused it.

    A boolean is not another spelling of a number, which is the difference
    from the strings and bytes much of this library accepts: "1" is a
    number written down, `True` is a different type that Python's
    inheritance makes indistinguishable from one.

    `isinstance` and not `type(value) is int`, so an `IntEnum` -- what
    issue #273 asks about for the sighash types -- and any other
    deliberate integer subclass stay integers. `bool` is the one
    subclass excluded, and by name.
    """
    return isinstance(value, int) and not isinstance(value, bool)


def int_from_json_number(value: Any, what: str) -> int:
    """Return the int of a whole number out of json, a bool not being one.

    `from_dict` feeds a constructor a json object, where a whole number
    may arrive as a float -- 1.0 for 1 -- which is why the int fields of
    the dataclasses coerce rather than refuse. A boolean is not one of
    those numbers: `true` decodes to `True`, `int(True)` is 1, and a
    schema mistake would become a version, a depth or an index instead of
    an error beside the input that caused it.

    A *whole* number: 1.0 is the json spelling of 1 and coerces, 1.5 is
    the spelling of nothing this library has a field for, and `int`
    truncates it to 1 rather than refusing -- silently, and to a number
    the caller did write, which is what makes it worse than a type error.
    `float.is_integer()` asks that of the value, `nan` and `inf` being no
    more whole than 1.5 is.

    `is_integer` is the same decision where there is nothing to coerce.
    """
    if isinstance(value, bool):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")
    if isinstance(value, float) and not value.is_integer():
        raise BTClibValueError(f"invalid {what}: {value}")
    try:
        return int(value)
    # what is left is anything at all, this taking Any: a str that is no
    # number, a None, an object. Neither error is btclib's as it stands,
    # and `except ValueError` is what a caller of a json reader writes
    except TypeError as e:
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}") from e
    except ValueError as e:
        raise BTClibValueError(f"invalid {what}: {value!r}") from e


def int_from_bits(octets: Octets, nlen: int) -> int:
    """Return the leftmost nlen bits.

    Take as input a sequence of blen bits and calculate a
    non-negative integer i that is less than 2^nlen according to
    SEC 1 v.2 section 4.1.3 (5); ensuring 0 < i < n would take a
    further reduction modulo n, which is the caller's.

    int_from_bits is not the reverse of i.to_bytes, even
    for input sequences of length nlen: i.to_bytes will add some
    bits on the left, while int_from_bits will discard some bits on the
    right. i.to_bytes is the reverse of int_from_bits only when
    nlen is a multiple of 8 and bit sequences already have length nlen.
    See:
    - https://www.rfc-editor.org/rfc/rfc6979.html#section-2.3.5
    """
    octets = bytes_from_octets(octets)
    i = int.from_bytes(octets, byteorder="big", signed=False)

    blen = len(octets) * 8  # bits
    n = (blen - nlen) if blen >= nlen else 0
    return i >> n


def int_from_integer(i: Integer) -> int:
    r"""Return an int from many possible integer representations.

    Allowed integer representations are:

    * 3735928559
    * -3735928559
    * "0xdeadbeef"
    * "-0xdeadbeef"
    * "deadbeef"
    * b'\xde\xad\xbe\xef'

    A str is always read as a hex-string, with or without the "0x" prefix:
    int_from_integer("1234") is 4660, not one thousand two hundred and
    thirty-four, and "9" raises ValueError for being a hex-string of odd
    length rather than evaluating to nine. A decimal representation is
    what int itself is for, so pass int("1234").

    The binary representation is not allowed because there is no way to
    discriminate it from a valid hex-string
    (e.g. "0b11011110101011011011111011101111").
    """
    if isinstance(i, int):
        return i

    if isinstance(i, str):
        i = i.strip().lower()
        if i.startswith(("0x", "-0x")):
            return int(i, 16)
        i = bytes.fromhex(i)

    # must be bytes
    return int.from_bytes(i, "big", signed=False)


def hex_string(i: Integer) -> str:
    """Return a hex-string from many positive integer representations.

    Negative integers are not allowed.

    The resulting hex-string has an even number of hex-digits and
    includes a space every four bytes (i.e. every eight hex-digits).
    """
    int_ = int_from_integer(i)
    if int_ < 0:
        raise BTClibValueError(f"negative integer: {int_}")
    a_str = f"{int_:x}"
    if len(a_str) % 2 != 0:
        a_str = f"0{a_str}"

    indexes = list(reversed(range(len(a_str), 0, -8)))
    lresult = [(a_str[max(0, i - 8) : i]) for i in indexes]
    result = " ".join(lresult)
    return result.upper()


def decode_num(data: bytes) -> int:
    """Decode a number to the bitcoin-specific little endian format.

    A number is encoded as little-endian variable-length byte vector
    with the most significant bit (MSB) determining the sign.

    * 0x01 is 1
    * 0x81 is -1

    Zero has three spellings, and this reads all three: the empty vector
    that `encode_num` writes and Core's `CScriptNum::set_vch` answers 0
    for, 0x00 -- "positive" zero -- and 0x80, "negative" zero. Only the
    first is minimal; refusing the other two belongs to the reader that
    knows whether MINIMALDATA is in force, which is the engine's
    `_to_num`, and not here.

    Not bounded the way `encode_num` is: this is the reader, and its two
    callers ask different things of it. The engine's `_to_num` caps an
    operand at four bytes -- five for CLTV and CSV -- before it gets
    here, and `Block.height` decodes whatever a coinbase pushed, BIP34
    being a byte comparison rather than a number, so an int64 bound here
    would refuse a coinbase the network accepts.
    """
    length = len(data)
    if length == 0:
        return 0
    i = int.from_bytes(data, byteorder="little", signed=False)
    if data[-1] >= 0x80:  # negative number
        # mask for all but the highest bit
        mask = (2 ** (length * 8) - 1) >> 1
        i &= mask
        i *= -1
    return i


# the int64_t of Core's CScriptNum, which is the type of the only
# parameter `CScript::operator<<` takes a number through: no script Core
# can build carries one outside this range, so no serializer of btclib's
# writes one either (issue #406). Here and not in script.serialize
# because every caller reaches the octets through encode_num
_MIN_SCRIPT_NUM = -(2**63)
_MAX_SCRIPT_NUM = 2**63 - 1


def encode_num(i: int) -> bytes:
    """Encode a number to the bitcoin-specific little endian format.

    A number is encoded as little-endian variable-length byte vector
    with the most significant bit (MSB) determining the sign.

    * 0x01 is 1
    * 0x81 is -1

    Zero is the empty vector, which is Core's `CScriptNum::serialize`
    and is the only spelling of it the interpreter reads back as a
    number: 0x00 and 0x80 -- "positive" and "negative" zero -- decode to
    zero and are refused as operands under MINIMALDATA, `(vch.back() &
    0x7f) == 0` with nothing before it being what Core's `CScriptNum`
    throws on. A push of the empty vector is OP_0, so the shortest
    command and the encoded number agree here and nowhere else (issue
    #646).

    The number is a CScriptNum, i.e. an int64, and a Python int outside
    that range is refused rather than encoded: what it would write is a
    push no node can have built, and one the interpreter -- capping every
    operand at four bytes, five for CLTV and CSV -- cannot read back
    either.

    The bound is on the value and not on the width: the most negative
    int64 is in range and takes nine octets, sign-magnitude having no
    room for its magnitude in eight, which is what Core's
    `CScriptNum::serialize` writes for it as well.
    """
    # before the bound, which is a comparison: `"5" <= 2**63 - 1` is a
    # bare TypeError about the operands, from underneath the library
    # rather than through its exception contract, and True would be the
    # script number one -- the reason `is_integer` names bool
    if not is_integer(i):
        raise BTClibTypeError(f"non-integer script number: {type(i).__name__}")
    if not _MIN_SCRIPT_NUM <= i <= _MAX_SCRIPT_NUM:
        err_msg = f"script number out of range: {i}"
        err_msg += f", not in [{_MIN_SCRIPT_NUM}, {_MAX_SCRIPT_NUM}]"
        raise BTClibValueError(err_msg)

    if i == 0:
        return b""
    # i.bit_length() bits, plus a sign bit
    n_bits = i.bit_length() + 1
    # The number of bytes necessary to accommodate n_bits
    n_bytes = (n_bits + 7) // 8
    # Convert the input number to absolute value + sign in top bit
    encoded_i = abs(i) | ((i < 0) << (n_bytes * 8 - 1))
    # Serialize to bytes
    return encoded_i.to_bytes(n_bytes, byteorder="little", signed=False)
