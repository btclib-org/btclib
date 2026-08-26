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
tx_id and four of vout, and every value of that shape is an outpoint
Bitcoin Core accepts. A class whose only invalidable child is one --
`TxIn`, whose own fields are of the same kind -- inherits the property.

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

from collections.abc import Iterable, Mapping
from io import BytesIO
from typing import Any, BinaryIO

from btclib.alias import BinaryData, Integer, Octets, String
from btclib.exceptions import BTClibTypeError, BTClibValueError

__all__ = [
    "NoneOneOrMoreInt",
    "assert_no_trailing",
    "assert_type",
    "bytes_from_octets",
    "bytesio_from_binarydata",
    "decode_num",
    "encode_num",
    "fields_from_json_object",
    "hex_string",
    "int_from_bits",
    "int_from_integer",
    "int_from_json_number",
    "is_integer",
    "is_octets",
    "list_from_json_array",
    "read_exactly",
    "str_from_string",
]

NoneOneOrMoreInt = int | Iterable[int] | None


def _assert_contiguous(octets: bytes | bytearray | memoryview) -> None:
    """Refuse a non-contiguous memoryview, the one buffer that can be one.

    `bytes` and `bytearray` are always C-contiguous; a `memoryview` need
    not be -- a strided slice such as `mv[::2]` is not, and is returned
    by `bytes_from_octets` untouched unless refused here.
    """
    if isinstance(octets, memoryview) and not octets.c_contiguous:
        err_msg = "invalid octets: non-contiguous memoryview"
        raise BTClibValueError(err_msg)


def bytes_from_octets(octets: Octets, out_size: NoneOneOrMoreInt = None) -> bytes:
    """Return bytes from a hex-string, stripping leading/trailing spaces.

    If the input is not a string, then it goes untouched. Optionally, it
    also ensures required output size: one size, or any iterable of them,
    and a bool is neither -- `out_size=True` would accept a single octet
    and say it had checked a size.

    A non-contiguous `memoryview` -- what a strided slice such as
    `mv[::2]` gives -- is refused here rather than handed back: every
    other consumer of the buffer this returns needs a C-contiguous one,
    `hash160` failing with a bare `BufferError` being one of them, so the
    refusal is raised through the exception contract at the one place
    every `Octets` parameter passes rather than left to whichever
    consumer trips over it first.
    """
    if isinstance(octets, str):  # hex string
        # `bytes.fromhex` raises a bare ValueError -- the same class the
        # contract promises, so what was lost is only that it came from
        # here. This is the one coercion every `Octets` parameter of the
        # library runs through, so it is the one place worth saying it in.
        # The message is fromhex's own, which names a position and never
        # the string: an Octets parameter is candidate key material as
        # often as not, and `to_prv_key` puts this very message inside its
        # own "not a private key" (issue #137)
        try:
            octets = bytes.fromhex(octets)
        except ValueError as e:
            raise BTClibValueError(f"invalid hex string: {e}") from e
    elif isinstance(octets, (bytes, bytearray, memoryview)):
        _assert_contiguous(octets)
    else:
        # what is neither went through untouched and reached whatever the
        # caller went on to do with it: `len` of a tuple of 33 ints is 33,
        # so `taproot.assert_valid_control_block` accepted one as a
        # control block size.
        # Every buffer and not `bytes` alone, and returned as it came:
        # `assert_valid` is a read and must not rewrite the field it
        # reads, which is what `bytes()` here would do to a bytearray a
        # caller built (`tests/bip32/bip32_test.py` pins it)
        err_msg = f"invalid octets type: {type(octets).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)

    if out_size is None:
        # the annotation says `bytes` and this hands back the buffer it
        # was given, which the widened `Octets` is what makes visible:
        # disclosed rather than silenced, because making the signature
        # true is a change across the tree and its own (issue #1255)
        return octets  # type: ignore[return-value]

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
        return octets  # type: ignore[return-value]

    err_msg = f"invalid size: {len(octets)} bytes instead of {out_size}"
    raise BTClibValueError(err_msg)


def str_from_string(s: String, what: str) -> str:
    """Return the text of a String, whether it came as text or as ascii bytes.

    What `bytes_from_octets` is to `Octets`, in the direction the
    addresses go: an address, a WIF and an xkey are ascii,
    so a byte outside it is an invalid character like any other and gets
    the same answer -- a UnicodeDecodeError let out would fly past every
    caller written to catch a BTClibValueError.

    `what` names the string in both messages, the caller knowing what it
    was reading and this not, exactly as `read_exactly` names a field.

    Nothing is stripped and nothing is lowered: which of those is right
    is the caller's to know, a message to be signed being the one String
    whose blanks are part of it.
    """
    if isinstance(s, str):
        return s

    if not isinstance(s, (bytes, bytearray, memoryview)):
        # what is neither went through untouched, to fail on `len` or on
        # a method of str that the value does not have -- a complaint
        # about a builtin rather than about the argument
        err_msg = f"invalid {what} type: {type(s).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)

    try:
        return bytes(s).decode("ascii")
    except UnicodeDecodeError as e:
        raise BTClibValueError(f"non-ascii character in {what}: {e}") from e


def bytesio_from_binarydata(stream: BinaryData) -> BytesIO:
    """Return a BytesIO stream object from a BytesIO or from Octets.

    A `BytesIO` is the caller's own and is handed back as it came, the
    position it is left at being how a transaction is read out of a
    block. Anything else is octets, and is wrapped in one.

    A `BytesIO` and not any binary stream: `deserialize_map` asks the
    result for `getbuffer()`, which a file object does not have, so
    accepting one here would only move the failure. `read_exactly` is
    the one that takes a `BinaryIO`, and its docstring says why.
    """
    if isinstance(stream, BytesIO):
        return stream

    # the refusal of what is neither a stream nor octets is
    # bytes_from_octets's to give: without it, what is neither would go
    # through untouched and be returned as it came, so `parse` would
    # answer a None with a None and the caller would fail on `.read`
    # rather than here
    return BytesIO(bytes_from_octets(stream))


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


def is_octets(value: Any) -> bool:
    """Return whether the value is one Octets, rather than a sequence of them.

    An `Octets` -- `str`, `bytes`, `bytearray` or `memoryview` -- is
    itself iterable, so a function that takes a sequence of them and
    guards against being handed one instead cannot ask `isinstance(value,
    Sequence)`: every `Octets` answers that too. The guard asks this
    question instead, once, so a spelling `Octets` gains later is refused
    at every caller of this rather than at whichever remembered to list
    it (issue #1261).
    """
    return isinstance(value, Octets)


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


def assert_type(value: Any, expected: Any, what: str) -> None:
    """Refuse a value of a type the signature does not declare.

    `expected` is what `isinstance` takes: one type, or a tuple of them.
    `bytes_from_octets` and `str_from_string` are the two coercions this
    library has, and each refuses what it cannot convert; this is the
    refusal for a position that takes neither -- a `bool` flag deciding
    which of two serializations is written, the text of a URI or a
    descriptor, the magic bytes an envelope is read against. Every one of
    those was compared, walked or handed to a builtin unasked, and left
    as a complaint about that builtin.

    `value` is `Any` rather than the declared type, which is what makes
    the check reachable: mypy proves the argument cannot be wrong, and
    the caller who has not run mypy is who this is for.
    """
    if not isinstance(value, expected):
        raise BTClibTypeError(f"invalid {what} type: {type(value).__name__}")


class _JsonObject(dict[str, Any]):
    """A json object that says which field it has not got.

    `dict.__getitem__` calls `__missing__` on a key it does not hold, and
    the default raises the `KeyError` that is not a `BTClibException`; a
    subclass is what lets every `dict_[...]` in a `from_dict` stay the
    plain lookup it reads as and still answer through the contract.
    """

    def __init__(self, what: str, dict_: Mapping[str, Any]) -> None:
        super().__init__(dict_)
        self.what = what

    def __missing__(self, key: str) -> Any:
        raise BTClibValueError(f"missing {self.what} field: {key}")


def fields_from_json_object(dict_: Any, what: str) -> Mapping[str, Any]:
    """Return the fields of a json object, refusing what is not one.

    The first line of every `from_dict`, and it answers the two questions
    that boundary owes its caller before a field is read:

    - a `Mapping[str, Any]` is what the signature declares, and the check
      refuses what is not one before it is walked: without it,
      `dict_["version"]` on a None is a TypeError about subscripting, on
      a str a TypeError about string indices, and neither says btclib
      refused anything
    - a mapping that is one and has not got the field is a value no valid
      input carries, so it is a `BTClibValueError` naming the field --
      `from_dict` is fed whatever a schema mistake produced, and a bare
      `KeyError` is neither a `BTClibException` nor a `ValueError`

    `what` names the object, the caller knowing what it is reading and
    this not, as `read_exactly` names a field. `.get` is untouched and
    stays the spelling for a field that may be absent.

    `Any` rather than the `Mapping` every caller declares, for the reason
    `assert_type` takes one: the check is here for the caller mypy did
    not read.
    """
    assert_type(dict_, Mapping, f"{what} dict")
    return _JsonObject(what, dict_)


def list_from_json_array(value: Any, what: str) -> list[Any]:
    """Return the list of a json array, a str and a mapping not being one.

    What `fields_from_json_object` is to the object, for the arrays a
    `from_dict` walks: the inputs of a transaction, the transactions of a
    block, the stack of a witness. Unasked, a non-iterable is "not
    iterable" from underneath the library, and the two iterables that are
    not arrays are worse than that -- a `str` is a list of its characters
    and a `Mapping` a list of its keys, so each element is refused for
    what it is not rather than the whole for what it is. `is_octets` is
    the four `Octets` spellings named once rather than listed here, so a
    spelling `Octets` gains later is refused the same way (issue #1420);
    `Mapping` is refused beside it for a reason of its own and stays a
    named check.
    """
    if (
        is_octets(value)
        or isinstance(value, Mapping)
        or not isinstance(value, Iterable)
    ):
        err_msg = f"invalid {what} type: {type(value).__name__}"
        raise BTClibTypeError(err_msg)
    return list(value)


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

    A bool is not one of them, `is_integer` being where this library
    says so: every `Integer` parameter runs through here, so the refusal
    is stated once and inherited (issue #1206).

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
        # `is_integer` and not the `isinstance` above: a bool is an int
        # to Python and is not a number to this library, which is the
        # rule issue #326 gave every integer field and issue #1206 found
        # the key path without. Here rather than at each caller, this
        # being the one coercion every `Integer` parameter runs through
        if not is_integer(i):
            raise BTClibTypeError(f"non-integer: {i}")
        return i

    if isinstance(i, str):
        i = i.strip().lower()
        if i.startswith(("0x", "-0x")):
            # the same bare ValueError bytes_from_octets names below, out
            # of the one spelling that does not reach it
            try:
                return int(i, 16)
            except ValueError as e:
                raise BTClibValueError(f"invalid hex integer: {i!r}") from e

    # the hex string, and the refusal of what is neither that nor bytes,
    # both being bytes_from_octets's to give
    return int.from_bytes(bytes_from_octets(i), "big", signed=False)


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
