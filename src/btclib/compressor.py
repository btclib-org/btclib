# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's coin compression: `VARINT`, amounts and scripts.

What a snapshot made by `dumptxoutset` and the `chainstate` database
write for a coin, at bitcoin/bitcoin@9be056a8a7, the v31.1 tag:
`VARINT` (`src/serialize.h`), `CompressAmount` and `DecompressAmount`,
and `ScriptCompression` (`src/compressor.cpp`, `src/compressor.h`).

Core's `VARINT` is not `btclib.var_int`, which is CompactSize. Each byte
but the last carries a continuation bit, and the number is less one for
each byte after the first, so that every number has one encoding.

Core's `VARINT` takes the width of the integer it is given. Here that is
`bits`, 64 where the integer is a `uint64_t` and 32 where it is an
`unsigned int`.
"""

from __future__ import annotations

from btclib_ecc.curves import point_from_octets
from btclib_ecc.exceptions import BTClibEccException

from btclib.alias import BinaryData, Octets
from btclib.amount import valid_sats_amount
from btclib.consensus import MAX_SCRIPT_SIZE
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import (
    _message_text,
    bytes_from_octets,
    bytesio_from_binarydata,
    is_integer,
    read_exactly,
)

__all__ = [
    "compress_amount",
    "compress_script",
    "decompress_amount",
    "decompress_script",
    "parse_script",
    "parse_varint",
    "serialize_script",
    "serialize_varint",
]

# `ScriptCompression::nSpecialScripts`: a size below it names a compressed form
_SPECIAL_SCRIPTS = 6

_OP_RETURN = 0x6A
_OP_DUP = 0x76
_OP_HASH160 = 0xA9
_OP_EQUALVERIFY = 0x88
_OP_EQUAL = 0x87
_OP_CHECKSIG = 0xAC

_P2PKH_SIZE = 25
_P2SH_SIZE = 23
_COMPRESSED_P2PK_SIZE = 35
_UNCOMPRESSED_P2PK_SIZE = 67

# the most `parse_script` holds of an oversized script at once
_SKIP_CHUNK = 1 << 16

_UINT64_MAX = 0xFFFF_FFFF_FFFF_FFFF


def _assert_unsigned(value: int, bits: int, what: str) -> None:
    """Refuse what is not an integer of `bits` bits, a bool not being one."""
    if not is_integer(value):
        raise BTClibTypeError(f"non-integer {what}: {_message_text(value)}")
    if not 0 <= value < 1 << bits:
        raise BTClibValueError(f"{what} out of range: {_message_text(value)}")


def _assert_bits(bits: int) -> None:
    """Refuse a width that is no integer from 1 to 64, a bool not being one."""
    if not is_integer(bits) or not 1 <= bits <= 64:
        raise BTClibValueError(f"invalid varint width: {_message_text(bits)}")


def serialize_varint(number: int, bits: int = 64) -> bytes:
    """Return `number` as Core's `VARINT` writes it (`WriteVarInt`).

    `number` is an unsigned integer of `bits` bits, `bits` from 1 to 64.
    """
    _assert_bits(bits)
    _assert_unsigned(number, bits, "varint")
    out = [number & 0x7F]
    while number > 0x7F:
        number = (number >> 7) - 1
        out.append((number & 0x7F) | 0x80)
    return bytes(reversed(out))


def parse_varint(stream: BinaryData, bits: int = 64) -> int:
    """Return the number Core's `VARINT` reads (`ReadVarInt`).

    A number that does not fit `bits` bits is refused, as Core's "size too
    large" does, and so is a stream that ends inside it. Every number has
    one spelling, the offset making a leading `0x80` byte add to the
    number rather than pad it: `80 00` is 128, not 0. No non-minimal
    spelling exists to refuse.
    """
    _assert_bits(bits)
    stream = bytesio_from_binarydata(stream)
    max_value = (1 << bits) - 1
    number = 0
    while True:
        byte = read_exactly(stream, 1, "varint")[0]
        if number > max_value >> 7:
            raise BTClibValueError("varint too large")
        number = (number << 7) | (byte & 0x7F)
        # a width under 7 bits is one the guard above lets a byte past
        if number > max_value:
            raise BTClibValueError("varint too large")
        if not byte & 0x80:
            return number
        if number == max_value:
            raise BTClibValueError("varint too large")
        number += 1


def compress_amount(amount: int) -> int:
    """Return Core's `CompressAmount`: trailing zeros made an exponent.

    Core states it only for 0 <= amount <= `MAX_MONEY`; its uint64
    arithmetic wraps from about 2**64 / 9. An amount above `MAX_MONEY`
    is refused here, which Core does not do.
    """
    if not is_integer(amount):
        raise BTClibTypeError(f"non-integer amount: {_message_text(amount)}")
    valid_sats_amount(amount)
    if amount == 0:
        return 0
    exponent = 0
    while amount % 10 == 0 and exponent < 9:
        amount //= 10
        exponent += 1
    if exponent < 9:
        digit = amount % 10
        amount //= 10
        return 1 + (amount * 9 + digit - 1) * 10 + exponent
    return 1 + (amount - 1) * 10 + 9


def decompress_amount(compressed: int) -> int:
    """Return Core's `DecompressAmount`.

    A compressed value is any `uint64_t`, and the result wraps modulo
    2**64 as Core's does: only a value `compress_amount` could have
    produced is the amount it came from.
    """
    _assert_unsigned(compressed, 64, "compressed amount")
    if compressed == 0:
        return 0
    compressed -= 1
    exponent = compressed % 10
    compressed //= 10
    if exponent < 9:
        digit = compressed % 9 + 1
        compressed //= 9
        number = compressed * 10 + digit
    else:
        number = compressed + 1
    scale: int = 10**exponent
    return (number * scale) & _UINT64_MAX


def _is_p2pk_key_on_curve(pub_key: bytes) -> bool:
    """Say whether an uncompressed public key is a point of secp256k1."""
    try:
        point_from_octets(pub_key)
    except BTClibEccException:
        return False
    return True


def compress_script(script: Octets) -> bytes | None:
    """Return Core's `CompressScript`, or None where there is none.

    A pay-to-pubkey-hash, a pay-to-script-hash and a pay-to-pubkey are a
    type byte and the hash or the x coordinate: 0 and 1 for the hashes, 2
    and 3 for a compressed key, 4 and 5 for an uncompressed key, the type
    holding the parity of its y. An uncompressed key that is not a point
    of the curve has no compressed form.
    """
    script = bytes_from_octets(script)
    size = len(script)
    if (
        size == _P2PKH_SIZE
        and script[0] == _OP_DUP
        and script[1] == _OP_HASH160
        and script[2] == 20
        and script[23] == _OP_EQUALVERIFY
        and script[24] == _OP_CHECKSIG
    ):
        return b"\x00" + script[3:23]
    if (
        size == _P2SH_SIZE
        and script[0] == _OP_HASH160
        and script[1] == 20
        and script[22] == _OP_EQUAL
    ):
        return b"\x01" + script[2:22]
    if (
        size == _COMPRESSED_P2PK_SIZE
        and script[0] == 33
        and script[34] == _OP_CHECKSIG
        and script[1] in (0x02, 0x03)
    ):
        return script[1:34]
    if (
        size == _UNCOMPRESSED_P2PK_SIZE
        and script[0] == 65
        and script[66] == _OP_CHECKSIG
        and script[1] == 0x04
        and _is_p2pk_key_on_curve(script[1:66])
    ):
        return bytes([0x04 | (script[65] & 1)]) + script[2:34]
    return None


def _special_script_size(size: int) -> int:
    """Return `GetSpecialScriptSize`: the bytes a compressed form holds."""
    return 20 if size < 2 else 32


def decompress_script(kind: int, compressed: Octets) -> bytes:
    """Return Core's `DecompressScript`, refusing where it answers false.

    `kind` is the type byte, 0 to 5, and `compressed` the hash or x
    coordinate after it. An x that is not on the curve, under type 4 or
    5, is refused.
    """
    if not is_integer(kind):
        raise BTClibTypeError(f"non-integer script type: {_message_text(kind)}")
    if not 0 <= kind < _SPECIAL_SCRIPTS:
        raise BTClibValueError(f"not a compressed script type: {_message_text(kind)}")
    compressed = bytes_from_octets(compressed)
    if len(compressed) != _special_script_size(kind):
        raise BTClibValueError(
            f"compressed script type {kind} holds "
            f"{_special_script_size(kind)} bytes, not {len(compressed)}"
        )
    if kind == 0:
        return (
            bytes([_OP_DUP, _OP_HASH160, 20])
            + compressed
            + bytes([_OP_EQUALVERIFY, _OP_CHECKSIG])
        )
    if kind == 1:
        return bytes([_OP_HASH160, 20]) + compressed + bytes([_OP_EQUAL])
    if kind < 4:
        return bytes([33, kind]) + compressed + bytes([_OP_CHECKSIG])
    try:
        x, y = point_from_octets(bytes([kind - 2]) + compressed)
    except BTClibEccException as e:
        raise BTClibValueError("x is not on the curve") from e
    uncompressed = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return bytes([65]) + uncompressed + bytes([_OP_CHECKSIG])


def serialize_script(script: Octets) -> bytes:
    """Return a script as `ScriptCompression::Ser` writes it.

    The compressed form where there is one, otherwise the size plus six as
    a `VARINT`, then the script.
    """
    script = bytes_from_octets(script)
    compressed = compress_script(script)
    if compressed is not None:
        return compressed
    return serialize_varint(len(script) + _SPECIAL_SCRIPTS, 32) + script


def parse_script(stream: BinaryData) -> bytes:
    """Return the script `ScriptCompression::Unser` reads.

    Core replaces a script longer than `MAX_SCRIPT_SIZE` with a lone
    `OP_RETURN`, skipping its bytes in bounded reads, as Core's `ignore`
    does, and so does this; a stream that ends inside them is refused. Where
    `DecompressScript` fails, Core leaves the script as it was, silently,
    which is empty for a caller that passes a fresh one; this returns the
    empty script, as for an off-curve key under type 4 or 5.
    """
    stream = bytesio_from_binarydata(stream)
    size = parse_varint(stream, 32)
    if size < _SPECIAL_SCRIPTS:
        compressed = read_exactly(stream, _special_script_size(size), "script")
        try:
            return decompress_script(size, compressed)
        except BTClibValueError:
            return b""
    size -= _SPECIAL_SCRIPTS
    if size <= MAX_SCRIPT_SIZE:
        return read_exactly(stream, size, "script")
    while size:
        chunk = min(size, _SKIP_CHUNK)
        read_exactly(stream, chunk, "script")
        size -= chunk
    return bytes([_OP_RETURN])
