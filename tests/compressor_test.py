# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.compressor` module.

The vectors are Bitcoin Core's, at bitcoin/bitcoin@9be056a8a7 (the v31.1
tag): `src/test/serialize_tests.cpp` for `VARINT` and
`src/test/compress_tests.cpp` for the amounts and the scripts.
"""

from io import BytesIO

import pytest
from btclib_ecc.curves import secp256k1
from hypothesis import example, given
from hypothesis import strategies as st
from typing_extensions import override

from btclib.compressor import (
    compress_amount,
    compress_script,
    decompress_amount,
    decompress_script,
    parse_script,
    parse_varint,
    serialize_script,
    serialize_varint,
)
from btclib.consensus import MAX_SCRIPT_SIZE
from btclib.exceptions import BTClibTypeError, BTClibValueError

COIN = 100_000_000  # src/consensus/amount.h
CENT = 1_000_000

G_X = secp256k1.G[0].to_bytes(32, "big")
G_Y = secp256k1.G[1].to_bytes(32, "big")
# x = 5 has no point on secp256k1: 5**3 + 7 = 132 is not a square mod p
OFF_CURVE_X = (5).to_bytes(32, "big")

# `varints_bitpatterns`, serialize_tests.cpp lines 140-155 (the unsigned
# ones); a number and its encoding
VARINT_BITPATTERNS = [
    (0, "00"),  # line 140
    (0x7F, "7f"),  # 141
    (0x80, "8000"),  # 143, 144
    (0x1234, "a334"),  # 145, 146
    (0xFFFF, "82fe7f"),  # 147, 148
    (0x123456, "c7e756"),  # 149, 150
    (0x80123456, "86ffc7e756"),  # 151, 152
    (0xFFFFFFFF, "8efefefe7f"),  # 153
    (0x7FFFFFFFFFFFFFFF, "fefefefefefefefe7f"),  # 154
    (0xFFFFFFFFFFFFFFFF, "80fefefefefefefefe7f"),  # 155
]


@pytest.mark.parametrize("number, hex_", VARINT_BITPATTERNS)
def test_varint_bitpatterns(number: int, hex_: str) -> None:
    """Core's bit patterns, written and read."""
    assert serialize_varint(number).hex() == hex_
    assert parse_varint(bytes.fromhex(hex_)) == number


def test_varint_loops() -> None:
    """The two loops of `varints`, serialize_tests.cpp lines 109-135."""
    numbers = list(range(100000))
    numbers += range(0, 100000000000, 999999937)
    stream = BytesIO(b"".join(serialize_varint(n) for n in numbers))
    assert [parse_varint(stream) for _ in numbers] == numbers
    assert stream.read() == b""


def test_varint_widths() -> None:
    """A number is refused outside the width it is written or read at."""
    for bits in (0, 65, True):
        with pytest.raises(BTClibValueError, match="invalid varint width"):
            serialize_varint(1, bits)
        with pytest.raises(BTClibValueError, match="invalid varint width"):
            parse_varint(b"\x01", bits)
    assert serialize_varint(0xFFFFFFFF, 32).hex() == "8efefefe7f"
    with pytest.raises(BTClibValueError, match="varint out of range"):
        serialize_varint(0x100000000, 32)
    with pytest.raises(BTClibValueError, match="varint out of range"):
        serialize_varint(0x10000000000000000)
    with pytest.raises(BTClibValueError, match="varint out of range"):
        serialize_varint(-1)
    with pytest.raises(BTClibTypeError, match="non-integer varint"):
        serialize_varint(True)
    # `ReadVarInt`'s "size too large", at the width it reads
    assert parse_varint(bytes.fromhex("8efefefe7f"), 32) == 0xFFFFFFFF
    with pytest.raises(BTClibValueError, match="varint too large"):
        parse_varint(bytes.fromhex("8efefefeff"), 32)
    with pytest.raises(BTClibValueError, match="varint too large"):
        parse_varint(bytes.fromhex("8efefeff7f"), 32)
    with pytest.raises(BTClibValueError, match="varint too large"):
        parse_varint(bytes.fromhex("80fefefefefefefefeff"))
    with pytest.raises(BTClibValueError, match="varint too large"):
        parse_varint(bytes.fromhex("81fefefefefefefefe7f"))


def test_varint_narrow_widths() -> None:
    """A number is refused above `bits` however few bytes it takes."""
    assert parse_varint(b"\x01", 1) == 1
    assert parse_varint(b"\x3f", 6) == 0x3F
    for bits in range(1, 7):
        too_large = 1 << bits
        with pytest.raises(BTClibValueError, match="varint too large"):
            parse_varint(serialize_varint(too_large, 7), bits)
    # a continuation byte past the width, before the next byte is read
    with pytest.raises(BTClibValueError, match="varint too large"):
        parse_varint(b"\x82", 1)


def test_varint_truncated() -> None:
    """A stream that ends inside a number is refused."""
    with pytest.raises(BTClibValueError, match="not enough data"):
        parse_varint(b"")
    with pytest.raises(BTClibValueError, match="not enough data"):
        parse_varint(b"\x80")


def test_varint_is_not_a_compact_size() -> None:
    """`0xfd` is no prefix: it is a continuation byte, then the number."""
    assert parse_varint(b"\xfd\x00") == (0x7D + 1) * 128
    assert serialize_varint(0xFD) == b"\x80\x7d"


def test_varint_has_one_spelling() -> None:
    """A leading `0x80` byte adds to the number, so it is never padding."""
    assert parse_varint(b"\x80\x00") == 128
    assert parse_varint(b"\x00") == 0
    assert parse_varint(b"\x80\x80\x00") == 128 * 128 + 128


def test_varint_stream_position() -> None:
    """A read leaves the stream after the number."""
    stream = BytesIO(b"\x80\x00\x7f\xff")
    assert parse_varint(stream) == 0x80
    assert parse_varint(stream) == 0x7F
    assert stream.read() == b"\xff"


# `compress_amounts`, compress_tests.cpp lines 43-48
AMOUNT_PAIRS = [
    (0, 0x0),
    (1, 0x1),
    (CENT, 0x7),
    (COIN, 0x9),
    (50 * COIN, 0x32),
    (21000000 * COIN, 0x1406F40),
]


@pytest.mark.parametrize("amount, compressed", AMOUNT_PAIRS)
def test_amount_pairs(amount: int, compressed: int) -> None:
    """Core's pairs, both ways."""
    assert compress_amount(amount) == compressed
    assert decompress_amount(compressed) == amount


def test_amount_loops() -> None:
    """The loops of `compress_amounts`, compress_tests.cpp lines 50-63."""
    for i in range(1, 100001):
        assert decompress_amount(compress_amount(i)) == i
    for i in range(1, 10001):
        assert decompress_amount(compress_amount(i * CENT)) == i * CENT
        assert decompress_amount(compress_amount(i * COIN)) == i * COIN
    for i in range(1, 420001, 7):
        assert decompress_amount(compress_amount(i * 50 * COIN)) == i * 50 * COIN
    for i in range(100000):
        assert compress_amount(decompress_amount(i)) == i


def test_amount_refusals() -> None:
    """Past `MAX_MONEY`, a negative, a bool or a string is refused."""
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        compress_amount(21000000 * COIN + 1)
    with pytest.raises(BTClibValueError, match="invalid satoshi amount"):
        compress_amount(-1)
    with pytest.raises(BTClibTypeError, match="non-integer amount"):
        compress_amount(True)
    with pytest.raises(BTClibTypeError, match="non-integer amount"):
        compress_amount("1")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="compressed amount out of range"):
        decompress_amount(2**64)
    with pytest.raises(BTClibValueError, match="compressed amount out of range"):
        decompress_amount(-1)
    with pytest.raises(BTClibTypeError, match="non-integer compressed amount"):
        decompress_amount(False)


def test_decompress_amount_wraps() -> None:
    """The results of Core's own `DecompressAmount`, compiled from its source.

    Each is a number the arithmetic carries past 2**64.
    """
    assert decompress_amount(2**64 - 1) == 2049638230412174624
    assert decompress_amount(184490445900) == 2300516290448384


# the scripts of `compress_script_to_*`, compress_tests.cpp lines 66-133
HASH = bytes(range(20))
P2PKH = b"\x76\xa9\x14" + HASH + b"\x88\xac"
P2SH = b"\xa9\x14" + HASH + b"\x87"
P2PK_COMPRESSED = b"\x21\x02" + G_X + b"\xac"
P2PK_UNCOMPRESSED = b"\x41\x04" + G_X + G_Y + b"\xac"

SCRIPT_PAIRS = [
    (P2PKH, b"\x00" + HASH),
    (P2SH, b"\x01" + HASH),
    (P2PK_COMPRESSED, b"\x02" + G_X),
    (b"\x21\x03" + G_X + b"\xac", b"\x03" + G_X),
    # G's y is even, so the parity is 0; the other root of x is odd
    (P2PK_UNCOMPRESSED, b"\x04" + G_X),
    (
        b"\x41\x04"
        + G_X
        + (secp256k1.p - secp256k1.G[1]).to_bytes(32, "big")
        + b"\xac",
        b"\x05" + G_X,
    ),
]


@pytest.mark.parametrize("script, compressed", SCRIPT_PAIRS)
def test_script_pairs(script: bytes, compressed: bytes) -> None:
    """Each compressible form, in every direction."""
    assert compress_script(script) == compressed
    assert decompress_script(compressed[0], compressed[1:]) == script
    assert serialize_script(script) == compressed
    stream = BytesIO(compressed + b"\xff")
    assert parse_script(stream) == script
    assert stream.read() == b"\xff"


def test_compress_script_none() -> None:
    """Scripts one byte off a compressible form are not compressed."""
    off_curve = b"\x41\x04" + OFF_CURVE_X + G_Y + b"\xac"
    for script in (
        b"",
        P2PKH[:-1] + b"\xad",
        P2PKH[:2] + b"\x13" + P2PKH[3:],
        P2SH[:-1] + b"\x88",
        P2PK_COMPRESSED[:-1] + b"\xad",
        b"\x21\x04" + G_X + b"\xac",
        b"\x41\x04" + G_X + G_Y[:-1] + b"\xac",
        P2PK_UNCOMPRESSED[:1] + b"\x02" + P2PK_UNCOMPRESSED[2:],
        # `compress_p2pk_scripts_not_on_curve`, compress_tests.cpp line 135
        off_curve,
    ):
        assert compress_script(script) is None


def test_off_curve_x_is_not_decompressed() -> None:
    """`compress_p2pk_scripts_not_on_curve`, compress_tests.cpp 157-164."""
    for kind in (4, 5):
        with pytest.raises(BTClibValueError, match="not on the curve"):
            decompress_script(kind, OFF_CURVE_X)
    # `Unser` ignores the failure, and leaves the script empty
    assert parse_script(b"\x04" + OFF_CURVE_X) == b""
    assert parse_script(b"\x05" + OFF_CURVE_X) == b""


def test_decompress_script_refusals() -> None:
    """A type or a length no compressed script has is refused."""
    with pytest.raises(BTClibValueError, match="not a compressed script type"):
        decompress_script(6, HASH)
    with pytest.raises(BTClibValueError, match="not a compressed script type"):
        decompress_script(-1, HASH)
    with pytest.raises(BTClibTypeError, match="non-integer script type"):
        decompress_script(True, HASH)
    with pytest.raises(BTClibValueError, match="type 0 holds 20 bytes, not 19"):
        decompress_script(0, HASH[:-1])
    with pytest.raises(BTClibValueError, match="type 3 holds 32 bytes, not 20"):
        decompress_script(3, HASH)


def test_other_scripts() -> None:
    """Any other script is its size plus six, then the script."""
    for size in (0, 1, 121, 122, MAX_SCRIPT_SIZE):
        script = b"\x51" * size
        serialized = serialize_script(script)
        assert serialized == serialize_varint(size + 6) + script
        assert parse_script(serialized) == script
    # `ScriptCompression`'s doc: up to 121 bytes cost one byte, to 16505 two
    assert len(serialize_script(b"\x51" * 121)) == 122
    assert len(serialize_script(b"\x51" * 122)) == 124


def test_oversized_script_is_op_return() -> None:
    """Over `MAX_SCRIPT_SIZE`, the bytes are skipped and `OP_RETURN` is left."""
    size = MAX_SCRIPT_SIZE + 1
    stream = BytesIO(serialize_varint(size + 6) + b"\x51" * size + b"\xff")
    assert parse_script(stream) == b"\x6a"
    assert stream.read() == b"\xff"


def test_script_truncated() -> None:
    """A script that the stream does not hold is refused."""
    with pytest.raises(BTClibValueError, match="not enough data"):
        parse_script(b"")
    with pytest.raises(BTClibValueError, match="not enough data"):
        parse_script(b"\x00" + HASH[:-1])
    with pytest.raises(BTClibValueError, match="not enough data"):
        parse_script(serialize_varint(10 + 6) + b"\x51" * 9)
    # a size no stream holds, which is skipped and not allocated
    with pytest.raises(BTClibValueError, match="not enough data"):
        parse_script(serialize_varint(0xFFFFFFFF, 32) + b"\x51")
    # `Unser` reads its size as an `unsigned int`
    with pytest.raises(BTClibValueError, match="varint too large"):
        parse_script(serialize_varint(0x100000000))


@given(st.integers(min_value=0, max_value=2**64 - 1))
def test_varint_roundtrip(number: int) -> None:
    """Every number is read back, and the read stops at its end."""
    serialized = serialize_varint(number)
    assert parse_varint(serialized) == number
    # the read takes the bytes of the number and no more
    stream = BytesIO(serialized + b"\x00")
    assert parse_varint(stream) == number
    assert stream.read() == b"\x00"


@given(st.integers(min_value=0, max_value=21000000 * COIN))
def test_amount_roundtrip(amount: int) -> None:
    """Every amount up to `MAX_MONEY` is read back."""
    compressed = compress_amount(amount)
    assert compressed <= 2**64 - 1
    assert decompress_amount(compressed) == amount


def _unwrapped_decompress(compressed: int) -> int:
    """Return `DecompressAmount`'s arithmetic without the uint64 wrap."""
    if compressed == 0:
        return 0
    compressed -= 1
    exponent = compressed % 10
    compressed //= 10
    if exponent < 9:
        number = compressed // 9 * 10 + compressed % 9 + 1
    else:
        number = compressed + 1
    scale: int = 10**exponent
    return number * scale


@given(st.integers(min_value=0, max_value=2**64 - 1))
@example(10 * 2**55)  # wraps to 0 modulo 2**64, and 0 is in range
def test_compressed_amount_roundtrip(compressed: int) -> None:
    """A value that does not wrap is the one `compress_amount` makes."""
    if _unwrapped_decompress(compressed) < 2**64:
        amount = decompress_amount(compressed)
        if amount <= 21000000 * COIN:
            assert compress_amount(amount) == compressed
    else:
        assert decompress_amount(compressed) == (
            _unwrapped_decompress(compressed) % 2**64
        )


def test_oversized_script_is_skipped_in_chunks() -> None:
    """The bytes of an oversized script are never read at once."""
    reads: list[int] = []

    class Recording(BytesIO):
        @override
        def read(self, size: int | None = -1, /) -> bytes:
            reads.append(-1 if size is None else size)
            return super().read(size)

    size = 3 * 65536 + 5
    stream = Recording(serialize_varint(size + 6, 32) + b"\x51" * size + b"\xff")
    assert parse_script(stream) == b"\x6a"
    assert max(reads) <= 65536
    assert stream.read() == b"\xff"


@given(st.binary(max_size=200))
def test_script_roundtrip(script: bytes) -> None:
    """Every script is read back."""
    assert parse_script(serialize_script(script)) == script
