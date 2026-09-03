# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""MuHash3072: a rolling, order-independent commitment to a multiset.

Core's `MuHash3072` (`src/crypto/muhash.h`/`.cpp`, at
bitcoin/bitcoin@9be056a8a7, tag v31.1) represents a multiset as a
fraction of two 3072-bit numbers modulo the largest 3072-bit safe prime,
`2**3072 - 1103717`: inserting an element multiplies it into the
numerator, removing one multiplies it into the denominator, and the two
operations are exact inverses of each other regardless of order, or of
what else has been inserted or removed meanwhile. `gettxoutsetinfo`'s own
digest of the UTXO set is one such multiset, one element per unspent
output, which is what makes MuHash incremental in a way a plain hash of
the sorted set is not: adding or removing one output is one
multiplication or division, never a walk of what else the set holds.

`insert`/`remove`/`digest` here are Core's `Insert`/`Remove`/`Finalize`,
lower-cased, matched against `src/test/crypto_tests.cpp`'s own
`muhash_tests` case (`tests/_data/muhash_vectors.json`,
`tests/_data/README.md` pins the revision).

The arithmetic is native Python `int`: `pow`, `%` and `pow(x, -1, m)` for
the modular inverse `digest` needs, in place of Core's own limb-by-limb
`Num3072` -- a fixed-width C++ integer split into 32- or 64-bit limbs for
a CPU register that has no 3072-bit width, which Python's own
arbitrary-precision `int` already is without that machinery. What is
committed to -- the modulus, the per-element hash, the byte order -- is
unchanged; only the representation is native rather than reimplementing
Core's carry-and-reduce trick. One divergence this buys for free rather
than by design: `Num3072`'s own "overflow" state (a value held between
the modulus and `2**3072`, only reduced lazily by `FullReduce`) has no
counterpart here, because `% _MODULUS` after every multiply keeps the
numerator and the denominator always fully reduced -- `%` on a Python
`int` is the exact residue whatever the operand's magnitude, so nothing
is lost by reducing eagerly. `crypto_tests.cpp`'s own overflow vector is
matched regardless (`muhash_test.py`'s `test_muhash_overflow_vector`): a
value Core carries unreduced until `Finalize` is folded in here
immediately instead, with the same result either way. Not constant-time
either -- `pow(x, -1, m)` is the extended Euclidean algorithm -- which is
not a concern here: every input `insert`/`remove` sees is public UTXO
set data, never key material, so there is no secret-dependent branch to
time.

## The per-element hash, and ISS #1066's line

`_num3072`, matching `MuHash3072::ToNum3072`: SHA256 of the element's own
bytes (a single SHA256, not bitcoin's usual double one) keys a ChaCha20
stream cipher seeded at nonce zero and block counter zero -- Core's own
default, `ToNum3072` never calling `Seek` -- whose first 384 bytes of
keystream are read as one little-endian 3072-bit integer, matching
`Num3072::ToBytes`, which packs each limb little-endian and the limbs
least-significant first. `_chacha20_block` below is RFC 8439's block
function -- the same `QUARTERROUND` rotation amounts (16, 12, 8, 7) and
the same column-then-diagonal ordering `chacha20.cpp`'s own unrolled
`REPEAT10` carries -- fed the block counter in word 12 and an all-zero
96-bit nonce in words 13-15. Six blocks (`_KEYSTREAM_BLOCKS`) cover the
384 bytes `Num3072::BYTE_SIZE` names; the 32-bit block counter never
overflows into the nonce word Core's own `++j12; if (!j12) ++j13;`
carries into, six being nowhere near 2**32.

[ISS #1066](https://github.com/btclib-org/btclib/issues/1066) put
`chacha20` on tf2's side of the line: btclib takes a cipher from its
caller rather than shipping one, because a hand-rolled cipher would be
the only implementation, on by default, on every installation, on a
network path. This module is not an exception to that rule -- it is an
instance of it read correctly. ChaCha20 enters here as a private
function computing one 3072-bit pseudorandom integer per element hashed;
nothing is encrypted with it, nothing decodes through it, no byte of its
output travels anywhere, and no caller can reach it: `__all__` names
`MuHash3072` and nothing else, so the tree offers no cipher, which is
what ISS #1066 protects against. `_chacha20_keystream` below carries a
`nonce_words`/`counter` pair for exactly one reason -- so that
`tests/muhash_test.py` can drive it against RFC 7539/8439's own vectors,
at a nonce and counter `Seek` sets and `_num3072` never uses -- and
stays private regardless: a caller-reachable knob over an
otherwise-fixed keystream is still a keystream a caller can reach.
"""

from __future__ import annotations

import hashlib

from btclib.alias import Octets
from btclib.utils import bytes_from_octets

__all__ = ["MuHash3072"]

# 2**3072 - 1103717, the largest 3072-bit safe prime -- muhash.cpp's own
# MAX_PRIME_DIFF, at bitcoin/bitcoin@9be056a8a7 (v31.1)
_MODULUS = (1 << 3072) - 1_103_717

# Num3072::BYTE_SIZE (muhash.h) and ChaCha20Aligned::BLOCKLEN (64):
# 384 / 64 == 6, the module docstring's own "six blocks" above
_BYTE_SIZE = 384
_KEYSTREAM_BLOCKS = _BYTE_SIZE // 64
_SERIALIZED_SIZE = 2 * _BYTE_SIZE

_MASK32 = 0xFFFF_FFFF

# the ASCII string "expand 32-byte k", split into four 4-byte
# little-endian words -- ChaCha20's own constant, chacha20.cpp:84-87
_CONSTANTS = (0x6170_7865, 0x3320_646E, 0x7962_2D32, 0x6B20_6574)


def _rotl32(x: int, n: int) -> int:
    """Rotate the low 32 bits of `x` left by `n`, RFC 8439's own `<<<=`."""
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _quarter_round(a: int, b: int, c: int, d: int) -> tuple[int, int, int, int]:
    """One ChaCha20 quarter round -- chacha20.cpp's own `QUARTERROUND` macro."""
    a = (a + b) & _MASK32
    d = _rotl32(d ^ a, 16)
    c = (c + d) & _MASK32
    b = _rotl32(b ^ c, 12)
    a = (a + b) & _MASK32
    d = _rotl32(d ^ a, 8)
    c = (c + d) & _MASK32
    b = _rotl32(b ^ c, 7)
    return a, b, c, d


def _chacha20_block(
    key_words: tuple[int, ...], nonce_words: tuple[int, int, int], counter: int
) -> bytes:
    """Build one 64-byte ChaCha20 block, RFC 8439's own block function.

    `ChaCha20Aligned::Keystream` (chacha20.cpp), unrolled the same way:
    ten double-rounds, columns then diagonals, the original state added
    back into the working state before the block is serialized
    little-endian word by word. `nonce_words` are state words 13-15 --
    `ChaCha20Aligned::Seek`'s own `nonce.first`, then the low and high 32
    bits of `nonce.second` -- and `counter` is word 12.
    """
    x0, x1, x2, x3 = _CONSTANTS
    x4, x5, x6, x7, x8, x9, x10, x11 = key_words
    x12, x13, x14, x15 = counter, *nonce_words

    for _ in range(10):
        x0, x4, x8, x12 = _quarter_round(x0, x4, x8, x12)
        x1, x5, x9, x13 = _quarter_round(x1, x5, x9, x13)
        x2, x6, x10, x14 = _quarter_round(x2, x6, x10, x14)
        x3, x7, x11, x15 = _quarter_round(x3, x7, x11, x15)
        x0, x5, x10, x15 = _quarter_round(x0, x5, x10, x15)
        x1, x6, x11, x12 = _quarter_round(x1, x6, x11, x12)
        x2, x7, x8, x13 = _quarter_round(x2, x7, x8, x13)
        x3, x4, x9, x14 = _quarter_round(x3, x4, x9, x14)

    words = (
        (x0 + _CONSTANTS[0]) & _MASK32,
        (x1 + _CONSTANTS[1]) & _MASK32,
        (x2 + _CONSTANTS[2]) & _MASK32,
        (x3 + _CONSTANTS[3]) & _MASK32,
        (x4 + key_words[0]) & _MASK32,
        (x5 + key_words[1]) & _MASK32,
        (x6 + key_words[2]) & _MASK32,
        (x7 + key_words[3]) & _MASK32,
        (x8 + key_words[4]) & _MASK32,
        (x9 + key_words[5]) & _MASK32,
        (x10 + key_words[6]) & _MASK32,
        (x11 + key_words[7]) & _MASK32,
        (x12 + counter) & _MASK32,
        (x13 + nonce_words[0]) & _MASK32,
        (x14 + nonce_words[1]) & _MASK32,
        (x15 + nonce_words[2]) & _MASK32,
    )
    return b"".join(w.to_bytes(4, "little") for w in words)


def _chacha20_keystream(
    key: bytes,
    blocks: int,
    *,
    nonce_words: tuple[int, int, int],
    counter: int,
) -> bytes:
    """`blocks` blocks (`blocks * 64` bytes) of ChaCha20 keystream.

    `nonce_words` and `counter` are private, so every call site names
    them: `_num3072` below is the only production caller, and passes
    `(0, 0, 0)` and `0`, `ChaCha20Aligned`'s own default.
    `tests/muhash_test.py` is the other caller, driving this function
    against `crypto_tests.cpp`'s own RFC 7539/8439 vectors, at a nonce
    and counter this module never needs otherwise -- including the
    32-bit counter overflow that carries into `nonce_words[0]`, matching
    `chacha20.cpp`'s own `++j12; if (!j12) ++j13;`. Private regardless:
    the module docstring's own "The per-element hash, and ISS #1066's
    line" is where that is argued.
    """
    key_words = tuple(
        int.from_bytes(key[4 * i : 4 * i + 4], "little") for i in range(8)
    )
    out = bytearray()
    for i in range(blocks):
        # ++j12; if (!j12) ++j13; (chacha20.cpp): the 32-bit block
        # counter wraps into the nonce's own first word. total >> 32 is
        # 0 for every block this module's own six-block calls ever
        # reach, and above 0 only for the overflow vector this exercises
        # it against.
        total = counter + i
        block_counter = total & _MASK32
        word0 = (nonce_words[0] + (total >> 32)) & _MASK32
        out += _chacha20_block(
            key_words, (word0, nonce_words[1], nonce_words[2]), block_counter
        )
    return bytes(out)


def _num3072(data: bytes) -> int:
    """`MuHash3072::ToNum3072`: SHA256(data) keys 384 bytes of keystream."""
    key = hashlib.sha256(data).digest()
    keystream = _chacha20_keystream(
        key, _KEYSTREAM_BLOCKS, nonce_words=(0, 0, 0), counter=0
    )
    return int.from_bytes(keystream, "little")


class MuHash3072:
    """A running numerator/denominator over `_MODULUS` -- Core's `MuHash3072`.

    The module docstring is where the construction, the per-element hash
    and the "no overflow state" divergence from Core's own `Num3072` are
    all argued.
    """

    __slots__ = ("_denominator", "_numerator")

    def __init__(self) -> None:
        """Start at the empty set -- `Num3072`'s own `SetToOne`, twice."""
        self._numerator = 1
        self._denominator = 1

    @classmethod
    def singleton(cls, data: Octets) -> MuHash3072:
        """Build a set holding exactly `data` -- the `MuHash3072(span)` ctor."""
        obj = cls()
        obj._numerator = _num3072(bytes_from_octets(data))
        return obj

    def insert(self, data: Octets) -> None:
        """Multiply `data` into the numerator -- `MuHash3072::Insert`."""
        element = _num3072(bytes_from_octets(data))
        self._numerator = (self._numerator * element) % _MODULUS

    def remove(self, data: Octets) -> None:
        """Multiply `data` into the denominator -- `MuHash3072::Remove`.

        The exact inverse of `insert` on the same bytes, in either order
        and regardless of anything else inserted or removed meanwhile:
        `insert`/`remove` only ever multiply the numerator and the
        denominator independently, and a factor common to both cancels
        out at `digest`'s own division whatever else multiplied either
        one in between.
        """
        element = _num3072(bytes_from_octets(data))
        self._denominator = (self._denominator * element) % _MODULUS

    @property
    def digest(self) -> bytes:
        """The 32-byte commitment -- `MuHash3072::Finalize`.

        Core's own `Finalize` divides the numerator by the denominator in
        place and resets the denominator to one -- a normalization that
        leaves the represented *value* unchanged (its own comment says
        so) but is otherwise pure bookkeeping, so this reads the digest
        without mutating `self`: an accumulator keeps accumulating after
        a caller reads its digest, unlike Core's own single-use
        `MuHash3072 acc` locals in `crypto_tests.cpp`. A `@property` and
        not a call, this class offering nothing else `digest()` would be
        read against: `MuHash3072` mirrors no library whose own API fixes
        the shape, the way `btclib.alias.HashObject` mirrors `hashlib`'s.
        """
        value = (self._numerator * pow(self._denominator, -1, _MODULUS)) % _MODULUS
        return hashlib.sha256(value.to_bytes(_BYTE_SIZE, "little")).digest()

    @property
    def serialize(self) -> bytes:
        """Return the numerator, then the denominator, each 384 bytes LE.

        768 bytes in total; `MuHash3072::SERIALIZE_METHODS` serializes
        the same two numbers in the same order.
        """
        return self._numerator.to_bytes(
            _BYTE_SIZE, "little"
        ) + self._denominator.to_bytes(_BYTE_SIZE, "little")

    @classmethod
    def deserialize(cls, data: Octets) -> MuHash3072:
        """Parse the 768 bytes `serialize` produced."""
        raw = bytes_from_octets(data, _SERIALIZED_SIZE)
        obj = cls()
        obj._numerator = int.from_bytes(raw[:_BYTE_SIZE], "little") % _MODULUS
        obj._denominator = int.from_bytes(raw[_BYTE_SIZE:], "little") % _MODULUS
        return obj
