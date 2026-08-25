# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Pure Python RIPEMD-160, for an interpreter whose hashlib has none.

Vendored from bitcoin/bitcoin at 08a4a56c, where the file is
test/functional/test_framework/crypto/ripemd160.py: Copyright (c) 2021
Pieter Wuille, distributed under the MIT license, which is this project's
license too, so the copy needs nothing beyond the attribution here.
Taking Core's file rather than writing one keeps the implementation
reviewable against an upstream that Core's own test suite exercises.

The name is upstream's, as every vendored file's is (tests/_data/README.md
says why); the leading underscore is what marks it private, and keeps
tests/docs_test.py from asking for an automodule stanza. It is not API:
`btclib.hashes.ripemd160` is, and it reaches this only where it must.

Five deltas from upstream, every one of them a gate of this repository and
none of them arithmetic:

- type annotations, mypy running strict here
- `fi` raises BTClibValueError where upstream has `assert False`: ruff's
  S101 forbids assert outside tests, and the round number is worth naming
- `if` in place of the `elif` after a return (ruff RET505)
- the unittest.TestCase is dropped, its vectors moved to
  tests/ripemd160_test.py: test code does not ship inside the package
- `# fmt: off` around the six tables, which ruff format would otherwise
  print one index per line: 480 lines to hold 480 numbers, and the grid is
  how the tables are checked against the specification
"""

from __future__ import annotations

from btclib.exceptions import BTClibValueError

# fmt: off
# Message schedule indexes for the left path.
ML = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
]

# Message schedule indexes for the right path.
MR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
]

# Rotation counts for the left path.
RL = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
]

# Rotation counts for the right path.
RR = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
]

# K constants for the left path.
KL = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e]

# K constants for the right path.
KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0]
# fmt: on


def fi(x: int, y: int, z: int, i: int) -> int:
    """Apply f1, f2, f3, f4, or f5 of the specification, as i selects."""
    if i == 0:
        return x ^ y ^ z
    if i == 1:
        return (x & y) | (~x & z)
    if i == 2:
        return (x | ~y) ^ z
    if i == 3:
        return (x & z) | (y & ~z)
    if i == 4:
        return x ^ (y | ~z)
    raise BTClibValueError(f"invalid round number: {i}")


def rol(x: int, i: int) -> int:
    """Rotate the bottom 32 bits of x left by i bits."""
    return ((x << i) | ((x & 0xFFFFFFFF) >> (32 - i))) & 0xFFFFFFFF


def compress(
    h0: int, h1: int, h2: int, h3: int, h4: int, block: bytes
) -> tuple[int, int, int, int, int]:
    """Compress state (h0, h1, h2, h3, h4) with block."""
    # Left path variables.
    al, bl, cl, dl, el = h0, h1, h2, h3, h4
    # Right path variables.
    ar, br, cr, dr, er = h0, h1, h2, h3, h4
    # Message variables.
    x = [int.from_bytes(block[4 * i : 4 * (i + 1)], "little") for i in range(16)]

    # Iterate over the 80 rounds of the compression.
    for j in range(80):
        rnd = j >> 4
        # Perform left side of the transformation.
        al = rol(al + fi(bl, cl, dl, rnd) + x[ML[j]] + KL[rnd], RL[j]) + el
        al, bl, cl, dl, el = el, al, bl, rol(cl, 10), dl
        # Perform right side of the transformation.
        ar = rol(ar + fi(br, cr, dr, 4 - rnd) + x[MR[j]] + KR[rnd], RR[j]) + er
        ar, br, cr, dr, er = er, ar, br, rol(cr, 10), dr

    # Compose old state, left transform, and right transform into new state.
    return h1 + cl + dr, h2 + dl + er, h3 + el + ar, h4 + al + br, h0 + bl + cr


def ripemd160(data: bytes) -> bytes:
    """Compute the RIPEMD-160 hash of data."""
    # Initialize state.
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    # Process full 64-byte blocks in the input.
    for b in range(len(data) >> 6):
        state = compress(*state, data[64 * b : 64 * (b + 1)])
    # Construct final blocks (with padding and size).
    pad = b"\x80" + b"\x00" * ((119 - len(data)) & 63)
    fin = data[len(data) & ~63 :] + pad + (8 * len(data)).to_bytes(8, "little")
    # Process final blocks.
    for b in range(len(fin) >> 6):
        state = compress(*state, fin[64 * b : 64 * (b + 1)])
    # Produce output.
    return b"".join((h & 0xFFFFFFFF).to_bytes(4, "little") for h in state)
