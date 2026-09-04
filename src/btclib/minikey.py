# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Casascius minikey support.

A minikey is a short base58 string -- 20 characters or more, always
starting with `S` -- that stands for a private key: `sha256(text)` is the
key itself, and `sha256(text + "?")` beginning with a zero byte is the
format's own typo check. Casascius physical bitcoins printed one on the
paper disc under their security hologram, at 22 characters for the
Series 1 coins and 30 for every series after -- neither length is
enforced on its own here, matching
`electrum/bitcoin.py:757-769` (`spesmilo/electrum`, pinned at
`342bca3a`) exactly.

**The string is never base58-decoded.** A minikey carries no version
prefix and no Base58Check payload behind it -- the base58 alphabet is
only the character set it happens to be drawn from -- so this module
owns the format rather than `btclib.b58`, which decodes Base58Check and
nothing else.

**The format is dead, and read-only by design.** Casascius stopped
making physical coins in 2013, after FinCEN classified them as money
transmission; a 30-character minikey carries about 160 bits of entropy
and a 22-character one about 128, well short of what a private key
generated today should have. btclib reads a minikey because the coins
already exist and their keys have to be swept out of them, and it
publishes no way to build one.
"""

from __future__ import annotations

from btclib.exceptions import InvalidPrvKeyError, NotAPrvKeyError
from btclib.hashes import sha256
from btclib.key import PrvKeyData
from btclib.network import network_from_name
from btclib.utils import assert_type

__all__ = ["prv_key_data_from_minikey"]

# base58's own alphabet, matched here as a plain character set rather than
# imported from btclib.base58: that module's _ALPHABET is private to it,
# and reaching for it would buy nothing a minikey needs -- this module
# checks characters, never runs the base58 decoder that alphabet feeds
_ALPHABET = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

# electrum/bitcoin.py:758-759 (spesmilo/electrum, pinned at 342bca3a):
# "Minikeys are typically 22 or 30 characters, but this routine permits
# any length of 20 or more provided the minikey is valid." 22 is what
# Casascius Series 1 holograms used and 30 what every later series and
# every other generator uses; electrum enforces neither length on its
# own, only the floor between the two, which is what this module matches
_MIN_LENGTH = 20


def prv_key_data_from_minikey(minikey: str) -> PrvKeyData:
    """Return the private key a Casascius minikey encodes.

    Two error classes, in refusal order, the same split
    `b58.prv_key_data_from_wif` draws for a WIF. The first three checks
    below -- the length, the leading `S`, the alphabet -- ask "is this
    shape a minikey at all", and a no is a NotAPrvKeyError: nothing else
    in this format could have produced such a string, so a caller trying
    several key formats in turn is told to keep going rather than stop.
    The `?`-suffix check asks "is this particular, well-shaped minikey
    sound", and a no is an InvalidPrvKeyError: the shape is a minikey's,
    the typo check is what failed, and it is what the check exists to
    catch -- with probability 255/256 for one wrong character, never a
    proof that no character is wrong, and no other format will read the
    same string differently.

    No message echoes the input or any part of it: unlike a WIF, whose
    text is Base58Check encoding a payload distinct from it, a minikey's
    text is the key material itself, `sha256(minikey)` being the private
    key it stands for.

    The key a minikey encodes carries no network of its own -- Casascius
    coins are a mainnet artefact -- and, by the same physical-coin
    convention, no compression flag beyond "uncompressed": both are
    fixed rather than read from the string.
    """
    assert_type(minikey, str, "minikey")

    if len(minikey) < _MIN_LENGTH:
        err_msg = (
            f"wrong minikey length: {len(minikey)}, at least {_MIN_LENGTH} required"
        )
        raise NotAPrvKeyError(err_msg)
    if minikey[0] != "S":
        raise NotAPrvKeyError("not a minikey: does not start with 'S'")
    if not all(c in _ALPHABET for c in minikey):
        raise NotAPrvKeyError("not a minikey: character outside the base58 alphabet")

    if sha256((minikey + "?").encode("ascii"))[0] != 0x00:
        raise InvalidPrvKeyError("invalid minikey: failed checksum")

    q = int.from_bytes(sha256(minikey.encode("ascii")), byteorder="big")
    ec = network_from_name("mainnet").curve
    if not 0 < q < ec.n:
        raise InvalidPrvKeyError("private key not in 1..n-1")

    # every field has just been checked -- the shape, the checksum, the
    # scalar ranged on the curve -- so the constructor is not asked to
    # check them again
    return PrvKeyData(q, "mainnet", False, check_validity=False)
