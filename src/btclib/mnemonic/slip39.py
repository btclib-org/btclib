# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""SLIP-0039 share / master secret / seed functions.

https://github.com/satoshilabs/slips/blob/master/slip-0039.md.

Shamir backup, the scheme every Trezor since 2019 offers. A master
secret is split into *shares*, of which a threshold number is required
to put it back together; fewer than that leak nothing about it. The
master secret is the BIP32 seed itself, not entropy to be stretched
into one, so ``mxprv_from_mnemonics`` hands it straight to
``rootxprv_from_seed``.

The split is two-level. The master secret is encrypted under the
passphrase, the result split ``GT``-of-``G`` into *group* shares, and
each group share split ``T``-of-``N`` into the *member* shares people
actually hold. A plain ``T``-of-``N`` backup is the degenerate case:
one group, split at the member level.

Four pieces underneath, none of them shared with BIP39:

* Shamir's scheme over GF(256), applied byte by byte, with the secret
  at ``f(255)`` and a digest of it at ``f(254)`` so that a wrong set of
  shares is caught rather than silently reconstructing rubbish
* an RS1024 checksum over the 10-bit word indexes, three words long
* a two-level group/member threshold structure, four bits per index and
  per threshold, which is what caps both at 16
* a four-round Feistel network with PBKDF2-HMAC-SHA256 as the round
  function, encrypting the master secret under the passphrase

The word-list is SLIP-0039's own 1024 words, ten bits each; it is not
BIP39's, and no localization exists.

+----------+---------------------------+---------------------+
| Security | Padded share value length | Total share length  |
+==========+===========================+=====================+
| 128 bits | 130 bits                  | 200 bits = 20 words |
+----------+---------------------------+---------------------+
| 256 bits | 260 bits                  | 330 bits = 33 words |
+----------+---------------------------+---------------------+

Both recovery and generation are here. Recovery alone is what a wallet
needs and what several implementations stop at; a library is asked the
other question too -- and generation is also what lets the round trip
be tested against something other than itself.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import pbkdf2_hmac, sha256

from btclib.alias import Octets
from btclib.bip32 import rootxprv_from_seed
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.entropy import (
    bin_str_entropy_from_wordlist_indexes,
    wordlist_indexes_from_bin_str_entropy,
)
from btclib.mnemonic.mnemonic import (
    WORDLISTS,
    Mnemonic,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
)
from btclib.network import network_from_name
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "Share",
    "master_secret_from_mnemonics",
    "mnemonic_from_share",
    "mnemonics_from_master_secret",
    "mxprv_from_mnemonics",
    "share_from_mnemonic",
]

# the key of the SLIP-0039 word-list in WORDLISTS; a scheme and not a
# language code, SLIP-0039 having no localization at all
_LANG = "slip39"

_RADIX_BITS = 10

# the share layout in bits: id || ext || e || GI || Gt || g || I || t,
# then the padded share value, then the checksum
_ID_BITS = 15
_EXT_BITS = 1
_E_BITS = 4
# each of the group index, group threshold, group count, member index
# and member threshold; four bits is what caps G and N at 16
_FIELD_BITS = 4
_HEADER_BITS = _ID_BITS + _EXT_BITS + _E_BITS + 5 * _FIELD_BITS
_CHECKSUM_WORDS = 3
_CHECKSUM_BITS = _CHECKSUM_WORDS * _RADIX_BITS

_MAX_SHARE_COUNT = 1 << _FIELD_BITS

# the master secret must be at least 128 bits and a multiple of 16 bits
_MIN_SECRET_BYTES = 16

# the shortest mnemonic: the header, the checksum, and the smallest
# share value padded up to a whole number of words -- 128 bits in 13
_MIN_VALUE_WORDS = -(-8 * _MIN_SECRET_BYTES // _RADIX_BITS)
_MIN_WORDS = (_HEADER_BITS + _CHECKSUM_BITS) // _RADIX_BITS + _MIN_VALUE_WORDS

# the x coordinates SLIP-0039 reserves; 255 rather than the usual 0 so
# that no share index has to be rejected as invalid
_SECRET_X = 255
_DIGEST_X = 254
_DIGEST_BYTES = 4

_ROUNDS = 4
_BASE_ITERATIONS = 2500


def _gf256_tables() -> tuple[list[int], list[int]]:
    """Return the exp/log tables of GF(256), generator 3.

    Bytes are elements of GF(256) modulo the Rijndael polynomial, as in
    AES. A table pair is what makes multiplication and division a table
    lookup and an addition modulo 255; there is no entry for 0, which
    has no logarithm, and none is ever read -- every argument reaching
    ``_log`` here is non-zero by construction.
    """
    exp = [0] * 255
    log = [0] * 256
    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i
        # multiply by the generator, x + 1, reducing modulo x**8 + x**4
        # + x**3 + x + 1 whenever the product overflows a byte
        poly = (poly << 1) ^ poly
        if poly & 0x100:
            poly ^= 0x11B
    return exp, log


_EXP, _LOG = _gf256_tables()


def _mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[(_LOG[a] + _LOG[b]) % 255]


def _div(a: int, b: int) -> int:
    """Return a/b in GF(256); both operands are non-zero."""
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _interpolate(points: Sequence[tuple[int, bytes]], x: int) -> bytes:
    """Return the value-vector of the Lagrange interpolation at x.

    Shamir's scheme runs once per byte, so a point is an index and a
    whole vector of values. The Lagrange basis depends on the indexes
    alone, hence is computed once per point and reused across the
    bytes.

    x is never one of the indexes: it is 254 or 255, which four bits
    cannot hold, or -- when generating -- an index above every one of
    the base points. So no basis denominator vanishes, and the division
    needs no guard.
    """
    result = bytearray(len(points[0][1]))
    for x_i, y_i in points:
        basis = 1
        for x_j, _ in points:
            if x_j != x_i:
                basis = _mul(basis, _div(x ^ x_j, x_i ^ x_j))
        for k, y in enumerate(y_i):
            result[k] ^= _mul(y, basis)
    return bytes(result)


def _digest(random_part: bytes, shared_secret: bytes) -> bytes:
    """Return the four-byte digest stored at index 254.

    Keyed on the random part rather than plain SHA256 of the secret:
    that is what stops an attacker holding the first bytes of T-1
    shares from brute-forcing the rest against the digest.
    """
    return hmac.new(random_part, shared_secret, sha256).digest()[:_DIGEST_BYTES]


# the generator of the RS1024 code, a Reed-Solomon code over GF(1024)
# whose alphabet is the 10-bit word index; the SLIP gives it as a table
_RS1024_GEN = (
    0xE0E040,
    0x1C1C080,
    0x3838100,
    0x7070200,
    0xE0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x3F3F120,
)


def _rs1024_polymod(values: Sequence[int]) -> int:
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xFFFFF) << 10 ^ v
        for i in range(10):
            chk ^= _RS1024_GEN[i] if ((b >> i) & 1) else 0
    return chk


def _customization_string(extendable: bool) -> list[int]:
    """Return the RS1024 customization string, as US-ASCII values.

    The extendable backup flag picks the string, so a share of one kind
    fails the checksum of the other: the two are different codes, not
    the same code over different data.
    """
    cs = "shamir_extendable" if extendable else "shamir"
    return [ord(char) for char in cs]


def _rs1024_checksum(indexes: Sequence[int], extendable: bool) -> list[int]:
    values = _customization_string(extendable) + list(indexes) + [0, 0, 0]
    polymod = _rs1024_polymod(values) ^ 1
    return [(polymod >> 10 * (2 - i)) & 1023 for i in range(_CHECKSUM_WORDS)]


def _rs1024_verify(indexes: Sequence[int], extendable: bool) -> bool:
    return _rs1024_polymod(_customization_string(extendable) + list(indexes)) == 1


def _assert_valid_length(n_bytes: int, what: str) -> None:
    if n_bytes < _MIN_SECRET_BYTES or n_bytes % 2:
        err_msg = f"invalid {what} length: {n_bytes} bytes; "
        err_msg += f"must be at least {_MIN_SECRET_BYTES} and even"
        raise BTClibValueError(err_msg)


@dataclass(frozen=True)
class Share:
    """A single SLIP-0039 share, i.e. one decoded mnemonic.

    The thresholds and the group count are the true values, 1 to 16,
    not the zero-based numbers the mnemonic encodes; the indexes are
    zero-based, as encoded, because they are x coordinates and nothing
    else.
    """

    identifier: int
    extendable: bool
    iteration_exponent: int
    group_index: int
    group_threshold: int
    group_count: int
    member_index: int
    member_threshold: int
    value: bytes

    def __post_init__(self) -> None:
        self.assert_valid()

    def assert_valid(self) -> None:
        """Raise if a field is outside what the share format can hold."""
        top = _MAX_SHARE_COUNT - 1
        for name, value, lower, upper in (
            ("identifier", self.identifier, 0, (1 << _ID_BITS) - 1),
            ("iteration exponent", self.iteration_exponent, 0, (1 << _E_BITS) - 1),
            ("group index", self.group_index, 0, top),
            ("group threshold", self.group_threshold, 1, _MAX_SHARE_COUNT),
            ("group count", self.group_count, 1, _MAX_SHARE_COUNT),
            ("member index", self.member_index, 0, top),
            ("member threshold", self.member_threshold, 1, _MAX_SHARE_COUNT),
        ):
            if not lower <= value <= upper:
                err_msg = f"invalid {name}: {value}, not in [{lower}-{upper}]"
                raise BTClibValueError(err_msg)
        # a group cannot need more shares than it has, and both numbers
        # are in every share, so this is a property of one share and
        # checked here rather than when a set of them is combined
        if self.group_count < self.group_threshold:
            err_msg = f"group count {self.group_count} "
            err_msg += f"smaller than group threshold {self.group_threshold}"
            raise BTClibValueError(err_msg)
        _assert_valid_length(len(self.value), "share value")


def _indexes_from_mnemonic(mnemonic: Mnemonic) -> list[int]:
    """Return the 10-bit word indexes of a SLIP-0039 mnemonic."""
    try:
        return indexes_from_mnemonic(mnemonic, _LANG)
    except ValueError as e:
        # indexes_from_mnemonic reports an unknown word as a plain
        # ValueError from list.index; the caller of a btclib function
        # should not have to catch two exception types to learn that a
        # word was misspelled
        words = set(mnemonic.split()) - set(WORDLISTS.wordlist(_LANG))
        err_msg = f"not in the SLIP-0039 word-list: {sorted(words)}"
        raise BTClibValueError(err_msg) from e


def share_from_mnemonic(mnemonic: Mnemonic) -> Share:
    """Return the Share the SLIP-0039 mnemonic encodes.

    The checksum is verified; the share value is not, a single share
    carrying nothing that could verify it.
    """
    mnemonic = " ".join(mnemonic.split())
    indexes = _indexes_from_mnemonic(mnemonic)
    n_words = len(indexes)
    if n_words < _MIN_WORDS:
        err_msg = f"invalid mnemonic length: {n_words} words, "
        err_msg += f"at least {_MIN_WORDS} needed"
        raise BTClibValueError(err_msg)

    bits = bin_str_entropy_from_wordlist_indexes(indexes, 1 << _RADIX_BITS)
    # the flag is read before the checksum is verified, being what says
    # which of the two customization strings the checksum used
    extendable = bits[_ID_BITS] == "1"
    if not _rs1024_verify(indexes, extendable):
        raise BTClibValueError(f"invalid checksum: {mnemonic}")

    padded_bits = len(bits) - _HEADER_BITS - _CHECKSUM_BITS
    # the padded value is a whole number of words, so its length is a
    # multiple of 10 and the padding is what that leaves over 16; more
    # than a byte of it means the word count belongs to no share
    padding = padded_bits % 16
    if padding > 8:
        err_msg = f"invalid mnemonic length: {n_words} words"
        raise BTClibValueError(err_msg)
    value_bits = bits[_HEADER_BITS : len(bits) - _CHECKSUM_BITS]
    if value_bits[:padding] != "0" * padding:
        err_msg = f"invalid padding: {value_bits[:padding]}, must be all zeros"
        raise BTClibValueError(err_msg)

    value = int(value_bits[padding:], 2)
    field = _ID_BITS + _EXT_BITS + _E_BITS
    return Share(
        identifier=int(bits[:_ID_BITS], 2),
        extendable=extendable,
        iteration_exponent=int(bits[_ID_BITS + _EXT_BITS : field], 2),
        group_index=int(bits[field : field + 4], 2),
        group_threshold=int(bits[field + 4 : field + 8], 2) + 1,
        group_count=int(bits[field + 8 : field + 12], 2) + 1,
        member_index=int(bits[field + 12 : field + 16], 2),
        member_threshold=int(bits[field + 16 : field + 20], 2) + 1,
        value=value.to_bytes((len(value_bits) - padding) // 8, byteorder="big"),
    )


def mnemonic_from_share(share: Share) -> Mnemonic:
    """Return the SLIP-0039 mnemonic encoding the share."""
    share.assert_valid()
    header = f"{share.identifier:015b}"
    header += "1" if share.extendable else "0"
    header += f"{share.iteration_exponent:04b}"
    header += f"{share.group_index:04b}"
    header += f"{share.group_threshold - 1:04b}"
    header += f"{share.group_count - 1:04b}"
    header += f"{share.member_index:04b}"
    header += f"{share.member_threshold - 1:04b}"
    value_bits = 8 * len(share.value)
    # left-padded with zeros up to the next multiple of ten, ten bits
    # being one word
    padded = f"{int.from_bytes(share.value, byteorder='big'):b}"
    padded = padded.zfill(-(-value_bits // _RADIX_BITS) * _RADIX_BITS)
    indexes = wordlist_indexes_from_bin_str_entropy(header + padded, 1 << _RADIX_BITS)
    indexes += _rs1024_checksum(indexes, share.extendable)
    return mnemonic_from_indexes(indexes, _LANG)


def _assert_valid_passphrase(passphrase: str) -> None:
    """Raise unless the passphrase is printable ASCII.

    SLIP-0039 restricts it to code points 32 to 126, and the
    restriction is the interoperable part: encoding anything else as
    UTF-8 and carrying on would derive a seed that another
    implementation, asked the same question, refuses to derive.
    """
    if any(not 32 <= ord(char) <= 126 for char in passphrase):
        err_msg = "invalid passphrase: only printable ASCII (32-126) is allowed"
        raise BTClibValueError(err_msg)


def _round_function(
    i: int, passphrase: str, iteration_exponent: int, salt: bytes, right: bytes
) -> bytes:
    password = bytes([i]) + passphrase.encode()
    # 2500 per round, i.e. the 10000 iterations SLIP-0039 asks for as a
    # minimum, doubled by every step of the exponent
    iterations = _BASE_ITERATIONS << iteration_exponent
    return pbkdf2_hmac("sha256", password, salt + right, iterations, len(right))


def _feistel(
    payload: bytes,
    passphrase: str,
    iteration_exponent: int,
    identifier: int,
    extendable: bool,
    *,
    decrypt: bool,
) -> bytes:
    """Return the four-round Feistel network applied to the payload.

    Encryption and decryption differ in the order of the round indexes
    alone, which is why one function does both.

    The extendable backup flag is what the salt hangs on: with it set
    the identifier stays out, so two sets of shares with different
    identifiers decrypt to the same master secret under the same
    passphrase. That is the whole point of the flag, and it means a
    share made before the flag existed and one made after do not
    decrypt alike -- hence both states are supported here.
    """
    salt = b"" if extendable else b"shamir" + identifier.to_bytes(2, byteorder="big")
    half = len(payload) // 2
    left, right = payload[:half], payload[half:]
    rounds = reversed(range(_ROUNDS)) if decrypt else range(_ROUNDS)
    for i in rounds:
        f = _round_function(i, passphrase, iteration_exponent, salt, right)
        left, right = right, bytes(x ^ y for x, y in zip(left, f, strict=True))
    return right + left


def _recover_secret(threshold: int, shares: Sequence[tuple[int, bytes]]) -> bytes:
    """Return the secret the shares interpolate to, digest checked."""
    if threshold == 1:
        return shares[0][1]
    secret = _interpolate(shares, _SECRET_X)
    digest_share = _interpolate(shares, _DIGEST_X)
    random_part = digest_share[_DIGEST_BYTES:]
    # `!=` and not hmac.compare_digest, which ecies.assert_valid_mac does
    # use: the two comparisons look alike and are not the same question.
    # There the mac key comes from an ECDH secret the attacker does not
    # hold, so the expected mac is not computable by whoever submits the
    # envelope, and a byte-at-a-time early exit is a forgery oracle --
    # the comment there says so.
    # Here both operands come out of the shares the caller just passed
    # in: `random_part` and `secret` are interpolated from them, so the
    # expected digest is something the caller can compute offline, for
    # any shares, without calling this at all. A timing signal can only
    # hand back what its observer already has, which is why the constant
    # time version buys nothing -- and it is why this check is an
    # integrity test that the shares belong together, not a security
    # boundary against somebody who chooses them: such an attacker forges
    # a passing digest directly rather than searching for one.
    # SLIP-0039's reference implementation compares with `!=` too.
    if digest_share[:_DIGEST_BYTES] != _digest(random_part, secret):
        raise BTClibValueError("invalid digest: the shares do not belong together")
    return secret


def _split_secret(
    threshold: int,
    share_count: int,
    secret: bytes,
    entropy_source: Callable[[int], bytes],
) -> list[bytes]:
    """Return share_count shares of the secret, threshold of them enough.

    The shares are returned in index order, the index being the x
    coordinate: the caller does not get to choose them.
    """
    if not 0 < threshold <= share_count <= _MAX_SHARE_COUNT:
        err_msg = f"invalid threshold {threshold} of {share_count}; "
        err_msg += f"0 < threshold <= count <= {_MAX_SHARE_COUNT} required"
        raise BTClibValueError(err_msg)
    if threshold == 1:
        # nothing to interpolate, and nothing to hide either: every
        # share is the secret
        return [secret] * share_count

    n = len(secret)
    # T-2 shares are free, the digest and the secret pin the rest of
    # the polynomial down
    points = [(i, entropy_source(n)) for i in range(threshold - 2)]
    random_part = entropy_source(n - _DIGEST_BYTES)
    points.extend(
        ((_DIGEST_X, _digest(random_part, secret) + random_part), (_SECRET_X, secret))
    )
    shares = [value for _, value in points[: threshold - 2]]
    shares += [_interpolate(points, i) for i in range(threshold - 2, share_count)]
    return shares


def _grouped(shares: Sequence[Share]) -> list[tuple[int, bytes]]:
    """Return one recovered group share per group index present."""
    groups: dict[int, list[Share]] = {}
    for share in shares:
        groups.setdefault(share.group_index, []).append(share)

    group_shares = []
    for group_index, members in groups.items():
        thresholds = {member.member_threshold for member in members}
        if len(thresholds) > 1:
            err_msg = f"mismatching member thresholds in group {group_index}: "
            err_msg += f"{sorted(thresholds)}"
            raise BTClibValueError(err_msg)
        threshold = thresholds.pop()
        indexes = [member.member_index for member in members]
        if len(set(indexes)) != len(indexes):
            err_msg = f"duplicate member indexes in group {group_index}: "
            err_msg += f"{sorted(indexes)}"
            raise BTClibValueError(err_msg)
        # equal, not "at least": SLIP-0039 asks for the threshold
        # number of shares and no more, so that a share which does not
        # belong is reported instead of being quietly outvoted
        if len(members) != threshold:
            err_msg = f"{len(members)} shares in group {group_index}, "
            err_msg += f"member threshold is {threshold}"
            raise BTClibValueError(err_msg)
        points = [(member.member_index, member.value) for member in members]
        group_shares.append((group_index, _recover_secret(threshold, points)))
    return group_shares


def _common_field(shares: Sequence[Share]) -> Share:
    """Return the first share, having checked the fields all shares share."""
    first = shares[0]
    for name, values in (
        ("identifier", {share.identifier for share in shares}),
        ("extendable backup flag", {share.extendable for share in shares}),
        ("iteration exponent", {share.iteration_exponent for share in shares}),
        ("group threshold", {share.group_threshold for share in shares}),
        ("group count", {share.group_count for share in shares}),
        ("share value length", {len(share.value) for share in shares}),
    ):
        if len(values) > 1:
            err_msg = f"mismatching {name}: {sorted(values, key=str)}"
            raise BTClibValueError(err_msg)
    return first


def master_secret_from_mnemonics(
    mnemonics: Sequence[Mnemonic], passphrase: str = ""
) -> bytes:
    """Return the master secret the SLIP-0039 mnemonics reconstruct.

    The mnemonics must be exactly a threshold number of groups, each
    holding exactly its own member threshold of shares. A wrong
    passphrase is not an error: SLIP-0039 has no way to tell one from a
    right one, which is what lets a decoy wallet exist.
    """
    _assert_valid_passphrase(passphrase)
    if not mnemonics:
        raise BTClibValueError("no mnemonic")

    shares = [share_from_mnemonic(mnemonic) for mnemonic in mnemonics]
    first = _common_field(shares)
    group_shares = _grouped(shares)
    if len(group_shares) != first.group_threshold:
        err_msg = f"{len(group_shares)} groups, "
        err_msg += f"group threshold is {first.group_threshold}"
        raise BTClibValueError(err_msg)

    ems = _recover_secret(first.group_threshold, group_shares)
    return _feistel(
        ems,
        passphrase,
        first.iteration_exponent,
        first.identifier,
        first.extendable,
        decrypt=True,
    )


def mnemonics_from_master_secret(
    master_secret: Octets,
    groups: Sequence[tuple[int, int]] = ((1, 1),),
    group_threshold: int = 1,
    passphrase: str = "",
    iteration_exponent: int = 1,
    extendable: bool = True,
    entropy_source: Callable[[int], bytes] = os.urandom,
) -> list[list[Mnemonic]]:
    """Return the SLIP-0039 shares of a master secret, grouped.

    groups is one (member threshold, member count) pair per group, and
    group_threshold is how many groups are needed; the default is the
    single 1-of-1 share a wallet starts with. The master secret is the
    BIP32 seed to back up, at least 128 bits and a multiple of 16.

    entropy_source is where every random byte comes from -- the
    identifier, the free coefficients of each polynomial and the
    digest padding -- and it is a parameter so that a caller can hand
    in a deterministic source and get a reproducible answer: nothing
    else in this scheme is testable against a fixed expectation, the
    shares of a 2-of-3 backup being random by construction. The default
    is os.urandom, the CSPRNG SLIP-0039 requires (secrets.token_bytes
    is the same bytes through another name); anything weaker substituted
    here is a secret an attacker can reproduce.
    """
    assert_type(extendable, bool, "extendable")
    _assert_valid_passphrase(passphrase)
    secret = bytes_from_octets(master_secret)
    _assert_valid_length(len(secret), "master secret")
    if not 0 <= iteration_exponent < (1 << _E_BITS):
        err_msg = f"invalid iteration exponent: {iteration_exponent}, "
        err_msg += f"not in [0-{(1 << _E_BITS) - 1}]"
        raise BTClibValueError(err_msg)
    for member_threshold, member_count in groups:
        # a 1-of-N group is N shares differing in an index and a
        # checksum, i.e. N copies of the same secret: SLIP-0039 forbids
        # it because someone asking for it has misunderstood the scheme
        if member_threshold == 1 and member_count > 1:
            err_msg = f"invalid 1-of-{member_count} group; "
            err_msg += "a group with threshold 1 must have a single member"
            raise BTClibValueError(err_msg)

    # the low fifteen bits of the first two bytes drawn, rather than the
    # high fifteen: both are uniform, and this way a two-byte source
    # spells the identifier it produces
    identifier = int.from_bytes(entropy_source(2), byteorder="big")
    identifier &= (1 << _ID_BITS) - 1
    ems = _feistel(
        secret, passphrase, iteration_exponent, identifier, extendable, decrypt=False
    )
    group_values = _split_secret(group_threshold, len(groups), ems, entropy_source)

    mnemonics = []
    for group_index, (group_value, group) in enumerate(
        zip(group_values, groups, strict=True)
    ):
        member_threshold, member_count = group
        values = _split_secret(
            member_threshold, member_count, group_value, entropy_source
        )
        mnemonics.append(
            [
                mnemonic_from_share(
                    Share(
                        identifier=identifier,
                        extendable=extendable,
                        iteration_exponent=iteration_exponent,
                        group_index=group_index,
                        group_threshold=group_threshold,
                        group_count=len(groups),
                        member_index=member_index,
                        member_threshold=member_threshold,
                        value=value,
                    )
                )
                for member_index, value in enumerate(values)
            ]
        )
    return mnemonics


def mxprv_from_mnemonics(
    mnemonics: Sequence[Mnemonic],
    passphrase: str | None = None,
    network: str = "mainnet",
) -> str:
    """Return BIP32 root master extended private key from SLIP-0039 shares.

    The master secret is the BIP32 seed, so there is no stretching step
    between the two: SLIP-0039 backs up the seed itself.
    """
    seed = master_secret_from_mnemonics(mnemonics, passphrase or "")
    version = network_from_name(network).bip32_prv
    return rootxprv_from_seed(seed, version)
