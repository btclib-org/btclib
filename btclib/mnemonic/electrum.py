#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Electrum entropy / mnemonic / seed functions.

Electrum mnemonic is versioned, conveying BIP32 derivation rule too.

What is implemented here is Electrum's scheme, not an approximation of
it: the same entropy yields the mnemonic Electrum yields, and a mnemonic
Electrum accepts is accepted here. Four consequences, none of them
BIP39's behaviour, so none of them can be guessed from `bip39.py`:

- the words run least-significant first, the reverse of BIP39's order
- the entropy is an integer and the search starts at entropy + 1, so the
  value supplied is a starting point and never itself the answer
- a candidate that is a pre-2.0 Electrum seed, or that is also a valid
  BIP39 mnemonic, is skipped rather than returned
- a mnemonic is normalized before it is hashed or stretched -- NFKD,
  lower-case, accents dropped, whitespace collapsed -- so an upper-cased
  or accented sentence is read, not rejected

Electrum reads five word-lists (en, es, ja, pt, zh_simplified) and
btclib ships two (en, it). English is the shared one, byte for byte, so
none of the above depends on the data; Italian is btclib's own
extension, and an "electrum" mnemonic generated in Italian is one
Electrum cannot read.
"""

from __future__ import annotations

import hmac
import math
import secrets
import string
import unicodedata
from functools import cache
from hashlib import pbkdf2_hmac, sha512
from os import path

from btclib.bip32 import derive, rootxprv_from_seed
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39
from btclib.mnemonic.entropy import (
    BinStr,
    Entropy,
    bin_str_entropy_from_entropy,
    bin_str_entropy_from_wordlist_indexes,
)
from btclib.mnemonic.mnemonic import (
    WORDLISTS,
    Mnemonic,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
)
from btclib.network import NETWORKS

_MNEMONIC_VERSIONS = {
    "standard": "01",  # P2PKH and P2MS-P2SH wallets
    "segwit": "100",  # P2WPKH and P2WSH wallets
    "2fa": "101",  # Two-factor authenticated wallets
    "2fa_segwit": "102",  # Two-factor authenticated wallets, using segwit
}

# the entropy electrum draws when the caller supplies none; 132 and not
# 128 because 132 is twelve whole words of eleven bits
_RANDOM_ENTROPY_BITS = 132

# the ranges electrum calls CJK, from the table its mnemonic.py cites,
# http://www.asahi-net.or.jp/~ax2s-kmtn/ref/unicode/e_asia.html.
# Vendored rather than derived from unicodedata: the set is an editorial
# choice -- it takes in Hangul, Bopomofo, Lisu, Miao, Yi and the
# halfwidth/fullwidth forms, which no one Unicode property groups -- and
# normalization has to agree with electrum's on every character, not
# nearly
_CJK_INTERVALS = (
    (0x4E00, 0x9FFF),  # CJK Unified Ideographs
    (0x3400, 0x4DBF),  # CJK Unified Ideographs Extension A
    (0x20000, 0x2A6DF),  # CJK Unified Ideographs Extension B
    (0x2A700, 0x2B73F),  # CJK Unified Ideographs Extension C
    (0x2B740, 0x2B81F),  # CJK Unified Ideographs Extension D
    (0xF900, 0xFAFF),  # CJK Compatibility Ideographs
    (0x2F800, 0x2FA1D),  # CJK Compatibility Ideographs Supplement
    (0x3190, 0x319F),  # Kanbun
    (0x2E80, 0x2EFF),  # CJK Radicals Supplement
    (0x2F00, 0x2FDF),  # CJK Radicals
    (0x31C0, 0x31EF),  # CJK Strokes
    (0x2FF0, 0x2FFF),  # Ideographic Description Characters
    (0xE0100, 0xE01EF),  # Variation Selectors Supplement
    (0x3100, 0x312F),  # Bopomofo
    (0x31A0, 0x31BF),  # Bopomofo Extended
    (0xFF00, 0xFFEF),  # Halfwidth and Fullwidth Forms
    (0x3040, 0x309F),  # Hiragana
    (0x30A0, 0x30FF),  # Katakana
    (0x31F0, 0x31FF),  # Katakana Phonetic Extensions
    (0x1B000, 0x1B0FF),  # Kana Supplement
    (0xAC00, 0xD7AF),  # Hangul Syllables
    (0x1100, 0x11FF),  # Hangul Jamo
    (0xA960, 0xA97F),  # Hangul Jamo Extended A
    (0xD7B0, 0xD7FF),  # Hangul Jamo Extended B
    (0x3130, 0x318F),  # Hangul Compatibility Jamo
    (0xA4D0, 0xA4FF),  # Lisu
    (0x16F00, 0x16F9F),  # Miao
    (0xA000, 0xA48F),  # Yi Syllables
    (0xA490, 0xA4CF),  # Yi Radicals
)

_OLD_WORDLIST_FILE = path.join(
    path.dirname(__file__), "_data", "electrum_old_english.txt"
)


def _is_cjk(char: str) -> bool:
    return any(imin <= ord(char) <= imax for imin, imax in _CJK_INTERVALS)


def _normalize(text: str) -> str:
    """Return the text as electrum hashes and stretches it.

    NFKD, lower-case, combining characters dropped, whitespace collapsed,
    and whitespace between two CJK characters removed. It applies to the
    passphrase as well as to the mnemonic, which is why it takes a plain
    string rather than a Mnemonic.

    Not mnemonic.py's normalize_mnemonic, which is BIP39's reading of the
    same question and agrees with this one on the whitespace alone. The
    two cannot be merged: dropping the combining characters undoes the
    decomposition BIP39 requires, and joining the words either side of a
    CJK space would hand PBKDF2 one long word where BIP39's japanese
    vectors expect twelve.
    """
    text = unicodedata.normalize("NFKD", text)
    text = text.lower()
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = " ".join(text.split())
    # the collapse above leaves no leading or trailing whitespace, so the
    # neighbour lookups cannot run off either end: at i == 0 and at
    # i == len - 1 the character is not whitespace, and the "and" stops
    # before text[i - 1] or text[i + 1] is asked for
    return "".join(
        text[i]
        for i in range(len(text))
        if not (
            text[i] in string.whitespace
            and _is_cjk(text[i - 1])
            and _is_cjk(text[i + 1])
        )
    )


@cache
def _old_wordlist() -> frozenset[str]:
    """Return electrum's pre-2.0 word-list, read once.

    Not a language of WORDLISTS: it has 1626 words, and load_lang rejects
    any count that is not a power of two, rightly -- an index into it is
    not a whole number of bits, the pre-2.0 scheme not being a base
    conversion. A set is enough because nothing here decodes an old seed:
    the only question asked of it is membership.
    """
    with open(_OLD_WORDLIST_FILE, encoding="ascii") as file_:
        return frozenset(line.rstrip("\n") for line in file_)


def _is_old_mnemonic(mnemonic: Mnemonic) -> bool:
    """Return True for a pre-2.0 Electrum seed.

    Deliberately weak, and electrum says so of its own is_old_seed
    (spesmilo/electrum#3149): twelve or twenty-four words that all happen
    to be in the old list are enough, as is any 16- or 32-byte hex
    string. Copied at that strength on purpose -- a stricter test here
    would accept a seed electrum refuses, which is the divergence this
    module exists to avoid.
    """
    mnemonic = _normalize(mnemonic)
    words = mnemonic.split()
    # electrum runs the old decoder and asks only whether it raised, and
    # an unknown word is its one failure mode: it walks len(words) // 3
    # triples, so a count that is not a multiple of three drops the tail
    # silently rather than complaining. Testing every word gives the same
    # answer wherever the answer is used, the count there being 12 or 24
    uses_old_words = all(word in _old_wordlist() for word in words)
    try:
        is_hex = len(bytes.fromhex(mnemonic)) in (16, 32)
    except ValueError:
        is_hex = False
    return is_hex or (uses_old_words and len(words) in (12, 24))


def _seed_version(mnemonic: Mnemonic) -> str:
    return hmac.new(b"Seed version", _normalize(mnemonic).encode(), sha512).hexdigest()


def _is_bip39_mnemonic(mnemonic: Mnemonic, lang: str) -> bool:
    """Return True if the mnemonic is also a valid BIP39 mnemonic.

    The English word-list is the same file for both schemes, so a
    sentence can satisfy both: one 12-word mnemonic in sixteen has a
    valid BIP39 checksum by chance, which makes this the skip that counts
    most towards generating what electrum generates.
    """
    # electrum's bip39_is_checksum_valid answers "checksum invalid"
    # rather than raising for a length outside this set, so the length is
    # a question of its own and not something to read out of an exception
    if len(mnemonic.split()) not in (12, 15, 18, 21, 24):
        return False
    try:
        bip39.entropy_from_mnemonic(mnemonic, lang)
    except BTClibValueError:
        return False
    return True


def _mnemonic_type(mnemonic: Mnemonic) -> str:
    """Return the Electrum seed type of the mnemonic, "" if it has none.

    Electrum's calc_seed_type. "old" is one of the answers and is not a
    key of _MNEMONIC_VERSIONS: the pre-2.0 scheme has no version prefix,
    it is recognized by its word-list, and it is tested first because an
    old seed can match one of the four prefixes by chance -- reporting it
    as "standard" would hand a caller the wrong derivation in silence.
    """
    # the count is taken before normalization, as electrum takes it:
    # dropping the whitespace between CJK characters joins words
    nwords = len(mnemonic.split())
    if _is_old_mnemonic(mnemonic):
        return "old"
    seed_version = _seed_version(mnemonic)
    for mnemonic_type, version in _MNEMONIC_VERSIONS.items():
        if not seed_version.startswith(version):
            continue
        # electrum 2.7 changed how "2fa" seeds derive keys and reused the
        # prefix, so the word count is all that tells the two apart:
        # twelve words is post-2.7, twenty or more pre-2.7, and "101" at
        # any other length is not a seed at all -- the loop goes on to
        # the remaining prefixes exactly as electrum's elif chain does
        if mnemonic_type == "2fa" and nwords != 12 and nwords < 20:
            continue
        return mnemonic_type
    return ""


def version_from_mnemonic(mnemonic: Mnemonic) -> tuple[str, str]:
    """Return the (Electrum version, normalized mnemonic) tuple.

    The version is one of the four in _MNEMONIC_VERSIONS, or "old" for
    the pre-2.0 scheme, which is recognized so that it is never mistaken
    for one of the four; deriving keys from it is not supported.

    The normalized mnemonic is the one electrum hashes and stretches:
    NFKD, lower-case, accents dropped, whitespace collapsed.
    """
    mnemonic_type = _mnemonic_type(mnemonic)
    if not mnemonic_type:
        seed_version = _seed_version(mnemonic)
        err_msg = f"unknown electrum mnemonic version: '{seed_version[:3]}'; "
        err_msg += f"not in {list(_MNEMONIC_VERSIONS.keys())}"
        raise BTClibValueError(err_msg)
    return mnemonic_type, _normalize(mnemonic)


def _mnemonic_from_int_entropy(int_entropy: int, lang: str) -> Mnemonic:
    """Return the mnemonic of an integer, least-significant word first.

    Electrum's mnemonic_encode. entropy.py's shared helpers end in
    list(reversed(indexes)) for bip39.py, where that order is right and
    the BIP39 vectors prove it, so they are not what this needs; working
    on the integer directly also keeps the leading-zero question out of
    it, an integer having no leading zeros to lose.
    """
    base = WORDLISTS.language_length(lang)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, base)
        indexes.append(index)
    return mnemonic_from_indexes(indexes, lang)


def _bin_str_entropy_from_mnemonic(mnemonic: Mnemonic, lang: str) -> BinStr:
    """Return the entropy of a mnemonic whose first word is least significant.

    Electrum's mnemonic_decode, which pops from the tail. The index list
    is reversed before entropy.py's helper sees it, that helper being
    written for BIP39's order.
    """
    indexes = indexes_from_mnemonic(mnemonic, lang)
    base = WORDLISTS.language_length(lang)
    return bin_str_entropy_from_wordlist_indexes(indexes[::-1], base)


def _random_int_entropy(lang: str) -> int:
    """Return the entropy electrum's make_seed draws when given none.

    132 bits rounded up to whole words, with anything below 2**121 drawn
    again: that is what makes the leading word uniformly distributed and
    the sentence twelve words long. secrets.randbits(128) instead leaves
    the word count to follow the bit length, and the word count is the
    one thing about the answer a caller cannot correct afterwards.
    """
    bits_per_word = int(math.log2(WORDLISTS.language_length(lang)))
    nbits = math.ceil(_RANDOM_ENTROPY_BITS / bits_per_word) * bits_per_word
    int_entropy = 1
    while int_entropy < 1 << (nbits - bits_per_word):
        # electrum's randrange: 1 <= r < 2**nbits, zero excluded
        int_entropy = secrets.randbelow((1 << nbits) - 1) + 1
    return int_entropy


def _search_mnemonic(int_entropy: int, version: str, lang: str) -> Mnemonic:
    """Return the first mnemonic of that version at or after entropy + 1."""
    nonce = 0
    while True:
        # the first candidate is int_entropy + 1: electrum increments
        # before it encodes, so the value handed in is never itself tried
        nonce += 1
        candidate = int_entropy + nonce
        mnemonic = _mnemonic_from_int_entropy(candidate, lang)
        if candidate != int(_bin_str_entropy_from_mnemonic(mnemonic, lang), 2):
            err_msg = f"cannot extract the same entropy from mnemonic: {mnemonic}"
            raise BTClibValueError(err_msg)
        # a pre-2.0 seed and a valid BIP39 mnemonic are both skipped, not
        # returned: electrum would read back what it had just written as
        # an old seed, or as a BIP39 one, and derive other keys from it
        if _is_old_mnemonic(mnemonic) or _is_bip39_mnemonic(mnemonic, lang):
            continue
        if _seed_version(mnemonic).startswith(version):
            return mnemonic


def mnemonic_from_entropy(
    mnemonic_type: str = "standard", entropy: Entropy | None = None, lang: str = "en"
) -> Mnemonic:
    """Convert input entropy to Electrum versioned mnemonic sentence.

    Input entropy can be expressed as binary 0/1 string, bytes-like, or
    integer.

    In the case of binary 0/1 string and bytes-like, leading zeros are
    considered redundant padding.

    The entropy is where the search for a mnemonic of the requested
    version starts, not what the mnemonic encodes: the first candidate
    tried is entropy + 1, and candidates that are pre-2.0 Electrum seeds
    or valid BIP39 mnemonics are passed over. The search is Electrum's,
    so the mnemonic is the one Electrum returns for that entropy.
    """
    if mnemonic_type not in _MNEMONIC_VERSIONS:
        err_msg = f"unknown electrum mnemonic version: '{mnemonic_type}'; "
        err_msg += f"not in {list(_MNEMONIC_VERSIONS.keys())}"
        raise BTClibValueError(err_msg)

    int_entropy = (
        _random_int_entropy(lang)
        if entropy is None or entropy == ""
        else int(bin_str_entropy_from_entropy(entropy), 2)
    )
    mnemonic = _search_mnemonic(int_entropy, _MNEMONIC_VERSIONS[mnemonic_type], lang)

    # the prefix is necessary and not sufficient, so electrum closes by
    # asking what the sentence it has just built would be read as. "2fa"
    # is the case that can fail: it wants twelve words or twenty, and an
    # entropy worth thirteen words gives neither
    found = _mnemonic_type(mnemonic)
    if found != mnemonic_type:
        err_msg = f"electrum mnemonic version: '{found}'; expected: '{mnemonic_type}'"
        raise BTClibValueError(err_msg)
    return mnemonic


def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> BinStr:
    """Return the entropy from the Electrum versioned mnemonic sentence.

    This is the entropy the mnemonic encodes, which is one more than the
    smallest entropy mnemonic_from_entropy would produce it from.
    """
    mnemonic_type, mnemonic = version_from_mnemonic(mnemonic)
    if mnemonic_type == "old":
        err_msg = "pre-2.0 electrum mnemonic: entropy is not a base conversion"
        raise BTClibValueError(err_msg)
    return _bin_str_entropy_from_mnemonic(mnemonic, lang)


def _seed_from_mnemonic(mnemonic: Mnemonic, passphrase: str) -> tuple[str, bytes]:
    """Return (version, seed) from the provided Electrum mnemonic."""
    version, mnemonic = version_from_mnemonic(mnemonic)

    hf_name = "sha512"
    password = mnemonic.encode()
    # the passphrase is normalized as the mnemonic is, electrum putting
    # both through the same function before it stretches them together
    salt = f"electrum{_normalize(passphrase)}".encode()
    iterations = 2048
    dksize = 64
    return version, pbkdf2_hmac(hf_name, password, salt, iterations, dksize)


def mxprv_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str | None = None, network: str = "mainnet"
) -> str:
    """Return BIP32 master extended private key from Electrum mnemonic.

    Note that for a "standard" mnemonic the derivation path is "m", for
    a "segwit" mnemonic it is "m/0h" instead.
    """
    version, seed = _seed_from_mnemonic(mnemonic, passphrase or "")

    if version == "standard":
        xversion = NETWORKS[network].bip32_prv
        return rootxprv_from_seed(seed, xversion)
    if version == "segwit":
        xversion = NETWORKS[network].slip132_p2wpkh_prv
        rootxprv = rootxprv_from_seed(seed, xversion)
        return derive(rootxprv, 0x80000000)  # "m/0h"
    raise BTClibValueError(f"unmanaged electrum mnemonic version: {version}")
