# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

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

Electrum reads five word-lists -- en, es, ja, pt, zh -- and its own
registry here holds all twelve of BIP39's beside them, so a language
Electrum does not read is still a language this module writes: an
"electrum" mnemonic in Italian is btclib's extension, and Electrum
cannot read it.

Four of the five are BIP39's file after NFKD normalization, byte for
byte, so nothing above depends on which of the two schemes loaded them.
Portuguese is the exception and the reason this module has a registry of
its own rather than sharing WORDLISTS: Electrum's Portuguese is Monero's
word-list, 1626 words rather than 2048, and "pt" therefore names one
word-list in bip39.py and another here. Two consequences, both of them
visible in the code below: 1626 is not a power of two, so an index into
it is not eleven bits and the entropy is a base conversion and nothing
more; and a Portuguese sentence carrying Electrum's default entropy is
thirteen words, which is why a "2fa" mnemonic cannot be generated in
Portuguese at all -- that version wants twelve words or twenty, and
Electrum raises there too.

The pre-2.0 scheme is here too, and it is a different thing wearing the
same words. A wallet created before Electrum 2.0 has a twelve- or
twenty-four-word mnemonic over a word-list of its own, 1626 words long;
it decodes to a hex master seed rather than to entropy, three words to
each 32-bit group; the master private key is that seed stretched by a
hundred thousand rounds of SHA-256 rather than by PBKDF2; and it has no
passphrase, so one supplied is refused rather than defaulted away. There
is no specification to follow -- the scheme predates the BIPs and never
had one -- so Electrum's implementation is what correct means, and every
vector for it comes from Electrum's own tests.
"""

from __future__ import annotations

import hmac
import math
import secrets
import string
import unicodedata
from functools import cache
from hashlib import pbkdf2_hmac, sha256, sha512
from pathlib import Path

from btclib.bip32 import derive, rootxprv_from_seed
from btclib.bip32.der_path import _HARDENED_OFFSET
from btclib.curves.curve import mult, secp256k1
from btclib.curves.sec_point import bytes_from_point, scalar_from_prv_key
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.entropy import (
    BinStr,
    Entropy,
    bin_str_entropy_from_entropy,
    bin_str_entropy_from_wordlist_indexes,
)
from btclib.mnemonic.mnemonic import (
    BIP39_LANGUAGE_FILES,
    Mnemonic,
    WordLists,
    data_file,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
)
from btclib.network import network_from_name

__all__ = [
    "ELECTRUM_WORDLISTS",
    "entropy_from_mnemonic",
    "hex_seed_from_old_mnemonic",
    "lang_from_mnemonic",
    "mnemonic_from_entropy",
    "mxprv_from_mnemonic",
    "old_master_prv_key_from_mnemonic",
    "old_master_pub_key_from_mnemonic",
    "old_mnemonic_from_hex_seed",
    "version_from_mnemonic",
]

_MNEMONIC_VERSIONS = {
    "standard": "01",  # p2pkh and p2ms-p2sh wallets
    "segwit": "100",  # p2wpkh and p2wsh wallets
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

# the pre-2.0 word-list, transcribed from the _words tuple of
# spesmilo/electrum's electrum/old_mnemonic.py -- MIT, "Copyright (C)
# 2011 thomasv@gitorious" -- one word per line, in its order, all 1626 of
# them. Pinned at commit 6be5bf96a89a72ac5b553493f7db385a0519ddb5
# (2025-07-18), whose blob for that path is
# c86634378e62935d4a68966ef19e2f6413066283. The order is load-bearing
# and is not the alphabet's -- the list is a frequency list of
# contemporary poetry -- so a re-sorted copy decodes every seed to
# something else. There is no upstream file to compare bytes against,
# the words living inside a python module rather than in a .txt
_OLD_WORDLIST_FILE = Path(__file__).parent / "_data" / "electrum_old_english.txt"

# the rounds of Old_KeyStore.stretch_key, which is what a pre-2.0 seed
# has instead of the versioned scheme's 2048 PBKDF2 iterations
_OLD_STRETCH_ROUNDS = 100_000

# Electrum's own word-lists, which are BIP39's but for Portuguese: that
# one is Monero's list, vendored as electrum_portuguese.txt
# (electrum/wordlist/portuguese.txt, BSD-3-Clause, "Copyright (c) 2014,
# The Monero Project", the licence header kept in the file because the
# loader reads '#' as a comment). power_of_two off for it: 1626 words is
# a base to convert to, not eleven bits per word
ELECTRUM_WORDLISTS = WordLists(
    {**BIP39_LANGUAGE_FILES, "pt": data_file("electrum_portuguese.txt")},
    power_of_two=False,
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
def _old_wordlist() -> tuple[str, ...]:
    """Return electrum's pre-2.0 word-list, read once, in its own order.

    Not a language of ELECTRUM_WORDLISTS, which would take it -- 1626
    words is what its Portuguese has -- because the pre-2.0 scheme is not
    a base conversion at all: three words carry four bytes, so an index
    into this list is not a digit, and none of the entropy machinery a
    registered language reaches applies to it.
    """
    with _OLD_WORDLIST_FILE.open(encoding="ascii") as file_:
        return tuple(line.rstrip("\n") for line in file_)


@cache
def _old_word_indexes() -> dict[str, int]:
    """Return the word-to-index map of electrum's pre-2.0 word-list.

    Electrum's Wordlist keeps the same map for the same reason: the
    decoder asks for an index once per word and the recognizer asks for
    membership once per word, and a 1626-tuple answers either by walking
    itself.
    """
    return {word: index for index, word in enumerate(_old_wordlist())}


def _is_hex_str(text: str) -> bool:
    """Return True for a string of hex characters and nothing else.

    Electrum's is_hex_str, and neither of the two shorter spellings:
    bytes.fromhex skips ASCII whitespace between pairs, so "0123 4567"
    would pass as four octets, and int(text, 16) takes a sign and
    underscore separators besides. The length check is what closes both.
    """
    try:
        octets = bytes.fromhex(text)
    except ValueError:
        return False
    return len(text) == 2 * len(octets)


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
    uses_old_words = all(word in _old_word_indexes() for word in words)
    try:
        is_hex = len(bytes.fromhex(mnemonic)) in {16, 32}
    except ValueError:
        is_hex = False
    return is_hex or (uses_old_words and len(words) in {12, 24})


def _seed_version(mnemonic: Mnemonic) -> str:
    return hmac.new(b"Seed version", _normalize(mnemonic).encode(), sha512).hexdigest()


def _is_bip39_mnemonic(mnemonic: Mnemonic, lang: str) -> bool:
    """Return True if the mnemonic is also a valid BIP39 mnemonic.

    The word-list is the same file for both schemes, so a sentence can
    satisfy both: one 12-word mnemonic in sixteen has a valid BIP39
    checksum by chance, which makes this the skip that counts most
    towards generating what electrum generates.

    Electrum's bip39_is_checksum_valid, arithmetic included, rather than a
    call into bip39.py -- which is the same answer for the four 2048-word
    lists, and a test pins that, but not for Portuguese. Electrum hands
    that function its own word-list whatever the language, so for
    Portuguese it is 1626 words being read with eleven bits per word:
    nonsense as a checksum, and still what decides which candidates
    electrum passes over, so a sentence generated here without it would
    not be the sentence electrum generates.
    """
    words = mnemonic.split()
    # electrum answers "checksum invalid" rather than raising for a length
    # outside this set, so the length is a question of its own and not
    # something to read out of an exception
    if len(words) not in {12, 15, 18, 21, 24}:
        return False
    try:
        indexes = indexes_from_mnemonic(mnemonic, lang, ELECTRUM_WORDLISTS)
    except BTClibValueError:
        return False

    base = ELECTRUM_WORDLISTS.language_length(lang)
    int_entropy = 0
    for index in indexes:
        int_entropy = int_entropy * base + index
    checksum_bits = 11 * len(words) // 33
    # the entropy is 32 bits per checksum bit, so four bytes: with a
    # 2048-word list the shift leaves exactly that many, and with a
    # 1626-word one it leaves fewer, never more, at every allowed length
    bytes_entropy = (int_entropy >> checksum_bits).to_bytes(4 * checksum_bits, "big")
    hashed = int.from_bytes(sha256(bytes_entropy).digest(), byteorder="big")
    return int_entropy % (1 << checksum_bits) == hashed >> (256 - checksum_bits)


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
    base = ELECTRUM_WORDLISTS.language_length(lang)
    indexes = []
    while int_entropy:
        int_entropy, index = divmod(int_entropy, base)
        indexes.append(index)
    return mnemonic_from_indexes(indexes, lang, ELECTRUM_WORDLISTS)


def _decodable(mnemonic: Mnemonic) -> Mnemonic:
    """Return the sentence in the spelling its words are looked up in.

    Not _normalize: that one drops the accents of a spanish word and the
    spaces between two chinese ones, and neither survives a word-list
    lookup -- what it returns is what electrum *hashes*, and electrum's
    own mnemonic_decode is handed the sentence untouched. Case is folded
    all the same, an upper-cased sentence being one version_from_mnemonic
    recognizes, so refusing to decode what was just recognized would be
    the worse answer. NFKD because the word-lists are NFKD.
    """
    return unicodedata.normalize("NFKD", mnemonic).lower()


def _bin_str_entropy_from_mnemonic(mnemonic: Mnemonic, lang: str) -> BinStr:
    """Return the entropy of a mnemonic whose first word is least significant.

    Electrum's mnemonic_decode, which pops from the tail. The index list
    is reversed before entropy.py's helper sees it, that helper being
    written for BIP39's order.
    """
    indexes = indexes_from_mnemonic(_decodable(mnemonic), lang, ELECTRUM_WORDLISTS)
    base = ELECTRUM_WORDLISTS.language_length(lang)
    return bin_str_entropy_from_wordlist_indexes(indexes[::-1], base)


def _random_int_entropy(lang: str) -> int:
    """Return the entropy electrum's make_seed draws when given none.

    132 bits rounded up to whole words, with anything below one word less
    drawn again: that is electrum's guard against a short sentence.
    secrets.randbits(128) instead leaves the word count to follow the bit
    length, and the word count is the one thing about the answer a caller
    cannot correct afterwards.

    Bits per word is a float, as it is in electrum: for a 2048-word list
    it is 11.0 and the rounding is exact. Portuguese has 1626 words and
    10.667 bits, so the lower bound is below the first integer that needs
    thirteen words. A small share of accepted draws therefore has twelve
    words, exactly as it does in electrum.
    """
    bits_per_word = math.log2(ELECTRUM_WORDLISTS.language_length(lang))
    nbits = int(math.ceil(_RANDOM_ENTROPY_BITS / bits_per_word) * bits_per_word)
    int_entropy = 1
    while int_entropy < 2 ** (nbits - bits_per_word):
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
        # not `not entropy`: entropy can be an int, and int 0 is a value
        # to search from, not a missing one -- bip39.py's version has why
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


def lang_from_mnemonic(mnemonic: Mnemonic) -> str:
    """Return the language of the Electrum mnemonic sentence.

    The word-lists that hold every word of the sentence are the
    candidates, and more than one is refused rather than resolved. BIP39's
    tie-break is not available here: an Electrum mnemonic has no checksum
    over its entropy -- the version prefix is a hash of the sentence and
    says nothing about which word-list spelled it -- so every candidate
    decodes to an entropy that is as valid as the others, and only the
    caller knows which one was meant. It is Chinese that reaches this,
    Simplified and Traditional sharing 1275 of their 2048 words.
    """
    candidates = ELECTRUM_WORDLISTS.langs_of_words(_decodable(mnemonic).split())
    if not candidates:
        raise BTClibValueError(f"unknown language for mnemonic: '{mnemonic}'")
    if len(candidates) > 1:
        err_msg = f"ambiguous language for mnemonic: {candidates}"
        raise BTClibValueError(err_msg)
    return candidates[0]


def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str | None = None) -> BinStr:
    """Return the entropy from the Electrum versioned mnemonic sentence.

    This is the entropy the mnemonic encodes, which is one more than the
    smallest entropy mnemonic_from_entropy would produce it from.

    The language is read off the words if it is not provided.
    """
    # the version first, and the language second: the version is a hash of
    # the sentence and needs no word-list, while a pre-2.0 seed is spelled
    # in a word-list no language here holds -- asking the language first
    # would report it as an unknown language rather than as what it is
    mnemonic_type, _ = version_from_mnemonic(mnemonic)
    if mnemonic_type == "old":
        err_msg = "pre-2.0 electrum mnemonic: entropy is not a base conversion; "
        err_msg += "use hex_seed_from_old_mnemonic"
        raise BTClibValueError(err_msg)
    lang = lang or lang_from_mnemonic(mnemonic)
    # the sentence handed in, and not the normalized one version_from_mnemonic
    # returns beside the version: _decodable says why
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

    The derivation path is "m" for a "standard" mnemonic and "m/0h"
    for a "segwit" one.
    """
    version, seed = _seed_from_mnemonic(mnemonic, passphrase or "")

    if version == "standard":
        xversion = network_from_name(network).bip32_prv
        return rootxprv_from_seed(seed, xversion)
    if version == "segwit":
        xversion = network_from_name(network).slip132_p2wpkh_prv
        rootxprv = rootxprv_from_seed(seed, xversion)
        return derive(rootxprv, _HARDENED_OFFSET)  # "m/0h"
    err_msg = f"unmanaged electrum mnemonic version: {version}"
    if version == "old":
        # the pre-2.0 scheme has no BIP32 master key to return: its keys
        # hang off the master public key by an addition of its own, not
        # by a chain code, so there is no xprv this could answer with
        err_msg += "; use old_master_prv_key_from_mnemonic"
    raise BTClibValueError(err_msg)


def old_mnemonic_from_hex_seed(hex_seed: str) -> Mnemonic:
    """Return the pre-2.0 Electrum mnemonic of a hex master seed.

    Electrum's old_mnemonic.mn_encode. Each group of eight hex characters
    -- one 32-bit word -- becomes three words of the 1626-word list, and
    the second and third are offsets from the one before rather than
    digits of their own. Electrum's file names the reason: US patent
    5892470 claims a scheme in which a word stands for a fixed digit, and
    in this one the digit a word carries depends on the word before it.

    Three words to a group is also why 1626 need not be a power of two,
    and so why the list is not a WORDLISTS language.
    """
    if not _is_hex_str(hex_seed):
        raise BTClibValueError("pre-2.0 electrum seed is not a hex string")
    if len(hex_seed) % 8:
        err_msg = f"invalid pre-2.0 electrum seed: {len(hex_seed)} hex "
        err_msg += "characters, not a multiple of eight"
        raise BTClibValueError(err_msg)

    wordlist = _old_wordlist()
    base = len(wordlist)
    words = []
    for i in range(len(hex_seed) // 8):
        group = int(hex_seed[8 * i : 8 * i + 8], 16)
        first = group % base
        second = (group // base + first) % base
        third = (group // base // base + second) % base
        words += [wordlist[first], wordlist[second], wordlist[third]]
    return " ".join(words)


def hex_seed_from_old_mnemonic(mnemonic: Mnemonic) -> str:
    """Return the hex master seed of a pre-2.0 Electrum mnemonic.

    Electrum's Old_KeyStore.format_seed wrapped around
    old_mnemonic.mn_decode: the sentence is normalized, a seed already
    written as hex passes through -- pre-2.0 Electrum stored the seed
    that way, so that is what a user may be holding -- and anything else
    is decoded three words at a time.

    The hex test here is the loose one, bytes.fromhex alone, because that
    is the one format_seed uses; the strict test of _is_hex_str is the
    one Electrum applies a step later, in stretch_key, and the gap
    between them is upstream's rather than something to close here.

    Whether the answer is a seed at all is a question this cannot answer,
    and Electrum cannot either: three words can carry a group above
    2**32, so twelve words can decode to 33 or 34 hex characters instead
    of 32, and neither decoder notices. Deriving is where that fails, if
    it fails at all -- 34 characters are still octets, and one of
    Electrum's own published seeds is exactly that.
    """
    if not _is_old_mnemonic(mnemonic):
        raise BTClibValueError("not a pre-2.0 electrum mnemonic")

    mnemonic = _normalize(mnemonic)
    try:
        bytes.fromhex(mnemonic)
    except ValueError:
        pass
    else:
        return mnemonic

    indexes = _old_word_indexes()
    words = mnemonic.split()
    base = len(_old_wordlist())
    hex_seed = ""
    # _is_old_mnemonic passed and the string is not hex, so every word is
    # in the list and there are 12 or 24 of them: the lookups below
    # cannot fail and no triple is left over
    for i in range(len(words) // 3):
        first, second, third = (indexes[word] for word in words[3 * i : 3 * i + 3])
        group = first
        group += base * ((second - first) % base)
        group += base * base * ((third - second) % base)
        hex_seed += f"{group:08x}"
    return hex_seed


def old_master_prv_key_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str | None = None
) -> int:
    """Return the pre-2.0 Electrum master private key, as an integer.

    Electrum's Old_KeyStore.stretch_key: a hundred thousand rounds of
    sha256 over the digest so far followed by the seed, where the seed is
    the hex *characters* and not the octets they spell, and the last
    digest read as a big-endian integer. Iterated sha256, not PBKDF2, and
    not the versioned scheme's 2048 iterations of it: that is the fact
    only a vector pins, and the vectors here are Electrum's own.

    The passphrase is refused rather than defaulted. Nothing but the seed
    enters the stretch, so there is nowhere for one to go, and accepting
    it silently would hand back the wallet of a seed the caller did not
    ask for. Electrum refuses it the same way in keystore.from_seed --
    "'old'-type electrum seed cannot have passphrase" -- and its
    can_seed_have_passphrase answers False for this scheme alone; None
    and the empty string are "no passphrase" there and here.
    """
    if passphrase:
        raise BTClibValueError("pre-2.0 electrum mnemonic cannot have a passphrase")

    hex_seed = hex_seed_from_old_mnemonic(mnemonic)
    if not _is_hex_str(hex_seed):
        # electrum asserts is_hex_str here and this is the assertion that
        # fires: a decode that overflowed 32 bits leaves an odd number of
        # hex characters, which bytes.fromhex refuses. Neither
        # implementation can derive from such a seed, and refusing is
        # what agreeing with electrum means
        err_msg = f"pre-2.0 electrum mnemonic decodes to {len(hex_seed)} hex "
        err_msg += "characters, which are not octets"
        raise BTClibValueError(err_msg)

    encoded = hex_seed.encode("ascii")
    digest = encoded
    for _ in range(_OLD_STRETCH_ROUNDS):
        digest = sha256(digest + encoded).digest()
    return int.from_bytes(digest, "big")


def old_master_pub_key_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str | None = None
) -> str:
    """Return the pre-2.0 Electrum master public key, as Electrum writes it.

    Electrum's Old_KeyStore.mpk_from_seed: the uncompressed SEC point of
    the stretched key with its 04 prefix cut off, so 128 hex characters
    of x and then y. That string is what a pre-2.0 wallet file holds
    under "master_public_key", which is what makes it the value a vector
    can be taken from.
    """
    prv_key = old_master_prv_key_from_mnemonic(mnemonic, passphrase)
    # scalar_from_prv_key and not mult alone: mult reduces the scalar mod n
    # and would answer for a stretch that landed outside 1..n-1, where
    # electrum's ECPrivkey raises. A 2**-128 disagreement, and refusing
    # is the side that costs nothing
    point = mult(scalar_from_prv_key(prv_key, secp256k1), secp256k1.G, secp256k1)
    return bytes_from_point(point, secp256k1, compressed=False)[1:].hex()
