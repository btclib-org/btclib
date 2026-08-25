# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP85 deterministic entropy from a BIP32 keychain.

https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki

One root key, many wallets. A fully hardened path off a BIP32 root
reaches a child private key k, and `HMAC-SHA512(key="bip-entropy-from-k",
msg=k)` turns it into 512 bits of entropy; the path says which
application the entropy is for, and the application takes as many of
those bits as it needs and truncates the rest. So one backup stands
behind a BIP39 wallet, a Bitcoin Core `hdseed` and a keychain of its
own, none of which shares a key with the others.

The HMAC is what makes the entropy hardened whatever the path was: BIP85
mandates hardened derivation but cannot enforce it, and a child key used
both as a key and as entropy would otherwise leak the one through the
other.

The module sits at the top level, beside `bip44` and `slip132`, and for
the same reason: the applications below need `b58` for a WIF, `b32` for
a bech32-encoded key and `mnemonic.bip39` for a sentence, and all of
those are above `bip32`, which `btclib/bip32/` may not import back.
Nothing in the library imports this module.

`entropy_from_der_path` is the derivation itself and answers for any
path, the applications no function here formats included. Every
application BIP85 defines is formatted beside it: 39' (a BIP39
mnemonic), 2' (the Bitcoin Core hdseed WIF), 32' (an xprv), 128002' (a
NIP-19 Nostr nsec), 128169' (raw bytes, which the BIP calls HEX), 707764'
and 707785' (a base64 and a base85 password), 89101' (dice rolls) and
828365' (RSA).

The last two read BIP85-DRNG-SHAKE256 rather than the 64 bytes: a
function whose appetite is not known in advance needs a stream, so the
entropy seeds a SHAKE256 one and `BIP85DRNG.read` squeezes it. RSA is
where that matters and where btclib stops: the BIP defines the path and
the stream to feed a key generator, not how the primes are found, so
`rsa_drng_from_root_key` hands back the reader an RSA library is to be
given -- and no two libraries handed the same stream need agree on the
key, which is why the BIP publishes vectors for every other application
and none for this one.
"""

from __future__ import annotations

import hmac
from base64 import b64encode, b85encode
from hashlib import shake_256

from btclib.alias import Octets
from btclib.b32 import power_of_2_base_conversion
from btclib.b58 import wif_from_prv_key
from btclib.bech32 import _BECH32_1_CONST, encode
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _derive,
    _key_data_from_bip32_key,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
    str_from_index_int,
)
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.bip39 import mnemonic_from_entropy
from btclib.mnemonic.mnemonic import Mnemonic
from btclib.network import network_from_name, network_from_xkeyversion
from btclib.to_prv_key import int_from_prv_key
from btclib.utils import bytes_from_octets

__all__ = [
    "BIP85DRNG",
    "base64_password_from_root_key",
    "base85_password_from_root_key",
    "bytes_entropy_from_root_key",
    "drng_from_der_path",
    "entropy_from_der_path",
    "mnemonic_from_root_key",
    "nsec_from_root_key",
    "rolls_from_root_key",
    "rsa_drng_from_root_key",
    "wif_from_root_key",
    "xprv_from_root_key",
]

# the HMAC key BIP85 fixes, as the ASCII it spells: the message is the
# 32-byte child private key, and the 64-byte digest is the entropy
_HMAC_KEY = b"bip-entropy-from-k"

# the first level of every BIP85 path, which is 83 69 69 68 read as one
# decimal number: the ASCII of "SEED", the BIP asking that an application
# number be semantic in some way
_PURPOSE = 83696968

# the least a path can say: the purpose, an application number, and one
# index for the application to number its outputs with. bipsea, the
# reference implementation the BIP names, refuses a shorter one too
_MIN_INDEXES = 3

# BIP85's Language Table, as the codes `mnemonic.mnemonic` keys its
# word-lists with. Ten of the twelve lists btclib ships: russian and
# turkish are trezor's rather than the BIP's, so BIP85 numbers neither,
# and a path derived for one would be a path no other implementation
# reads the same way
_LANGUAGE_INDEXES = {
    "en": 0,
    "ja": 1,
    "ko": 2,
    "es": 3,
    "zh": 4,
    "zh_tw": 5,
    "fr": 6,
    "it": 7,
    "cs": 8,
    "pt": 9,
}

# BIP85's Words Table, in bytes rather than in its own bits: the entropy
# a sentence of that many words encodes, which is what the 64 bytes are
# truncated to before BIP39 checksums them
_ENTROPY_BYTES = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}

# the HEX application's bounds, both inclusive, as BIP85 states them
_MIN_BYTES = 16
_MAX_BYTES = 64

# the password lengths of the two encodings, both inclusive and both the
# BIP's. 86 is where base64 stops because the 88 characters 64 bytes
# encode to end in the two "=" of a final group holding one byte, so a
# slice no longer than 86 never reaches the padding
_MIN_B64_LEN = 20
_MAX_B64_LEN = 86
_MIN_B85_LEN = 10
_MAX_B85_LEN = 80

# the least a die and a session of rolls can be. The BIP's own upper
# bound of 2**32 - 1 for each is not reachable and is not written here:
# both are hardened path levels, so what the derivation can spell stops
# at 2**31 - 1, and `str_from_index_int` refuses the rest
_MIN_SIDES = 2
_MIN_ROLLS = 1

# Nostr's two path levels, identity and account_index, both start at 1':
# 0' of either is reserved by the BIP for a future NIP's key-management
# use rather than for a signing key
_MIN_NOSTR_INDEX = 1

# NIP-19's human-readable part for a bech32-encoded Nostr secret key
_NSEC_HRP = "nsec"

# BIP85-DRNG-SHAKE256's seed size, which the BIP fixes at the HMAC's own
# output and requires to be exactly that
_DRNG_SEED_SIZE = 64


def _assert_valid_der_path(indexes: list[int]) -> None:
    """Raise unless the path is one BIP85 defines entropy for.

    Three rules, and the third is the one that matters: an unhardened
    step derives a child whose private key an xpub of its parent and one
    other child expose, so the entropy behind it would be recoverable
    without the root. BIP85 requires the whole path hardened, and the
    HMAC below is a second line of defence rather than a substitute.
    """
    if len(indexes) < _MIN_INDEXES:
        err_msg = f"too few bip85 path levels: {len(indexes)}"
        err_msg += f" instead of {_MIN_INDEXES} or more"
        raise BTClibValueError(err_msg)
    if indexes[0] != _PURPOSE + _HARDENED_OFFSET:
        # the level as a path step and not as the index it is: an
        # unhardened 83696968 and a hardened one are 2**31 apart as
        # numbers and one apostrophe apart in what the caller wrote
        err_msg = f"not a bip85 derivation path: {str_from_index_int(indexes[0])}"
        raise BTClibValueError(err_msg)
    if any(index < _HARDENED_OFFSET for index in indexes):
        raise BTClibValueError("unhardened bip85 derivation path")


def _entropy_from_der_path(root_key: BIP32KeyData, der_path: DerPath) -> bytes:
    """Return the 64 entropy bytes of a path, the key being valid."""
    indexes = indexes_from_der_path(der_path)
    _assert_valid_der_path(indexes)
    # a public root key is refused by the derivation itself, every index
    # being hardened; the leading 0x00 of the private one is dropped,
    # BIP85 hashing the 32 bytes of the key and not the 33 of the field
    xkey = _derive(root_key, indexes, None)
    return hmac.new(_HMAC_KEY, xkey.key[1:], "sha512").digest()


def entropy_from_der_path(root_key: BIP32Key, der_path: DerPath) -> bytes:
    """Return the 64 bytes of entropy BIP85 derives for a path.

    The path is the whole of it, `m/83696968h/{app}h/...` as the BIP
    writes it, and every level must be hardened. Each application
    truncates what it needs off the front; this is the answer for an
    application no function here formats, the caller doing the truncation
    and the formatting.

    The root key must be private, hardened derivation having no public
    form. BIP85 assumes a master root key and this does not check the
    depth: neither does bipsea, the reference implementation, and a
    derived key is a legitimate root of a keychain of its own -- but it
    is a different one, so entropy derived from it is reproducible only
    from that same key.
    """
    return _entropy_from_der_path(_key_data_from_bip32_key(root_key), der_path)


class BIP85DRNG:
    """BIP85-DRNG-SHAKE256: the 64 entropy bytes as a stream.

    The entropy of a path is 64 bytes and no more, which is not enough
    for a function whose appetite is not known until it has finished --
    RSA key generation is the BIP's example. So the 64 bytes seed a
    SHAKE256 extendable-output function, and `read` squeezes as many as
    are asked for, each call continuing where the last one stopped.

    The seed must be exactly 64 bytes, which is what the BIP requires: a
    shorter one is a different stream that no other implementation
    reaches, so it is refused rather than padded.

    `read` is `shake_256(seed).digest(cursor + num_bytes)[cursor:]`,
    which is a squeeze of the whole prefix each time rather than a
    resumed one -- hashlib publishes no incremental squeeze. The output
    is the same either way, SHAKE256's output at a given length being a
    prefix of its output at any greater one, and that identity is also
    what makes a stream read in small pieces equal to the same stream
    read in one: `bipsea`, the reference implementation, reads it the
    same way.
    """

    def __init__(self, entropy: Octets) -> None:
        self._entropy = bytes_from_octets(entropy, _DRNG_SEED_SIZE)
        self._cursor = 0

    def read(self, num_bytes: int) -> bytes:
        """Return the next num_bytes of the stream, and advance it."""
        if num_bytes < 0:
            raise BTClibValueError(f"invalid number of bytes: {num_bytes}")
        start, self._cursor = self._cursor, self._cursor + num_bytes
        return shake_256(self._entropy).digest(self._cursor)[start:]


def drng_from_der_path(root_key: BIP32Key, der_path: DerPath) -> BIP85DRNG:
    """Return the BIP85-DRNG seeded with the entropy of a path.

    The path is any BIP85 path, `entropy_from_der_path`'s own rules
    applying to it: what this adds is the stream on top of the 64 bytes,
    for an application that needs more of them than there are.
    """
    return BIP85DRNG(entropy_from_der_path(root_key, der_path))


def mnemonic_from_root_key(
    root_key: BIP32Key, words: int = 12, lang: str = "en", index: int = 0
) -> Mnemonic:
    """Return a BIP39 mnemonic, BIP85's application 39'.

    The path is `m/83696968h/39h/{language}h/{words}h/{index}h`: the
    entropy is truncated to what a sentence of that many words encodes
    and handed to BIP39, which appends its checksum. `words` is one of
    12, 15, 18, 21 and 24, and `lang` one of the ten of BIP85's Language
    Table, which are ten of the twelve `mnemonic.bip39` writes.
    """
    if words not in _ENTROPY_BYTES:
        err_msg = f"invalid number of words: {words}; "
        err_msg += f"expected: {sorted(_ENTROPY_BYTES)}"
        raise BTClibValueError(err_msg)
    if lang not in _LANGUAGE_INDEXES:
        err_msg = f"unnumbered bip85 language: '{lang}'; "
        err_msg += f"expected: {sorted(_LANGUAGE_INDEXES)}"
        raise BTClibValueError(err_msg)

    der_path = f"m/{_PURPOSE}h/39h/{_LANGUAGE_INDEXES[lang]}h/{words}h/{index}h"
    entropy = _entropy_from_der_path(_key_data_from_bip32_key(root_key), der_path)
    return mnemonic_from_entropy(entropy[: _ENTROPY_BYTES[words]], lang)


def wif_from_root_key(root_key: BIP32Key, index: int = 0) -> str:
    """Return a compressed WIF, BIP85's application 2'.

    The path is `m/83696968h/2h/{index}h`, and the leading 256 bits of
    the entropy are the secret exponent: this is the `hdseed` a Bitcoin
    Core wallet takes. The network is the root key's own, as the WIF
    prefix has to name one.
    """
    xkey = _key_data_from_bip32_key(root_key)
    entropy = _entropy_from_der_path(xkey, f"m/{_PURPOSE}h/2h/{index}h")
    network = network_from_xkeyversion(xkey.version)
    # a scalar of zero or beyond the curve order is refused here, which
    # is the hard failure BIP85 asks for: at odds of about 2**-127 the
    # answer is for the caller to move to the next index, and deriving
    # it here would hand back a key of an index nobody asked for
    return wif_from_prv_key(entropy[:32], network, compressed=True)


def xprv_from_root_key(root_key: BIP32Key, index: int = 0) -> str:
    """Return an extended private key, BIP85's application 32'.

    The path is `m/83696968h/32h/{index}h`, and the 64 entropy bytes are
    read in the order BIP85 states and BIP32 reverses: the first 32 are
    the chain code and the second 32 the private key. Depth, index and
    parent fingerprint are zero, the answer being the root of a keychain
    of its own.

    The version is the network's own xprv or tprv, which is what BIP85
    asks for -- a testnet root emits a tprv and nothing else does. It is
    not the root key's own four bytes: a SLIP132 yprv says which script
    type *that* tree is derived for, and the tree this key roots is a new
    one no such claim has been made about.
    """
    xkey = _key_data_from_bip32_key(root_key)
    entropy = _entropy_from_der_path(xkey, f"m/{_PURPOSE}h/32h/{index}h")
    network = network_from_xkeyversion(xkey.version)
    derived = BIP32KeyData(
        version=network_from_name(network).bip32_prv,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        index=0,
        chain_code=entropy[:32],
        # the same hard failure the WIF above documents, raised by the
        # key validation this constructor performs
        key=b"\x00" + entropy[32:],
    )
    return derived.b58encode()


def nsec_from_root_key(root_key: BIP32Key, identity: int, account_index: int) -> str:
    """Return a NIP-19 nsec, BIP85's application 128002'.

    The path is `m/83696968h/128002h/{identity}h/{account_index}h`: the
    leading 256 bits of the entropy are the secp256k1 secret key, exactly
    as in the HD-Seed WIF application above, and NIP-19 bech32-encodes
    them with the `nsec` human-readable part -- plain bech32, not
    bech32m, and with no witness-version digit in front of the key the
    way a segwit address carries one.

    `identity` is an independent, unlinkable Nostr key namespace and
    `account_index` a distinct key within it. Both must be 1 or more:
    the BIP reserves index 0' of either for a future NIP's key-management
    use -- proof-of-linkage between an identity's keys, rotation,
    revocation -- and defines no signing key there, so neither defaults.

    A scalar of zero or beyond the curve order is refused rather than
    encoded, the same hard failure `wif_from_root_key` documents and the
    same curve-order footnote this section of the BIP cross-references
    from the WIF one: at odds of about 2**-127 the answer is for the
    caller to move to the next index.
    """
    if identity < _MIN_NOSTR_INDEX:
        raise BTClibValueError(f"invalid nostr identity: {identity}")
    if account_index < _MIN_NOSTR_INDEX:
        raise BTClibValueError(f"invalid nostr account index: {account_index}")

    xkey = _key_data_from_bip32_key(root_key)
    der_path = f"m/{_PURPOSE}h/128002h/{identity}h/{account_index}h"
    entropy = _entropy_from_der_path(xkey, der_path)
    # the hard failure the docstring above documents, raised before the
    # bech32 encoding rather than after it
    int_from_prv_key(entropy[:32])
    data = power_of_2_base_conversion(entropy[:32], 8, 5)
    return encode(_NSEC_HRP, data, _BECH32_1_CONST).decode("ascii")


def bytes_entropy_from_root_key(
    root_key: BIP32Key, num_bytes: int = 32, index: int = 0
) -> bytes:
    """Return raw entropy bytes, BIP85's application 128169'.

    The path is `m/83696968h/128169h/{num_bytes}h/{index}h`, and the
    entropy is truncated to `num_bytes`, which the BIP bounds to 16..64
    inclusive. The BIP calls this application HEX and prints its output
    as hex; the bytes are what btclib hands back, `.hex()` being the
    spelling.
    """
    if not _MIN_BYTES <= num_bytes <= _MAX_BYTES:
        err_msg = f"invalid number of bytes: {num_bytes}; "
        err_msg += f"expected: {_MIN_BYTES}..{_MAX_BYTES}"
        raise BTClibValueError(err_msg)

    der_path = f"m/{_PURPOSE}h/128169h/{num_bytes}h/{index}h"
    entropy = _entropy_from_der_path(_key_data_from_bip32_key(root_key), der_path)
    return entropy[:num_bytes]


def base64_password_from_root_key(
    root_key: BIP32Key, pwd_len: int, index: int = 0
) -> str:
    """Return a base64 password, BIP85's application 707764'.

    The path is `m/83696968h/707764h/{pwd_len}h/{index}h`: all 64 bytes
    of the entropy are base64-encoded and the leading `pwd_len`
    characters are the password. `pwd_len` is bounded to 20..86
    inclusive, and the upper end is what keeps the slice clear of the
    "=" padding those 64 bytes encode to.
    """
    if not _MIN_B64_LEN <= pwd_len <= _MAX_B64_LEN:
        err_msg = f"invalid password length: {pwd_len}; "
        err_msg += f"expected: {_MIN_B64_LEN}..{_MAX_B64_LEN}"
        raise BTClibValueError(err_msg)

    der_path = f"m/{_PURPOSE}h/707764h/{pwd_len}h/{index}h"
    entropy = _entropy_from_der_path(_key_data_from_bip32_key(root_key), der_path)
    return b64encode(entropy).decode("ascii")[:pwd_len]


def base85_password_from_root_key(
    root_key: BIP32Key, pwd_len: int, index: int = 0
) -> str:
    """Return a base85 password, BIP85's application 707785'.

    The path is `m/83696968h/707785h/{pwd_len}h/{index}h`: all 64 bytes
    of the entropy are base85-encoded and the leading `pwd_len`
    characters are the password. `pwd_len` is bounded to 10..80
    inclusive.

    The alphabet is the one `base64.b85encode` writes, which is
    RFC1924's; the BIP names no alphabet and its vector is in this one.
    """
    if not _MIN_B85_LEN <= pwd_len <= _MAX_B85_LEN:
        err_msg = f"invalid password length: {pwd_len}; "
        err_msg += f"expected: {_MIN_B85_LEN}..{_MAX_B85_LEN}"
        raise BTClibValueError(err_msg)

    der_path = f"m/{_PURPOSE}h/707785h/{pwd_len}h/{index}h"
    entropy = _entropy_from_der_path(_key_data_from_bip32_key(root_key), der_path)
    return b85encode(entropy).decode("ascii")[:pwd_len]


def rolls_from_root_key(
    root_key: BIP32Key, rolls: int, sides: int = 6, index: int = 0
) -> list[int]:
    """Return dice rolls, BIP85's application 89101'.

    The path is `m/83696968h/89101h/{sides}h/{rolls}h/{index}h` -- the
    sides before the rolls, where this signature takes the rolls first,
    a die having a customary number of sides and a session no customary
    length. Each roll is in `0..sides-1`, which is what BIP85 defines
    and what a caller printing them as a die's faces adds one to.

    The rolls are read off the DRNG rather than off the 64 bytes: enough
    of them exhaust any fixed entropy, and a trial landing at or beyond
    `sides` is skipped rather than folded, so that every face stays
    equally likely.

    Nothing bounds `rolls` from above here beyond what a path level can
    hold, and the wait is the caller's: a session is `rolls` reads of a
    stream and takes as long as it takes.

    `mnemonic.entropy.bin_str_entropy_from_rolls` is the other direction,
    dice into entropy for a wallet that does not exist yet; its docstring
    says how the two number a die's faces.
    """
    if rolls < _MIN_ROLLS:
        raise BTClibValueError(f"invalid number of rolls: {rolls}")
    if sides < _MIN_SIDES:
        raise BTClibValueError(f"invalid number of sides: {sides}")

    der_path = f"m/{_PURPOSE}h/89101h/{sides}h/{rolls}h/{index}h"
    drng = drng_from_der_path(root_key, der_path)

    # ceil(log2(sides)) as an integer operation, where BIP85 writes it as
    # a logarithm: `math.log(sides, 2)` is a float, and its rounding at a
    # power of two is the difference between a roll of the right width
    # and one bit too many
    bits_per_roll = (sides - 1).bit_length()
    bytes_per_roll = -(-bits_per_roll // 8)
    excess_bits = 8 * bytes_per_roll - bits_per_roll

    history: list[int] = []
    while len(history) < rolls:
        trial = int.from_bytes(drng.read(bytes_per_roll), byteorder="big")
        # the most significant bits are the roll, which is what the BIP
        # trims to; a trial the die has no face for is dropped
        trial >>= excess_bits
        if trial < sides:
            history.append(trial)
    return history


def rsa_drng_from_root_key(
    root_key: BIP32Key, key_bits: int, key_index: int = 0, sub_key: int | None = None
) -> BIP85DRNG:
    """Return the DRNG of an RSA key, BIP85's application 828365'.

    The path is `m/83696968h/828365h/{key_bits}h/{key_index}h`, with a
    further `{sub_key}h` level for the GPG sub-keys the BIP allocates:
    0' encrypts, 1' authenticates, 2' signs, and the key at `key_index`
    itself is the one that certifies.

    What comes back is the stream, not a key: BIP85 says an RSA
    generator should take the DRNG as its source of randomness and says
    nothing about how the primes are found, so the key belongs to
    whatever library is handed this reader. btclib generates no RSA key
    and the BIP publishes no vector for one.

    A GPG key built this way has one more rule the BIP states and this
    cannot enforce: the creation date must be UNIX Epoch timestamp
    1231006505, the fingerprint being a function of it.
    """
    der_path = f"m/{_PURPOSE}h/828365h/{key_bits}h/{key_index}h"
    if sub_key is not None:
        der_path += f"/{sub_key}h"
    return drng_from_der_path(root_key, der_path)
