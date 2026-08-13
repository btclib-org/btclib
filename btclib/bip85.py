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
the same reason: the applications below need `b58` for a WIF and
`mnemonic.bip39` for a sentence, and both of those are above `bip32`,
which `btclib/bip32/` may not import back. Nothing in the library
imports this module.

Four of BIP85's applications are here -- 39' (a BIP39 mnemonic), 2' (the
Bitcoin Core hdseed WIF), 32' (an xprv) and 128169' (raw bytes) -- and
`entropy_from_der_path` is the derivation itself, which answers for any
path including the ones no function here formats. What is not here is
the rest of the BIP: 707764' and 707785' are a base64 and a base85 slice
of the same entropy, and 828365' (RSA) and 89101' (dice) need
BIP85-DRNG-SHAKE256, a stream of arbitrary length seeded with the 64
bytes rather than the bytes themselves.
"""

from __future__ import annotations

import hmac

from btclib.b58 import wif_from_prv_key
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _derive,
    _key_data_from_bip32_key,
)
from btclib.bip32.der_path import _HARDENED_OFFSET, DerPath, indexes_from_der_path
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.bip39 import mnemonic_from_entropy
from btclib.mnemonic.mnemonic import Mnemonic
from btclib.network import NETWORKS, network_from_xkeyversion

__all__ = [
    "bytes_entropy_from_root_key",
    "entropy_from_der_path",
    "mnemonic_from_root_key",
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
        raise BTClibValueError(f"not a bip85 derivation path: {indexes[0]}")
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
        version=NETWORKS[network].bip32_prv,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        index=0,
        chain_code=entropy[:32],
        # the same hard failure the WIF above documents, raised by the
        # key validation this constructor performs
        key=b"\x00" + entropy[32:],
    )
    return derived.b58encode()


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
