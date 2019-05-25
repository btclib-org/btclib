#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Electrum entropy / mnemonic / seed functions.

Electrum mnemonic is versioned, conveying BIP32 derivation rule too.
"""

from hashlib import sha512, pbkdf2_hmac
import hmac

from .entropy import Entropy, GenericEntropy, _int_from_entropy, \
    str_from_entropy
from .mnemonic import indexes_from_entropy, mnemonic_from_indexes, \
    indexes_from_mnemonic, entropy_from_indexes, Mnemonic, _seed_from_mnemonic
from . import bip32

ELECTRUM_MNEMONIC_VERSIONS = {'standard': '01',
                              'segwit': '100',
                              '2fa': '101'}

def mnemonic_from_entropy(entropy: GenericEntropy,
                          lang: str,
                          eversion: str) -> Mnemonic:
    """Convert input entropy to versioned Electrum mnemonic sentence.

    Input entropy (*GenericEntropy*) can be expressed as
    binary 0/1 string, bytes-like, or integer.

    In the case of binary 0/1 string and bytes-like,
    leading zeros are considered redundant padding.
    """

    if eversion not in ELECTRUM_MNEMONIC_VERSIONS:
        m = f"mnemonic version '{eversion}' not in electrum allowed "
        m += f"mnemonic versions {list(ELECTRUM_MNEMONIC_VERSIONS.keys())}"
        raise ValueError(m)

    invalid = True
    # electrum considers entropy as integer, losing any leading zero
    int_entropy = _int_from_entropy(entropy)
    while invalid:
        str_entropy = str_from_entropy(int_entropy, int_entropy.bit_length())
        indexes = indexes_from_entropy(str_entropy, lang)
        mnemonic = mnemonic_from_indexes(indexes, lang)
        # version validity check
        s = hmac.new(b"Seed version",
                     mnemonic.encode('utf8'), sha512).hexdigest()
        if s.startswith(ELECTRUM_MNEMONIC_VERSIONS[eversion]):
            invalid = False
        # next trial
        int_entropy += 1

    return mnemonic


def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str) -> Entropy:
    """Convert mnemonic sentence to Electrum versioned entropy."""

    s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
    valid = s.startswith(ELECTRUM_MNEMONIC_VERSIONS['standard']) or s.startswith(ELECTRUM_MNEMONIC_VERSIONS['segwit']) or s.startswith(ELECTRUM_MNEMONIC_VERSIONS['2fa'])
    if not valid:
        raise ValueError(f"unmanaged electrum mnemonic version ({s[:3]})")

    indexes = indexes_from_mnemonic(mnemonic, lang)
    entropy = entropy_from_indexes(indexes, lang)
    return entropy


def _seed_from_electrum_mnemonic(mnemonic: Mnemonic, passphrase: str) -> bytes:
    """Return seed from mnemonic according to Electrum standard.
    
    Please note: in the Electrum standard, mnemonic conveys BIP32
    derivation rule too. As such, seed alone is partial information.
    """

    return _seed_from_mnemonic(mnemonic, passphrase, 'electrum')


def mprv_from_mnemonic(mnemonic: Mnemonic,
                       passphrase: str,
                       xversion: bytes) -> bytes:
    """Return a BIP32 master private key from Electrum mnemonic."""

    seed = _seed_from_electrum_mnemonic(mnemonic, passphrase)

    # verify that the mnemonic is versioned
    s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
    if s.startswith(ELECTRUM_MNEMONIC_VERSIONS['standard']):
        # FIXME: mainnet / testnet
        return bip32.xmprv_from_seed(seed, xversion)
    elif s.startswith(ELECTRUM_MNEMONIC_VERSIONS['segwit']):
        # FIXME: parametrizazion of the xversion prefix is needed
        mprv = bip32.xmprv_from_seed(seed, b'\x04\xb2\x43\x0c')
        # BIP32 default first account: m/0'
        return bip32.ckd(mprv, 0x80000000)
    else:
        raise ValueError(f"unmanaged electrum mnemonic version ({s[:3]})")


def mprv_from_entropy(entropy: GenericEntropy,
                      passphrase: str,
                      lang: str,
                      xversion: bytes) -> bytes:
    """Return a BIP32 master private key from entropy."""

    mnemonic = mnemonic_from_entropy(entropy, lang, 'standard')
    mprv = mprv_from_mnemonic(mnemonic, passphrase, xversion)
    return mprv
