#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""electrum entropy / mnemonic / seed functions"""

from hashlib import sha512, pbkdf2_hmac
import hmac

from .entropy import Entropy, GenericEntropy, int_from_entropy, \
    str_from_entropy
from .mnemonic import indexes_from_entropy, mnemonic_from_indexes, \
    indexes_from_mnemonic, entropy_from_indexes, Mnemonic
from . import bip32

ELECTRUM_MNEMONIC_VERSIONS = {'standard': '01',
                              'segwit': '100',
                              '2fa': '101'}

# entropy can be expresses as binary string, bytes-like, or int


def mnemonic_from_raw_entropy(raw_entropy: GenericEntropy,
                              lang: str,
                              eversion: str) -> Mnemonic:

    if eversion not in ELECTRUM_MNEMONIC_VERSIONS:
        m = f"mnemonic version '{eversion}' not in electrum allowed "
        m += f"mnemonic versions {list(ELECTRUM_MNEMONIC_VERSIONS.keys())}"
        raise ValueError(m)

    invalid = True
    # electrum considers entropy as integer, losing any leading zero
    int_entropy = int_from_entropy(raw_entropy)
    while invalid:
        str_entropy = str_from_entropy(int_entropy, int_entropy.bit_length())
        indexes = indexes_from_entropy(str_entropy, lang)
        mnemonic = mnemonic_from_indexes(indexes, lang)
        # version validity check
        s = hmac.new(b"Seed version", mnemonic.encode(
            'utf8'), sha512).hexdigest()
        if s.startswith(ELECTRUM_MNEMONIC_VERSIONS[eversion]):
            invalid = False
        # next trial
        int_entropy += 1

    return mnemonic

def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str) -> Entropy:
    """entropy is returned as binary string"""
    indexes = indexes_from_mnemonic(mnemonic, lang)
    entropy = entropy_from_indexes(indexes, lang)
    return entropy


def seed_from_mnemonic(mnemonic: Mnemonic, passphrase: str) -> bytes:
    hash_name = 'sha512'
    password = mnemonic.encode()
    salt = ('electrum' + passphrase).encode()
    iterations = 2048
    dksize = 64
    return pbkdf2_hmac(hash_name, password, salt, iterations, dksize)


def mprv_from_mnemonic(mnemonic: Mnemonic,
                       passphrase: str,
                       xversion: bytes) -> bytes:
    seed = seed_from_mnemonic(mnemonic, passphrase)

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


def mprv_from_raw_entropy(raw_entropy: GenericEntropy,
                          passphrase: str,
                          lang: str,
                          xversion: bytes) -> bytes:
    mnemonic = mnemonic_from_raw_entropy(raw_entropy, lang, 'standard')
    mprv = mprv_from_mnemonic(mnemonic, passphrase, xversion)
    return mprv
