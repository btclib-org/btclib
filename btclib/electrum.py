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
    indexes_from_mnemonic, entropy_from_indexes, Mnemonic
from . import bip32

ELECTRUM_MNEMONIC_VERSIONS = {
    'standard'   :  '01',  # P2PKH and Multisig P2SH wallets
    'segwit'     : '100',  # P2WPKH and P2WSH wallets
    '2fa'        : '101',  # Two-factor authenticated wallets
    '2fa_segwit' : '102'}  # Two-factor authenticated wallets, using segwit

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
    valid = (
        s.startswith(ELECTRUM_MNEMONIC_VERSIONS['standard']) or
        s.startswith(ELECTRUM_MNEMONIC_VERSIONS['segwit']) or
        s.startswith(ELECTRUM_MNEMONIC_VERSIONS['2fa']) or
        s.startswith(ELECTRUM_MNEMONIC_VERSIONS['2fa_segwit'])
        )
    if valid:
        indexes = indexes_from_mnemonic(mnemonic, lang)
        entropy = entropy_from_indexes(indexes, lang)
        return entropy

    raise ValueError(f"unknown electrum mnemonic version ({s[:3]})")


def _seed_from_mnemonic(mnemonic: Mnemonic, passphrase: str) -> bytes:
    """Return seed from mnemonic according to Electrum standard.
    
    Please note: in the Electrum standard, mnemonic conveys BIP32
    derivation rule too. As such, seed alone is partial information.
    """

    hf_name = 'sha512'
    password = mnemonic.encode()
    salt = ('electrum' + passphrase).encode()
    iterations = 2048
    dksize = 64
    return pbkdf2_hmac(hf_name, password, salt, iterations, dksize)


def masterxprv_from_mnemonic(mnemonic: Mnemonic,
                             passphrase: str,
                             testnet: bool = False) -> bytes:
    """Return BIP32 master extended private key from Electrum mnemonic.

    Note that for a standard mnemonic the derivation path is "m",
    for a segwit mnemonic it is "m/0h" instead.
    """

    seed = _seed_from_mnemonic(mnemonic, passphrase)

    # verify that the mnemonic is versioned
    s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
    if s.startswith(ELECTRUM_MNEMONIC_VERSIONS['standard']):
        xversion = bip32.TEST_tprv if testnet else bip32.MAIN_xprv
        return bip32.rootxprv_from_seed(seed, xversion)
    elif s.startswith(ELECTRUM_MNEMONIC_VERSIONS['segwit']):
        xversion = bip32.TEST_vprv if testnet else bip32.MAIN_zprv
        rootxprv = bip32.rootxprv_from_seed(seed, xversion)
        return bip32.ckd(rootxprv, 0x80000000)  # "m/0h"
    elif s.startswith(ELECTRUM_MNEMONIC_VERSIONS['2fa']):
        raise ValueError(f"2fa mnemonic version is not managed yet")
    elif s.startswith(ELECTRUM_MNEMONIC_VERSIONS['2fa_segwit']):
        raise ValueError(f"2fa_segwit mnemonic version is not managed yet")
    else:
        raise ValueError(f"unknown electrum mnemonic version ({s[:3]})")
