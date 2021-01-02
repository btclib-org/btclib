#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Electrum entropy / mnemonic / seed functions.

Electrum mnemonic is versioned, conveying BIP32 derivation rule too.
"""

import hmac
from hashlib import pbkdf2_hmac, sha512
from typing import Optional, Tuple

from btclib.bip32.bip32 import derive, rootxprv_from_seed
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.entropy import (
    BinStr,
    Entropy,
    bin_str_entropy_from_entropy,
    bin_str_entropy_from_wordlist_indexes,
    wordlist_indexes_from_bin_str_entropy,
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


def version_from_mnemonic(mnemonic: Mnemonic) -> Tuple[str, str]:
    """Return the (Electrum version, clean mnemonic) tuple.

    The clean mnemonic is free from spurious whitespace characters
    (extra spaces, tab, newline, return, formfeed, etc.)
    """

    # split remove spurious whitespaces
    mnemonic = " ".join(mnemonic.split())
    s = hmac.new(b"Seed version", mnemonic.encode(), sha512).hexdigest()

    if s.startswith(_MNEMONIC_VERSIONS["standard"]):
        return "standard", mnemonic
    if s.startswith(_MNEMONIC_VERSIONS["segwit"]):
        return "segwit", mnemonic
    if s.startswith(_MNEMONIC_VERSIONS["2fa"]):
        return "2fa", mnemonic
    if s.startswith(_MNEMONIC_VERSIONS["2fa_segwit"]):
        return "2fa_segwit", mnemonic

    err_msg = f"unknown electrum mnemonic version: '{s[:3]}'; "
    err_msg += f"not in {list(_MNEMONIC_VERSIONS.keys())}"
    raise BTClibValueError(err_msg)


def mnemonic_from_entropy(
    entropy: Entropy, version_str: str = "standard", lang: str = "en"
) -> Mnemonic:
    """Convert input entropy to Electrum versioned mnemonic sentence.

    Input entropy can be expressed as
    binary 0/1 string, bytes-like, or integer.

    In the case of binary 0/1 string and bytes-like,
    leading zeros are considered redundant padding.
    """

    if version_str not in _MNEMONIC_VERSIONS:
        err_msg = f"unknown electrum mnemonic version: '{version_str}'; "
        err_msg += f"not in {list(_MNEMONIC_VERSIONS.keys())}"
        raise BTClibValueError(err_msg)
    version = _MNEMONIC_VERSIONS[version_str]

    bin_str_entropy = bin_str_entropy_from_entropy(entropy)
    int_entropy = int(bin_str_entropy, 2)
    base = WORDLISTS.language_length(lang)
    while True:
        # electrum considers entropy as integer, losing any leading zero
        # so the value of bin_str_entropy before the while must be updated
        nbits = int_entropy.bit_length()
        bin_str_entropy = bin_str_entropy_from_entropy(int_entropy, nbits)
        indexes = wordlist_indexes_from_bin_str_entropy(bin_str_entropy, base)
        mnemonic = mnemonic_from_indexes(indexes, lang)
        # version validity check
        s = hmac.new(b"Seed version", mnemonic.encode(), sha512).hexdigest()
        if s.startswith(version):
            return mnemonic
        # next trial
        int_entropy += 1


def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> BinStr:
    "Return the entropy from the Electrum versioned mnemonic sentence."

    # verify that it is a valid Electrum mnemonic sentence
    version_from_mnemonic(mnemonic)

    indexes = indexes_from_mnemonic(mnemonic, lang)
    base = WORDLISTS.language_length(lang)
    return bin_str_entropy_from_wordlist_indexes(indexes, base)


def _seed_from_mnemonic(mnemonic: Mnemonic, passphrase: str) -> Tuple[str, bytes]:
    "Return (version, seed) from the provided Electrum mnemonic."

    # clean up mnemonic from spurious whitespaces
    version, mnemonic = version_from_mnemonic(mnemonic)

    hf_name = "sha512"
    password = mnemonic.encode()
    salt = ("electrum" + passphrase).encode()
    iterations = 2048
    dksize = 64
    return version, pbkdf2_hmac(hf_name, password, salt, iterations, dksize)


def mxprv_from_mnemonic(
    mnemonic: Mnemonic, passphrase: Optional[str] = None, network: str = "mainnet"
) -> str:
    """Return BIP32 master extended private key from Electrum mnemonic.

    Note that for a "standard" mnemonic the derivation path is "m",
    for a "segwit" mnemonic it is "m/0h" instead.
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
