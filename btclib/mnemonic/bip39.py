#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BIP39 entropy / mnemonic / seed functions.

https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki.

Checksummed entropy (**ENT+CS**) is converted from/to mnemonic.

* bits per word = bpw = 11
* **ENT** = raw entropy
* **CS** = checksum = **ENT** / 32
* **MS** = words in the mnemonic sentence = (**ENT+CS**) / bpw

+-----+----+--------+----+
| ENT | CS | ENT+CS | MS |
+=====+====+========+====+
| 128 |  4 |    132 | 12 |
+-----+----+--------+----+
| 160 |  5 |    165 | 15 |
+-----+----+--------+----+
| 192 |  6 |    198 | 18 |
+-----+----+--------+----+
| 224 |  7 |    231 | 21 |
+-----+----+--------+----+
| 256 |  8 |    264 | 24 |
+-----+----+--------+----+
"""


import secrets
from hashlib import pbkdf2_hmac, sha256
from typing import Optional, Tuple

from btclib.bip32.bip32 import rootxprv_from_seed
from btclib.exceptions import BTClibValueError
from btclib.mnemonic.entropy import (
    BinStr,
    Entropy,
    bin_str_entropy_from_entropy,
    bin_str_entropy_from_wordlist_indexes,
    bytes_entropy_from_str,
    wordlist_indexes_from_bin_str_entropy,
)
from btclib.mnemonic.mnemonic import (
    WORDLISTS,
    Mnemonic,
    indexes_from_mnemonic,
    mnemonic_from_indexes,
)
from btclib.network import NETWORKS


def _entropy_checksum(entropy: Entropy) -> Tuple[BinStr, BinStr]:
    """Return the checksum of the binary string input entropy.

    Entropy must be expressed as binary 0/1 string and
    must be 128, 160, 192, 224, or 256 bits.
    Leading zeros are considered genuine entropy, not redundant padding.
    """

    bin_str_entropy = bin_str_entropy_from_entropy(entropy)
    bytes_entropy = bytes_entropy_from_str(bin_str_entropy)

    # 256-bit checksum
    bytes_checksum = sha256(bytes_entropy).digest()
    # integer checksum (leading zeros are lost)
    int_checksum = int.from_bytes(bytes_checksum, byteorder="big", signed=False)
    # convert checksum to binary '01' string
    checksum = bin(int_checksum)[2:]  # remove '0b'
    checksum = checksum.zfill(256)  # pad with leading lost zeros
    # leftmost bits
    checksum_bits = len(bytes_entropy) // 4
    return bin_str_entropy, checksum[:checksum_bits]


def mnemonic_from_entropy(
    entropy: Optional[Entropy] = None, lang: str = "en"
) -> Mnemonic:
    """Convert input entropy to BIP39 checksummed mnemonic sentence.

    Input entropy can be expressed as
    binary 0/1 string, bytes-like, or integer;
    it must be 128, 160, 192, 224, or 256 bits.

    In the case of binary 0/1 string and bytes-like,
    leading zeros are not considered redundant padding.

    In the case of integer, where leading zeros cannot be represented,
    if the bit length is not an allowed value, then the binary 0/1
    string is padded with leading zeros up to the next allowed bit
    length; if the integer bit length is longer than the maximum
    length, then only the leftmost bits are retained.
    """

    if entropy is None or entropy == "":
        entropy = secrets.randbits(128)
    bin_str_entropy, checksum = _entropy_checksum(entropy)
    base = WORDLISTS.language_length(lang)
    indexes = wordlist_indexes_from_bin_str_entropy(bin_str_entropy + checksum, base)
    return mnemonic_from_indexes(indexes, lang)


def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> BinStr:
    "Return the entropy from the BIP39 checksummed mnemonic sentence."

    indexes = indexes_from_mnemonic(mnemonic, lang)
    base = WORDLISTS.language_length(lang)
    cs_entropy = bin_str_entropy_from_wordlist_indexes(indexes, base)

    bits = int(len(cs_entropy) * 32 / 33)
    # entropy is only the first part of cs_entropy
    # the second part being the checksum, to be verified
    bin_str_entropy, checksum = _entropy_checksum(cs_entropy[:bits])
    if cs_entropy[bits:] != checksum:
        err_msg = f"invalid checksum: {cs_entropy[bits:]}; expected: {checksum}"
        raise BTClibValueError(err_msg)

    return bin_str_entropy


def seed_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str, verify_checksum: bool = True
) -> bytes:
    """Return the seed from the provided BIP39 mnemonic sentence.

    The mnemonic checksum verification can be skipped if needed.
    """

    # clean up mnemonic from spurious whitespaces
    mnemonic = " ".join(mnemonic.split())

    if verify_checksum:
        entropy_from_mnemonic(mnemonic)

    hf_name = "sha512"
    password = mnemonic.encode()
    salt = ("mnemonic" + passphrase).encode()
    iterations = 2048
    dksize = 64
    return pbkdf2_hmac(hf_name, password, salt, iterations, dksize)


def mxprv_from_mnemonic(
    mnemonic: Mnemonic,
    passphrase: Optional[str] = None,
    network: str = "mainnet",
    verify_checksum: bool = True,
) -> str:
    "Return BIP32 root master extended private key from BIP39 mnemonic."

    seed = seed_from_mnemonic(mnemonic, passphrase or "", verify_checksum)
    version = NETWORKS[network].bip32_prv
    return rootxprv_from_seed(seed, version)
