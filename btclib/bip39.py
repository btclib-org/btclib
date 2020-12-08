#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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


from hashlib import pbkdf2_hmac, sha256

from .entropy import (
    BinStr,
    Entropy,
    _bits,
    _entropy_from_indexes,
    _indexes_from_entropy,
    binstr_from_entropy,
)
from .exceptions import BTClibValueError
from .mnemonic import (
    Mnemonic,
    _indexes_from_mnemonic,
    _mnemonic_from_indexes,
    _wordlists,
)

_words = tuple(b // 32 * 3 for b in _bits)


def _entropy_checksum(binstr_entropy: BinStr) -> BinStr:
    """Return the checksum of the binary string input entropy.

    Entropy must be expressed as binary 0/1 string and
    must be 128, 160, 192, 224, or 256 bits.
    Leading zeros are considered genuine entropy, not redundant padding.
    """

    nbits = len(binstr_entropy)
    int_entropy = int(binstr_entropy, 2)
    if nbits not in _bits:
        m = f"invalid number of bits for BIP39 entropy: {nbits}; must be in {_bits}"
        raise BTClibValueError(m)
    nbytes = (nbits + 7) // 8
    bytes_entropy = int_entropy.to_bytes(nbytes, byteorder="big", signed=False)

    # 256-bit checksum
    byteschecksum = sha256(bytes_entropy).digest()
    # integer checksum (leading zeros are lost)
    intchecksum = int.from_bytes(byteschecksum, byteorder="big", signed=False)
    # convert checksum to binary '01' string
    checksum = bin(intchecksum)[2:]  # remove '0b'
    checksum = checksum.zfill(256)  # pad with leading lost zeros
    # leftmost bits
    checksum_bits = nbytes // 4
    return checksum[:checksum_bits]


def mnemonic_from_entropy(entropy: Entropy, lang: str = "en") -> Mnemonic:
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

    binstr_entropy = binstr_from_entropy(entropy, _bits)
    checksum = _entropy_checksum(binstr_entropy)
    base = _wordlists.language_length(lang)
    indexes = _indexes_from_entropy(binstr_entropy + checksum, base)
    return _mnemonic_from_indexes(indexes, lang)


def entropy_from_mnemonic(mnemonic: Mnemonic, lang: str = "en") -> BinStr:
    "Return the entropy from the BIP39 checksummed mnemonic sentence."

    words = len(mnemonic.split())
    if words not in _words:
        msg = f"Wrong number of words: ({words}); expected: {_words}"
        raise BTClibValueError(msg)

    indexes = _indexes_from_mnemonic(mnemonic, lang)
    base = _wordlists.language_length(lang)
    cs_entropy = _entropy_from_indexes(indexes, base)

    # entropy is only the first part of cs_entropy
    bits = int(len(cs_entropy) * 32 / 33)
    binstr_entropy = cs_entropy[:bits]

    # the second part being the checksum, to be verified
    checksum = _entropy_checksum(binstr_entropy)
    if cs_entropy[bits:] != checksum:
        m = f"invalid checksum: {cs_entropy[bits:]}; expected: {checksum}"
        raise BTClibValueError(m)

    return binstr_entropy


def seed_from_mnemonic(
    mnemonic: Mnemonic, passphrase: str, verify_checksum=True
) -> bytes:
    """Return the seed from the provided BIP39 mnemonic sentence.

    The mnemonic checksum verification can be skipped if needed.
    """

    if verify_checksum:
        entropy_from_mnemonic(mnemonic)

    hf_name = "sha512"
    # clean up mnemonic from spurious whitespaces
    password = " ".join(mnemonic.split()).encode()
    salt = ("mnemonic" + passphrase).encode()
    iterations = 2048
    dksize = 64
    return pbkdf2_hmac(hf_name, password, salt, iterations, dksize)
