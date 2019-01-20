#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BIP39 entropy / mnemonic / seed functions"""

from hashlib import sha256, pbkdf2_hmac

from btclib.entropy import Entropy, GenericEntropy, bytes_from_entropy, \
    str_from_entropy
from btclib.mnemonic import mnemonic_dict
from btclib import bip32


def raw_entropy_checksum(raw_entr: GenericEntropy) -> Entropy:
    raw_entr = bytes_from_entropy(raw_entr, _allowed_raw_entr_bits)
    # raw_entr 256-bit checksum
    byteschecksum = sha256(raw_entr).digest()  # 256 bits
    # convert checksum to binary '01' string
    intchecksum = int.from_bytes(
        byteschecksum, 'big')                  # leading zeros are lost
    checksum = bin(intchecksum)[2:]            # remove '0b'
    checksum = checksum.zfill(256)             # pad with lost zeros
    # rightmost bits
    checksum_bits = len(raw_entr) // 4
    return checksum[:checksum_bits]


#  bits per word = bpw = 11
#  CheckSum = raw ENTropy / 32
#  MnemonicSentence (in words) = (ENT + CS) / bpw
#
# | ENT | CS | ENT+CS | MS |
# +-----+----+--------+----+
# | 128 |  4 |    132 | 12 |
# | 160 |  5 |    165 | 15 |
# | 192 |  6 |    198 | 18 |
# | 224 |  7 |    231 | 21 |
# | 256 |  8 |    264 | 24 |
_allowed_raw_entr_bits = (128, 160, 192, 224, 256)

# https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
#
# input raw entropy can be expresses as binary string, bytes-like, or int
# it must be 128, 160, 192, 224, or 256 bits
# int is pre zero padded up to 128, 160, 192, 224, or 256 bits
#
# output entropy is returned as binary string


def entropy_from_raw_entropy(raw_entropy: GenericEntropy) -> Entropy:
    raw_entropy = str_from_entropy(raw_entropy, _allowed_raw_entr_bits)
    checksum = raw_entropy_checksum(raw_entropy)
    return raw_entropy + checksum


def mnemonic_from_raw_entropy(raw_entr: GenericEntropy,
                                    lang: str) -> str:
    entropy = entropy_from_raw_entropy(raw_entr)
    indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
    mnemonic = mnemonic_dict.mnemonic_from_indexes(indexes, lang)
    return mnemonic

# output raw entropy is returned as binary string


def raw_entropy_from_mnemonic(mnemonic: str, lang: str) -> Entropy:
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)

    # raw entropy is only the first part of entropy
    raw_entr_bits = int(len(entropy)*32/33)
    assert raw_entr_bits in _allowed_raw_entr_bits, "invalid raw entropy size"
    raw_entr = entropy[:raw_entr_bits]

    # the second one being the checksum, to be verified
    bytes_raw_entr = int(raw_entr, 2).to_bytes(raw_entr_bits//8, 'big')
    checksum = raw_entropy_checksum(bytes_raw_entr)
    assert entropy[raw_entr_bits:] == checksum

    return raw_entr

# TODO: re-evaluate style


def seed_from_mnemonic(mnemonic: str, passphrase: str) -> bytes:
    hash_name = 'sha512'
    password = mnemonic.encode()
    salt = ('mnemonic' + passphrase).encode()
    iterations = 2048
    dksize = 64
    return pbkdf2_hmac(hash_name, password, salt, iterations, dksize)

# TODO: re-evaluate style


def mprv_from_mnemonic(mnemonic: str,
                                      passphrase: str,
                                      xversion: bytes) -> bytes:
    seed = seed_from_mnemonic(mnemonic, passphrase)
    return bip32.mprv_from_seed(seed, xversion)

# TODO: move to wallet file


def mprv_from_raw_entropy(raw_entr: GenericEntropy,
                                         passphrase: str,
                                         lang: str,
                                         xversion: bytes) -> bytes:
    mnemonic = mnemonic_from_raw_entropy(raw_entr, lang)
    mprv = mprv_from_mnemonic(mnemonic, passphrase, xversion)
    return mprv
