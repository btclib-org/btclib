#!/usr/bin/python3

"""BIP39 functions"""

from hashlib import sha256, sha512
from pbkdf2 import PBKDF2
from mnemonic import mnemonic_dict
from bip32_functions import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
import os
import json

def bip39_raw_entropy_checksum(raw_entr):
    # raw_entr 256-bit checksum
    checksum = sha256(raw_entr).digest()       # 256 bits
    # convert checksum to binary '01' string
    checksum = int.from_bytes(checksum, 'big') # leading zeros are lost
    checksum = bin(checksum)[2:]               # remove '0b'
    checksum = checksum.zfill(256)             # pad with lost zeros
    # rightmost bits
    checksum_bits = len(raw_entr) // 4
    return checksum[:checksum_bits]

#  bits per word = bpw = 11
#  CheckSum = raw ENTropy / 32
#  MnemonicSentence (in words) = (ENT + CS) / bpw
#
# |  ENT  | CS | ENT+CS |  MS  |
# +-------+----+--------+------+
# |  128  |  4 |   132  |  12  |
# |  160  |  5 |   165  |  15  |
# |  192  |  6 |   198  |  18  |
# |  224  |  7 |   231  |  21  |
# |  256  |  8 |   264  |  24  |
_allowed_raw_entr_bit_sizes = (128, 160, 192, 224, 256)

# raw entropy can be expresse in bytes, hex string or int
# hex string and bytes must be 128, 160, 192, 224, or 256 bits
# int is padded with leading zeros up to 128, 160, 192, 224, or 256 bits
# entropy is instead expressed as binary string
# other specifications as per
# https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
def bip39_entropy_from_raw_entropy(raw_entr):
    if type(raw_entr) == str:
        raw_entr = bytes.fromhex(raw_entr)

    if type(raw_entr) == bytes:
        raw_entr_bits = len(raw_entr) * 8
        assert raw_entr_bits in _allowed_raw_entr_bit_sizes
    elif type(raw_entr) == int:
        raw_entr_bits = raw_entr.bit_length()
        for i in _allowed_raw_entr_bit_sizes:
            if raw_entr_bits < i:
                raw_entr_bits = i
                break
        assert raw_entr_bits in _allowed_raw_entr_bit_sizes
        raw_entr = raw_entr.to_bytes(raw_entr_bits//8, 'big')
    else:
        raise ValueError("entropy must be bytes, hexstring, or int")

    checksum = bip39_raw_entropy_checksum(raw_entr)

    # convert raw_entr to binary '01' string
    raw_entr = int.from_bytes(raw_entr, 'big') # leading zeros are lost
    raw_entr = bin(raw_entr)[2:]               # remove '0b'
    raw_entr = raw_entr.zfill(raw_entr_bits)   # pad with lost zeros

    return raw_entr + checksum


def bip39_mnemonic_from_raw_entropy(raw_entr, lang):
    entropy = bip39_entropy_from_raw_entropy(raw_entr)
    indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
    return mnemonic_dict.mnemonic_from_indexes(indexes, lang)


def bip39_raw_entropy_from_mnemonic(mnemonic, lang):
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)

    # raw entropy is only the first part of entropy
    raw_entr_bits = int(len(entropy)*32/33)
    assert raw_entr_bits in _allowed_raw_entr_bit_sizes, "invalid entropy size"
    raw_entr = entropy[:raw_entr_bits]
    
    # the second one being the checksum, to be verified
    bytes_raw_entr = int(raw_entr, 2).to_bytes(raw_entr_bits//8, 'big')
    checksum = bip39_raw_entropy_checksum(bytes_raw_entr)
    assert entropy[raw_entr_bits:] == checksum
    
    # package result as bytes
    raw_entr_bytes = raw_entr_bits//8
    raw_entr = int(raw_entr, 2)
    return raw_entr.to_bytes(raw_entr_bytes, 'big')

# TODO: re-evaluate style
def bip39_seed_from_mnemonic(mnemonic, passphrase):
    seed = PBKDF2(mnemonic, 'mnemonic' + passphrase,
                  2048, sha512).read(64) # 512 bits
    return seed

# TODO: re-evaluate style
def bip39_master_prvkey_from_mnemonic(mnemonic, passphrase):
    seed = bip39_seed_from_mnemonic(mnemonic, passphrase)
    return bip32_master_prvkey_from_seed(seed)

# TODO move to wallet file
def bip39_master_prvkey_from_raw_entropy(raw_entr, passphrase, lang):
    mnemonic = bip39_mnemonic_from_raw_entropy(raw_entr, lang)
    return bip39_master_prvkey_from_mnemonic(mnemonic, passphrase)


def test_bip39_wallet():
    lang = "en"
    bpw = mnemonic_dict.bits_per_word(lang) # 11
    words = 12
    # ENT = entropy bits
    # CS  = checksum bits
    # ENT + CS     = words*bpw
    # ENT + ENT/32 = words*bpw
    # ENT * 33/32  = words*bpw
    # ENT          = words*bpw*32/33
    # hexdigits    = words*bpw*32/33/4
    bits = (words*bpw*32)//33
    print("\nFor a", words, "words target", bits,
          'bits of entropy are needed, i.e.', bits//4, 'hexadecimal digits')

    raw_entr = "0000003974d093eda670121023cd0000"
    print(int(len(raw_entr)/2), "bytes raw entropy:", raw_entr)

    mnemonic = bip39_mnemonic_from_raw_entropy(raw_entr, lang)
    assert raw_entr == bip39_raw_entropy_from_mnemonic(mnemonic, lang).hex()
    print('mnemonic:', mnemonic)

    passphrase = ''
    mpr = bip39_master_prvkey_from_mnemonic(mnemonic, passphrase)
    print('mprv:', mpr)


# Test vectors:
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
def bip39_test_vectors():
    filename = "bip39_test_vectors.json"
    path_to_filename = os.path.join(os.path.dirname(__file__),
                                    # folder,
                                    filename)
    with open(path_to_filename, 'r') as f:
        test_vectors = json.load(f)["english"]
    f.closed
    for test_vector in test_vectors:
        lang = "en"
        mnemonic = bip39_mnemonic_from_raw_entropy(test_vector[0], lang)
        if mnemonic != test_vector[1]:
            raise ValueError("\n" + mnemonic + "\n" + test_vector[1])

        raw_entr = bip39_raw_entropy_from_mnemonic(mnemonic, lang).hex()
        if raw_entr != test_vector[0]:
            raise ValueError("\n" + raw_entr + "\n" + test_vector[0])

        seed = bip39_seed_from_mnemonic(mnemonic, "TREZOR").hex()
        if seed != test_vector[2]:
            raise ValueError("\n" + seed + "\n" + test_vector[2])
        # test_vector[3], i.e. the bip32 master private key from seed,
        # has been tested in bip32, as it does not belong here


if __name__ == "__main__":
    bip39_test_vectors()
    test_bip39_wallet()
