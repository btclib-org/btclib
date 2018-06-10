#!/usr/bin/python3

"""BIP39 entropy / mnemonic / seed functions"""

from hashlib import sha256, sha512
from pbkdf2 import PBKDF2
from mnemonic import mnemonic_dict
from bip32_functions import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
import os
import json
import math

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
_allowed_raw_entr_bits = (128, 160, 192, 224, 256)

# https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
#
# input raw entropy can be expresses as binary string, bytes-like, or int
# it must be 128, 160, 192, 224, or 256 bits
# int is pre zero padded up to 128, 160, 192, 224, or 256 bits
#
# output entropy is returned as binary string
def bip39_entropy_from_raw_entropy(raw_entropy):
    if type(raw_entropy) == str:
        bits = len(raw_entropy)
        assert bits in _allowed_raw_entr_bits, "invalid raw entropy size"
        raw_entropy = int(raw_entropy, 2).to_bytes(bits//8, 'big')
    elif isinstance(raw_entropy, (bytes, bytearray)):
        bits = len(raw_entropy) * 8
        assert bits in _allowed_raw_entr_bits, "invalid raw entropy size"
    elif type(raw_entropy) == int:
        bits = raw_entropy.bit_length()
        for i in _allowed_raw_entr_bits:
            if bits < i:
                bits = i
                break
        assert bits in _allowed_raw_entr_bits, "invalid raw entropy size"
        raw_entropy = raw_entropy.to_bytes(bits//8, 'big')
    else:
        raise ValueError("entropy must be binary string, bytes-like, or int")

    checksum = bip39_raw_entropy_checksum(raw_entropy)

    # convert raw_entropy to binary string
    raw_entropy = int.from_bytes(raw_entropy, 'big') # leading zeros are lost
    raw_entropy = bin(raw_entropy)[2:]               # remove '0b'
    raw_entropy = raw_entropy.zfill(bits)            # pad with lost zeros

    return raw_entropy + checksum


def bip39_mnemonic_from_raw_entropy(raw_entr, lang):
    entropy = bip39_entropy_from_raw_entropy(raw_entr)
    indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
    return mnemonic_dict.mnemonic_from_indexes(indexes, lang)

# output raw entropy is returned as binary string
def bip39_raw_entropy_from_mnemonic(mnemonic, lang):
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)

    # raw entropy is only the first part of entropy
    raw_entr_bits = int(len(entropy)*32/33)
    assert raw_entr_bits in _allowed_raw_entr_bits, "invalid raw entropy size"
    raw_entr = entropy[:raw_entr_bits]
    
    # the second one being the checksum, to be verified
    bytes_raw_entr = int(raw_entr, 2).to_bytes(raw_entr_bits//8, 'big')
    checksum = bip39_raw_entropy_checksum(bytes_raw_entr)
    assert entropy[raw_entr_bits:] == checksum
    
    return raw_entr

# TODO: re-evaluate style
def bip39_seed_from_mnemonic(mnemonic, passphrase):
    seed = PBKDF2(mnemonic, 'mnemonic' + passphrase,
                  2048, sha512).read(64) # 512 bits
    return seed

# TODO: re-evaluate style
def bip39_master_prvkey_from_mnemonic(mnemonic, passphrase):
    seed = bip39_seed_from_mnemonic(mnemonic, passphrase)
    return bip32_master_prvkey_from_seed(seed)

# TODO: move to wallet file
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
          'bits of entropy are needed, i.e.', bits//8, 'bytes')

    raw_entr = bytes.fromhex("0000003974d093eda670121023cd0000")
    print(len(raw_entr), "bytes raw entropy:", raw_entr.hex())

    mnemonic = bip39_mnemonic_from_raw_entropy(raw_entr, lang)
    r = bip39_raw_entropy_from_mnemonic(mnemonic, lang)
    nbytes = math.ceil(len(r)/8)
    r = int(r, 2).to_bytes(nbytes, 'big')
    if r != raw_entr:
        raise ValueError("\n" + r.hex() + "\n" + raw_entr.hex())
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
        test_vector[0] = bytes.fromhex(test_vector[0])
        mnemonic = bip39_mnemonic_from_raw_entropy(test_vector[0], lang)
        if mnemonic != test_vector[1]:
            raise ValueError("\n" + mnemonic + "\n" + test_vector[1])

        raw_entr = bip39_raw_entropy_from_mnemonic(mnemonic, lang)
        nbytes = math.ceil(len(raw_entr)/8)
        raw_entr = int(raw_entr, 2).to_bytes(nbytes, 'big')
        if raw_entr != test_vector[0]:
            raise ValueError("\n" + raw_entr.hex() + "\n" + test_vector[0].hex())

        seed = bip39_seed_from_mnemonic(mnemonic, "TREZOR").hex()
        if seed != test_vector[2]:
            raise ValueError("\n" + seed + "\n" + test_vector[2])
        # test_vector[3], i.e. the bip32 master private key from seed,
        # has been tested in bip32, as it does not belong here


if __name__ == "__main__":
    bip39_test_vectors()
    test_bip39_wallet()
