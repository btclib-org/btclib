#!/usr/bin/python3

"""electrum entropy / mnemonic / seed functions"""

from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32 import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
from mnemonic import mnemonic_dict

MNEMONIC_VERSIONS = {'standard' : '01',
                     'segwit'   : '100',
                     '2fa'      : '101'}

# entropy can be expresses as binary string, bytes-like, or int
def electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang):
    # electrum consider entropy as integer, losing any leading zero
    # https://github.com/spesmilo/electrum/blob/master/lib/mnemonic.py

    if type(raw_entropy) == str:
        raw_entropy = int(raw_entropy, 2)
    elif type(raw_entropy) == bytes:
        raw_entropy = int.from_bytes(raw_entropy, 'big')
    elif type(raw_entropy) != int:
        raise ValueError("entropy must be bytes, hexstring, or int")

    assert version in MNEMONIC_VERSIONS, "unknown electrum mnemonic version"
    invalid = True
    while invalid:
        indexes = mnemonic_dict.indexes_from_entropy(raw_entropy, lang)
        mnemonic = mnemonic_dict.mnemonic_from_indexes(indexes, lang)
        # version validity check
        s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
        if s.startswith(MNEMONIC_VERSIONS[version]): invalid = False
        # next trial
        raw_entropy += 1
    
    return mnemonic

# entropy is returned as binary string
def electrum_entropy_from_mnemonic(mnemonic, lang):
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)
    return entropy


def electrum_seed_from_mnemonic(mnemonic, passphrase):
  seed = PBKDF2(mnemonic, 'electrum' + passphrase,
                2048, sha512).read(64) # 512 bits
  return seed


def electrum_master_prvkey_from_mnemonic(mnemonic, passphrase):
  seed = electrum_seed_from_mnemonic(mnemonic, passphrase)

  # verify that the mnemonic is versioned
  s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
  if s.startswith(MNEMONIC_VERSIONS['standard']):
    return bip32_master_prvkey_from_seed(seed)
  elif s.startswith(MNEMONIC_VERSIONS['segwit']):
    # FIXME: parametrizazion of the prefix is needed
    mprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    # why this hardned derivation?
    return bip32_ckd(mprv, 0x80000000)
  else:
    raise ValueError("unmanaged electrum mnemonic version")


def electrum_master_prvkey_from_raw_entropy(raw_entropy, words, version, passphrase, lang):
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang)
  mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
  return mprv


import unittest
import os
import json

class TestMnemonicDictionaries(unittest.TestCase):
    def test_electrum_wallet(self):
        lang = "en"

        raw_entropy = 0x110aaaa03974d093eda670121023cd0772
        version = 'standard'
        mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang)
        entropy = int(electrum_entropy_from_mnemonic(mnemonic, lang), 2)
        self.assertLess(entropy-raw_entropy, 0xfff)

    def test_electrum_vectors(self):
        filename = "test_electrum_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "../data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)
        f.closed

        for test_vector in test_vectors:
            test_mnemonic = test_vector[1]
            passphrase = test_vector[2]
            test_mpub = test_vector[3]
            mprv = electrum_master_prvkey_from_mnemonic(test_mnemonic, passphrase)
            mpub = bip32_xpub_from_xprv(mprv).decode()
            self.assertEqual(mpub, test_mpub)
            
            lang = "en"
            entropy = int(electrum_entropy_from_mnemonic(test_mnemonic, lang), 2)
            version = test_vector[0]
            mnemonic = electrum_mnemonic_from_raw_entropy(entropy, version, lang)
            self.assertEqual(mnemonic, test_mnemonic)

 
if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
