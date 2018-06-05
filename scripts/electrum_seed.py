# -*- coding: utf-8 -*-
"""
Created on Fri Nov 17 14:34:59 2017

@author: dfornaro, fametrano
"""

# This script gives you the basic functions used for the Electrum seed and its mnemonic phrase

from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_prvkey_from_seed, bip32_xpub_from_xprv, bip32_ckd
from bip39_functions import bip39_seed_from_mnemonic, bip39_mnemonic_from_ints

def electrum_ints_from_entropy(entropy, number_words):
  # Function that transforms the entropy number in a vector of numbers with 11 bits each 
  # INPUT:
  #   entropy: number large enough to guarantee randomness
  #   number_words: number of words required in the mnemonic phrase
  # OUTPUT:
  #   mnemonic_int: vector of numbers, each of this number with 11 bits each
  assert entropy < 2**(11*number_words)
  entropy_bin = bin(entropy)
  while len(entropy_bin)< number_words*11+2:
    entropy_bin = '0b0' + entropy_bin[2:]
  entropy_checked = entropy_bin[2:]
  ints = [0]*number_words
  for i in range(0,number_words):
    ints[i] = int(entropy_checked[i*11:(i+1)*11],2)
  return ints

def electrum_wallet(entropy, number_words = 24, passphrase='', version = "standard", dictionary = 'dict_eng.txt'):
  # Function that generates a valid electrum mnemonic and the related master extended public key, from a given entropy and with a specific version
  # INPUT:
  #   entropy: number large enough to guarantee randomness
  #   number_words: number of words requested
  #   passphrase: string used as passphrase
  #   version: version required for the Electrum wallet
  #   dictionary: string with the name of the dictionary file (.txt)
  # OUTPUT:
  #   mnemonic: Electrum mnemonic phrase
  #   entropy: final entropy really used
  #   xpub: master extended public key derived from the mnemonic phrase + passphrase
  is_verify = False
  while not is_verify:
    mnemonic_int = electrum_ints_from_entropy(entropy, number_words)
    mnemonic = bip39_mnemonic_from_ints(mnemonic_int, dictionary)
    is_verify = verify_mnemonic_electrum(mnemonic, version)
    if not is_verify:
      entropy = entropy + 1
  seed = bip39_seed_from_mnemonic(mnemonic, passphrase, "electrum")
  xprv = bip32_master_prvkey_from_seed(seed)
  return  entropy, mnemonic, seed, xprv

def test_electrum_wallet():

  # number of words chosen by the user:
  number_words = 24
  entropy_lenght = int(11*number_words/4)
  print('\nYour entropy should have', entropy_lenght, 'hexadecimal digits')

  # entropy is entered by the user
  entropy = 0x545454545454545453335454545454545454545454545454545454545454666666

  # dictionary chosen by the user:
  dictionary = 'dict_ita.txt'
  dictionary = 'dict_eng.txt'

  # passphrase chosen by the user:
  passphrase = ''

  # version chosen by the user:
  version = 'standard'

  entropy, mnemonic, seed, xprv = electrum_wallet(entropy, number_words, passphrase, version, dictionary)
  print('entropy:', hex(entropy))
  print('mnemonic:', mnemonic)
  print('seed:', seed.hex())
  print('xprv:', xprv)

def verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version = "standard", passphrase = ''):
  # Function used to verify the correctness of an Electrum mnemonic and its xpub wrt its version
  # INPUT:
  #   mnemonic: Electrum mnemonic phrase
  #   xpub_electrum: extended public key (shown by Electrum)
  #   version: version that we need to verify
  #   passphrase: passphrase used for the seed derivation
  # OUTPUT:
  #   seed: seed for the BIP32 HD wallet
  t = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).digest()
  s = t.hex()
  seed = bip39_seed_from_mnemonic(mnemonic, passphrase, "electrum")
  #seed = int(seed, 16)
  #seed_bytes = 64  
  if s[0:2] == '01':
    assert version == "standard"
    xprv = bip32_master_prvkey_from_seed(seed)
  elif s[0:3] == '100':
    assert version == "segwit"
    xprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    xprv = bip32_ckd(xprv, 0x80000000)
  else:
    print("\nVersion unknown")
    return False
  xpub = bip32_xpub_from_xprv(xprv)
  assert xpub_electrum == xpub

def verify_mnemonic_electrum(mnemonic, version = "standard"):
  # Function used to verify the correctness of an Electrum mnemonic wrt its version
  # INPUT:
  #   mnemonic: Electrum mnemonic phrase
  #   version: version that we need to verify
  # OUTPUT:
  #   boolean: True if the version matches, False otherwise 
  t = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).digest()
  s = t.hex()
  if s[0:2] == '01':
    return version == "standard"
  elif s[0:3] == '100':
    return version == "segwit"
  elif s[0:3] == '101':
    return version == "2FA"
  else:
    return False
  return True

### Test Vectors
# These test vectors are obtained directly with Electrum:
# First a new mnemonic phrase was generated, through Electrum software, with a chosen version
# Then we check that the mnemonic phrase matches with the version and that generates the corresponding xpub

def my_test_vector_1():
  mnemonic = "term gain fish all ivory talent gold either trap today balance kingdom"
  xpub_electrum = b"xpub661MyMwAqRbcGJg6qHFEYXMkbKuREsjWXQJetGTYQuz8GLBPfUtKs53bAW1MP4JPUSEKK6m9dVzJhDbw5xf3NPbH7PHwXrkPY89cVLLTAk8"
  version = "standard"
  verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version)

def my_test_vector_2():
  mnemonic = "guard chat liar swallow zebra retire practice expand hood spider alert evolve"
  xpub_electrum = b"xpub661MyMwAqRbcGi3axFUKX8iu4QFqP37XpXnXJPqY37wqyBaX64mERS3cXkoM8PRECUNUPP6foH9HdxHGriV2fFyPmDvjZ9eg2HTiPdM49rs"
  version = "standard"
  verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version)

def my_test_vector_3():
  mnemonic = "kind hazard heavy super novel book horn price bone misery moon depend"
  passphrase = "danielefornaro"
  xpub_electrum = b"xpub661MyMwAqRbcFv1yFk3WaqMFpHUKNvn1qGDyJhdp7yL18V9pwibKWVUebSCzwPSMEioVWKzcyktvyMaYN3Lips4zyu5idw7keWi7pmZSfwq"
  version = "standard"
  verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version, passphrase)

def my_test_vector_4():
  mnemonic = "glad shoulder possible elder route remind suit unable hedgehog pistol era define"
  xpub_electrum = b"zpub6nnNomZvczQDUvRZh1xThQTcSaV54NJiQBhvswqC5jG32fWm2LnURBDSM1Argj2B2fR6xAKEAMj1PuZ2wEZzjGZcbAPhbGa2RtDoMKaTE7L"
  version = "segwit"
  verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version)

def my_test_vector_5():
  mnemonic = "slogan detect embark famous flip middle impact normal price artwork program power"
  passphrase = "danielefornaro"
  xpub_electrum = b"zpub6nC6GjnipUB41rp3yS2TozLkyoHiR4jCHJiZ69GhsJRNEeXJR63fV5sCoHTkhc999fevr5S78b6XPydetbe5w2b5HHpUoWCLHCfe55VknvX"
  version = "segwit"
  verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version, passphrase)

def my_test_vector_6():
  mnemonic = "miss mixed vibrant cheap riot comfort pulse forum pet injury slogan fame"
  passphrase = "fatti non foste a viver come bruti"
  xpub_electrum = b"zpub6nfRLg2gunSr2LyRpGxzW5pdrvtHxLS5JzNtGWdef5M7wKs3m4CiyzPDe3zXGFLqABKK1gA41mXgKq3jyfgcH4nsCzWfBVsPSpJvFEDCUzT"
  version = "segwit"
  verify_mnemonic_and_xpub_electrum(mnemonic, xpub_electrum, version, passphrase)

def test_vector():
  my_test_vector_1()
  my_test_vector_2()
  my_test_vector_3()
  my_test_vector_4()
  my_test_vector_5()
  my_test_vector_6()
  
if __name__ == "__main__":
  test_vector()
  test_electrum_wallet()
