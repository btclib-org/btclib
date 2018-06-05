# -*- coding: utf-8 -*-
"""
Created on Mon Dec 11 09:17:49 2017

@author: dfornaro, fametrano
"""

# This script gives you the basic functions to generate your own mnemonic phrase, without relying on a random function.
# The randomness must be guaranteed by the entropy inserted as input. This entropy is entirely entrusted to the user.
#
# dict_eng.txt: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
# dict_ita.txt: https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt

from bip39_functions import bip39_ints_from_entropy, bip39_mnemonic_from_ints, bip39_seed_from_mnemonic
from bip32_functions import bip32_master_prvkey_from_seed, bip32_xpub_from_xprv, bip32_derive, address_from_xpub

def bip39_wallet(entropy, number_words = 24, passphrase='', dictionary = 'dict_eng.txt'):
  # Function that generate a valid BIP39 mnemonic and the related master extended public key, from a given entropy
  # INPUT:
  #   entropy: number large enough to guarantee randomness
  #   number_words: number of words requested
  #   passphrase: string used as passphrase
  #   dictionary: string with the name of the dictionary file (.txt)
  # OUTPUT:
  #   mnemonic: mnemonic phrase with BIP39
  #   xpub: master extended public key derived from the mnemonic phrase + passphrase
  ENT = int(number_words*32/3)
  ints = bip39_ints_from_entropy(entropy, ENT)
  mnemonic = bip39_mnemonic_from_ints(ints, dictionary)
  seed = bip39_seed_from_mnemonic(mnemonic, passphrase)
  xprv = bip32_master_prvkey_from_seed(seed)
  xpub = bip32_xpub_from_xprv(xprv)
  return mnemonic, seed, xprv, xpub


def test_wallet():

  # number of words chosen by the user:
  number_words = 12
  entropy_lenght = int(number_words*32/3/4)
  print('Your entropy should have', entropy_lenght, 'hexadecimal digits')

  # entropy is entered by the user:
  entropy = 0xf012003974d093eda670121023cd03bb
  print(hex(entropy))

  # dictionary chosen by the user:
  dictionary = 'dict_ita.txt'
  dictionary = 'dict_eng.txt'

  # passphrase chosen by the user:
  passphrase = ''

  mnemonic, seed, xprv, xpub = bip39_wallet(entropy, number_words, passphrase, dictionary)

  print('\nmnemonic:', mnemonic)
  print('\nseed:', seed.hex())
  print('\nxprv:', xprv)
  print('\nxpub:', xpub)

  receive0 = bip32_derive(xpub, "./0/0")
  receive1 = bip32_derive(xpub, "./0/1")
  receive2 = bip32_derive(xpub, "./0/2")
  receive3 = bip32_derive(xpub, "./0/3")

  change0 = bip32_derive(xpub, "./1/0")
  change1 = bip32_derive(xpub, "./1/1")
  change2 = bip32_derive(xpub, "./1/2")
  change3 = bip32_derive(xpub, "./1/3")

  print()
  print('1st receive address: ', address_from_xpub(receive0))
  print('2nd receive address: ', address_from_xpub(receive1))
  print('3rd receive address: ', address_from_xpub(receive2))
  print('4th receive address: ', address_from_xpub(receive3))
  print()
  print('1st change address: ', address_from_xpub(change0))
  print('2nd change address: ', address_from_xpub(change1))
  print('3rd change address: ', address_from_xpub(change2))
  print('4th change address: ', address_from_xpub(change3))

if __name__ == "__main__":
  test_wallet()
