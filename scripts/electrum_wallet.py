# -*- coding: utf-8 -*-
"""
Created on Sun Dec 10 16:53:56 2017

@author: dfornaro, fametrano
"""

# This script gives you the basic functions to generate your own Electrum mnemonic phrase and the corresponding wallet, without relying on a random function.
# The randomness must be guaranteed by the entropy inserted as input. This entropy is entirely entrusted to the user.
#
# dict_eng.txt: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
# dict_ita.txt: https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt

from bip39_functions import bip39_seed_from_mnemonic, bip39_mnemonic_from_ints
from electrum_seed import verify_mnemonic_electrum, electrum_ints_from_entropy
from bip32_functions import bip32_master_prvkey_from_seed, bip32_xpub_from_xprv, bip32_derive, address_from_xpub

def generate_wallet_electrum(entropy, number_words = 24, passphrase='', version = "standard", dictionary = 'dict_eng.txt'):
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
  xpub = bip32_xpub_from_xprv(xprv)
  return mnemonic, seed, xprv, xpub, entropy

def test_wallet():

  # number of words chosen by the user:
  number_words = 24
  entropy_lenght = int(11*number_words/4)
  print('Your entropy should have', entropy_lenght, 'hexadecimal digits')

  # entropy is entered by the user
  entropy = 0x545454545454545453335454545454545454545454545454545454545454666666

  # dictionary chosen by the user:
  dictionary = 'dict_ita.txt'
  dictionary = 'dict_eng.txt'

  # passphrase chosen by the user:
  passphrase = ''

  # version chosen by the user:
  version = 'standard'

  mnemonic, seed, xprv, xpub, entropy = generate_wallet_electrum(entropy, number_words, passphrase, version, dictionary)

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
