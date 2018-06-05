# -*- coding: utf-8 -*-
"""
Created on Sun Dec 10 16:53:56 2017

@author: dfornaro, fametrano
"""

# This script gives you the basic functions to generate your own Electrum mnemonic phrase and the corresponding wallet, without relying on a random function.
# The randomness must be guaranteed by the entropy inserted as input. This entropy is entirely entrusted to the user.
#
# English_dictionary: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
# Italian_dictionary: https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt

from electrum_seed import from_mnemonic_to_seed_eletrcum, verify_mnemonic_electrum, from_entropy_to_mnemonic_int_electrum, from_mnemonic_int_to_mnemonic_electrum
from bip32_functions import bip32_master_key, bip32_xprvtoxpub, path

def generate_wallet_electrum(entropy, number_words = 24, passphrase='', version = "standard", dictionary = 'English_dictionary.txt'):
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
    mnemonic_int = from_entropy_to_mnemonic_int_electrum(entropy, number_words)
    mnemonic = from_mnemonic_int_to_mnemonic_electrum(mnemonic_int, dictionary)
    is_verify = verify_mnemonic_electrum(mnemonic, version)
    if not is_verify:
      entropy = entropy + 1
  seed = from_mnemonic_to_seed_eletrcum(mnemonic, passphrase)
  seed = int(seed, 16)
  seed_bytes = 64
  xprv = bip32_master_key(seed, seed_bytes)
  xpub = bip32_xprvtoxpub(xprv)
  return mnemonic, entropy, xpub

def generate_receive(xpub, number):
  # Function that generates a valid P2PKH receive address from an extended public key.
  # INPUT:
  #   xpub: extended public key
  #   number: child index
  # OUTPUT:
  #   P2PKH receive address 
  index_child = [0, number]
  return path(xpub, index_child)

def generate_change(xpub, number):
  # Function that generates a valid P2PKH change address from an extended public key.
  # INPUT:
  #   xpub: extended public key
  #   number: child index
  # OUTPUT:
  #   P2PKH change address 
  index_child = [1, number]
  return path(xpub, index_child)

# entropy is entered by the user
entropy = 0x545454545454545453335454545454545454545454545454545454545454666666

# number of words chosen by the user:
number_words = 24
entropy_lenght = int(11*number_words/4)

# dictionary chosen by the user:
dictionary = 'Italian_dictionary.txt'
dictionary = 'English_dictionary.txt'

# passphrase chosen by the user:
passphrase = ''

# version chosen by the user:
version = 'standard'

print('Your entropy should have', entropy_lenght, 'hexadecimal digits')
mnemonic, entropy, xpub = generate_wallet_electrum(entropy, number_words, passphrase, version, dictionary)

print('\nmnemonic: ', mnemonic)
print('\nxpub: ', xpub)

receive0 = generate_receive(xpub, 0)
receive1 = generate_receive(xpub, 1)
receive2 = generate_receive(xpub, 2)
receive3 = generate_receive(xpub, 3)

change0 = generate_change(xpub, 0)
change1 = generate_change(xpub, 1)
change2 = generate_change(xpub, 2)
change3 = generate_change(xpub, 3)

print('\nfirst receive address: ', receive0)
print('second receive address: ', receive1)
print('third receive address: ', receive2)
print('fourth receive address: ', receive3)

print('\nfirst change address: ', change0)
print('second change address: ', change1)
print('third change address: ', change2)
print('fourth change address: ', change3)
