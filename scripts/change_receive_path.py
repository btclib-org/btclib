# -*- coding: utf-8 -*-
"""
Created on Mon Nov 20 12:26:47 2017

@author: dfornaro, fametrano
"""

# This script is used to test the HD path used by some Bitcoin Wallets.

from bip39 import from_mnemonic_to_seed
from electrum_seed import from_mnemonic_to_seed_eletrcum
from bip32_functions import bip32_master_key, bip32_xprvtoxpub, path

#### Electrum path derivation (bip39) ####
# Electrum gives also the possibility to restore a BIP39 wallet.
# After changed the version of the addresses, we take from Electrum a mnemonic phrase and 2 addresses (change and receive).
# Our goal is to find the path needed to derive the addreeses from the mnemonic phrase:

mnemonic = 'army van defense carry jealous true garbage claim echo media make crunch'
passphrase = ''
receive = 'VTpEhLjvGYE16pLcNrMY53gQB9bbhn581W'
change = 'VRtaZvAe4s29aB3vuXyq7GYEpahsQet2B1'

version = 0x46.to_bytes(1, 'big')

seed = from_mnemonic_to_seed(mnemonic, passphrase)
seed = int(seed, 16)
seed_bytes = 64
xprv = bip32_master_key(seed, seed_bytes)

index_child = [0x80000000, 0, 0]
assert path(xprv, index_child, version) == receive

index_child = [0x80000000, 1, 0]
assert path(xprv, index_child, version) == change

#### Bitcoin-core path derivation ####
# Bitcoin core doesn't implement BIP39 up to now.
# It starts directly from the master private key.
# After changed the version of the addresses, we consider the master key and 2 addresses (change and receive).
# Our goal is to find the path needed to derive the addreeses from the master private key:

xprv = 'xprv9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'
receive = 'VUqyLGVdUADWEqDqL2DeUBAcbPQwZfWDDY' # "hdkeypath": "m/0'/0'/5'"
change = 'VMg6DpX7SQUsoECdpXJ8Bv6R7p11PfwHwy' # "hdkeypath": "m/0'/1'/1'"

version = 0x46.to_bytes(1, 'big')

index_child = [0x80000000, 0x80000000, 0x80000005]
assert path(xprv, index_child, version) == receive

index_child = [0x80000000, 0x80000001, 0x80000001]
assert path(xprv, index_child, version) == change

#### Electrum standard path derivation ####
# The scope of this section is to find out the HD path used by Electrum:
# First we generate a new mnemonic phrase and some addresses (change and receive), using Electrum.
# Then we check their derivation.

mnemonic = 'clay abstract easily position index taxi arrange ecology hobby digital turtle feel'
xpub = 'xpub661MyMwAqRbcFMYjmw8C6dJV97a4oLss6hb3v9wTQn2X48msQB61RCaLGtNhzgPCWPaJu7SvuB9EBSFCL43kTaFJC3owdaMka85uS154cEh'
passphrase = ''

seed = from_mnemonic_to_seed_eletrcum(mnemonic, passphrase)
seed = int(seed, 16)
seed_bytes = 64
xprv = bip32_master_key(seed, seed_bytes)

assert xpub == bip32_xprvtoxpub(xprv)

receive0 = '1FcfDbWwGs1PmyhMVpCAhoTfMnmSuptH6g'
index_child = [0, 0]
assert path(xprv, index_child) == receive0

receive1 = '1K5GjYkZnPFvMDTGaQHTrVnd8wjmrtfR5x'
index_child = [0, 1]
assert path(xprv, index_child) == receive1

receive2 = '1PQYX2uN7NYFd7Hq22ECMzfDcKhtrHmkfi'
index_child = [0, 2]
assert path(xprv, index_child) == receive2

change0 = '1BvSYpojWoWUeaMLnzbkK55v42DbizCoyq'
index_child = [1, 0]
assert path(xprv, index_child) == change0

change1 = '1NXB59hF4QzYpFrB7o6usLBjbk2D3ZqxAL'
index_child = [1, 1]
assert path(xprv, index_child) == change1

change2 = '16NLYkKtvYhW1Jp86tbocku3gxWcvitY1w'
index_child = [1, 2]
assert path(xprv, index_child) == change2

#### Bitcoin-core path derivation ####
# The scope of this section is to find out the HD path used by Bitcoin-core:
# First we generate a new xprv and some addresses, using Bitcoin-core.
# Then we check their derivation.


xprv = 'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'
add1 = '1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5' # hdkeypath=m/0'/0'/463'
add2 = '11x2mn59Qy43DjisZWQGRResjyQmgthki' # hdkeypath=m/0'/0'/267'

index_child = [0x80000000, 0x80000000, 0x80000000 + 463]
assert path(xprv, index_child) == add1

index_child = [0x80000000, 0x80000000, 0x80000000 + 267]
assert path(xprv, index_child) == add2

#### Bitcoin-core testnet path derivation ####
# The scope of this section is to find out the HD path used by Bitcoin-core:
# First we generate a new xprv and some testnet addresses, using Bitcoin-core.
# Then we check their derivation.

tprv = 'tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK'
add1 = 'mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj' # hdkeypath=m/0'/0'/51'
add2 = 'mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb' # hdkeypath=m/0'/1'/150'

version = 0x6f.to_bytes(1, 'big')

index_child = [0x80000000, 0x80000000, 0x80000000 + 51]
assert path(tprv, index_child, version) == add1

index_child = [0x80000000, 0x80000000 + 1, 0x80000000 + 150]
assert path(tprv, index_child, version) == add2













