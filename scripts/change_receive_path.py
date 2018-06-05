# -*- coding: utf-8 -*-
"""
Created on Mon Nov 20 12:26:47 2017

@author: dfornaro, fametrano
"""

# This script is used to test the HD bip32_derive used by some Bitcoin Wallets.

from bip39_functions import bip39_seed_from_mnemonic
from bip32_functions import bip32_master_prvkey_from_seed, bip32_xpub_from_xprv, bip32_derive, address_from_xpub

#### Electrum bip32_derive derivation (bip39) ####
# Electrum gives also the possibility to restore a BIP39 wallet.
# After changed the version of the addresses, we take from Electrum a mnemonic phrase and 2 addresses (change and receive).
# Our goal is to find the bip32_derive needed to derive the addreeses from the mnemonic phrase:
mnemonic = b'army van defense carry jealous true garbage claim echo media make crunch'
passphrase = ''
seed = bip39_seed_from_mnemonic(mnemonic, passphrase)
print(seed.hex())
xprv = bip32_master_prvkey_from_seed(seed)
print(xprv)

version = 0x46.to_bytes(1, 'big')

receive = b'VTpEhLjvGYE16pLcNrMY53gQB9bbhn581W'
index_child = [0x80000000, 0, 0]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)), version)
assert addr == receive

change = b'VRtaZvAe4s29aB3vuXyq7GYEpahsQet2B1'
index_child = [0x80000000, 1, 0]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)), version)
assert addr == change

#### Bitcoin-core bip32_derive derivation ####
# The scope of this section is to find out the HD bip32_derive used by Bitcoin-core:
# First we generate a new xprv and some addresses, using Bitcoin-core.
# Then we check their derivation.
xprv = b'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'

addr1 = b'1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5' # hdkeybip32_derive=m/0'/0'/463'
index_child = [0x80000000, 0x80000000, 0x80000000 + 463]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == addr1

addr2 = b'11x2mn59Qy43DjisZWQGRResjyQmgthki' # hdkeybip32_derive=m/0'/0'/267'
index_child = [0x80000000, 0x80000000, 0x80000000 + 267]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == addr2

#### Bitcoin-core testnet bip32_derive derivation ####
# The scope of this section is to find out the HD bip32_derive used by Bitcoin-core:
# First we generate a new xprv and some testnet addresses, using Bitcoin-core.
# Then we check their derivation.
tprv = b'tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK'

version = 0x6f.to_bytes(1, 'big')

addr1 = b'mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj' # hdkeybip32_derive=m/0'/0'/51'
index_child = [0x80000000, 0x80000000, 0x80000000 + 51]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(tprv, index_child)))
assert addr == addr1

addr2 = b'mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb' # hdkeybip32_derive=m/0'/1'/150'
index_child = [0x80000000, 0x80000000 + 1, 0x80000000 + 150]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(tprv, index_child)))
assert addr == addr2

#### Electrum standard bip32_derive derivation ####
# The scope of this section is to find out the HD bip32_derive used by Electrum:
# First we generate a new mnemonic phrase and some addresses (change and receive), using Electrum.
# Then we check their derivation.
mnemonic = b'clay abstract easily position index taxi arrange ecology hobby digital turtle feel'
passphrase = ''

seed = bip39_seed_from_mnemonic(mnemonic, passphrase, 'electrum')
xprv = bip32_master_prvkey_from_seed(seed)

xpub = b'xpub661MyMwAqRbcFMYjmw8C6dJV97a4oLss6hb3v9wTQn2X48msQB61RCaLGtNhzgPCWPaJu7SvuB9EBSFCL43kTaFJC3owdaMka85uS154cEh'
assert xpub == bip32_xpub_from_xprv(xprv)

receive0 = b'1FcfDbWwGs1PmyhMVpCAhoTfMnmSuptH6g'
index_child = [0, 0]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == receive0

receive1 = b'1K5GjYkZnPFvMDTGaQHTrVnd8wjmrtfR5x'
index_child = [0, 1]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == receive1

receive2 = b'1PQYX2uN7NYFd7Hq22ECMzfDcKhtrHmkfi'
index_child = [0, 2]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == receive2

change0 = b'1BvSYpojWoWUeaMLnzbkK55v42DbizCoyq'
index_child = [1, 0]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == change0

change1 = b'1NXB59hF4QzYpFrB7o6usLBjbk2D3ZqxAL'
index_child = [1, 1]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == change1

change2 = b'16NLYkKtvYhW1Jp86tbocku3gxWcvitY1w'
index_child = [1, 2]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)))
assert addr == change2

#### Bitcoin-core bip32_derive derivation ####
# Bitcoin core doesn't implement BIP39 up to now.
# It starts directly from the master private key.
# After changed the version of the addresses, we consider the master key and 2 addresses (change and receive).
# Our goal is to find the bip32_derive needed to derive the addreeses from the master private key:
xprv = b'xprv9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'

version = 0x46.to_bytes(1, 'big')

receive = b'VUqyLGVdUADWEqDqL2DeUBAcbPQwZfWDDY' # "hdkeybip32_derive": "m/0'/0'/5'"
index_child = [0x80000000, 0x80000000, 0x80000005]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)), version)
assert addr == receive

change = b'VMg6DpX7SQUsoECdpXJ8Bv6R7p11PfwHwy' # "hdkeybip32_derive": "m/0'/1'/1'"
index_child = [0x80000000, 0x80000001, 0x80000001]
addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, index_child)), version)
assert addr == change
