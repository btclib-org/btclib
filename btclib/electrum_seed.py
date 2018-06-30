#!/usr/bin/env python3

"""electrum entropy / mnemonic / seed functions"""

from hashlib import sha512
import hmac
from btclib.pbkdf2 import PBKDF2
from btclib.mnemonic import mnemonic_dict, Entropy, GenericEntropy
from btclib.bip32 import PRIVATE, bip32_master_prvkey_from_seed, \
                         bip32_ckd, bip32_xpub_from_xprv

ELECTRUM_MNEMONIC_VERSIONS = {'standard' : '01',
                              'segwit'   : '100',
                              '2fa'      : '101'}

# entropy can be expresses as binary string, bytes-like, or int
def electrum_mnemonic_from_raw_entropy(raw_entropy: GenericEntropy, lang: str, eversion: str) -> str:
    # electrum consider entropy as integer, losing any leading zero
    # https://github.com/spesmilo/electrum/blob/master/lib/mnemonic.py

    if type(raw_entropy) == str:
        raw_entropy = int(raw_entropy, 2)
    elif type(raw_entropy) == bytes:
        raw_entropy = int.from_bytes(raw_entropy, 'big')
    elif type(raw_entropy) != int:
        raise ValueError("entropy must be bytes, hexstring, or int")

    assert eversion in ELECTRUM_MNEMONIC_VERSIONS, "unknown electrum mnemonic version"
    invalid = True
    while invalid:
        indexes = mnemonic_dict.indexes_from_entropy(raw_entropy, lang)
        mnemonic = mnemonic_dict.mnemonic_from_indexes(indexes, lang)
        # version validity check
        s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
        if s.startswith(ELECTRUM_MNEMONIC_VERSIONS[eversion]): invalid = False
        # next trial
        raw_entropy += 1
    
    return mnemonic

# entropy is returned as binary string
def electrum_entropy_from_mnemonic(mnemonic: str, lang: str) -> Entropy:
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)
    return entropy


def electrum_seed_from_mnemonic(mnemonic: str, passphrase: str) -> bytes:
  seed = PBKDF2(mnemonic, 'electrum' + passphrase,
                2048, sha512).read(64) # 512 bits
  return seed


def electrum_master_prvkey_from_mnemonic(mnemonic: str, passphrase: str, xversion: bytes) -> bytes:
  seed = electrum_seed_from_mnemonic(mnemonic, passphrase)

  # verify that the mnemonic is versioned
  s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
  if s.startswith(ELECTRUM_MNEMONIC_VERSIONS['standard']):
    # FIXME: mainnet / testnet?
    return bip32_master_prvkey_from_seed(seed, xversion)
  elif s.startswith(ELECTRUM_MNEMONIC_VERSIONS['segwit']):
    # FIXME: parametrizazion of the prefix is needed (mainnet/testnet?)
    mprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    # BIP32 default first account: m/0'
    return bip32_ckd(mprv, 0x80000000)
  else:
    raise ValueError("unmanaged electrum mnemonic version")


def electrum_master_prvkey_from_raw_entropy(raw_entropy: GenericEntropy, passphrase: str, lang: str, xversion: bytes) -> bytes:
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, lang, xversion)
  mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase, xversion)
  return mprv
