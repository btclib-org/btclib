from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
from mnemonic import mnemonic_dict


MNEMONIC_VERSIONS = {'standard' : '01',
                     'segwit'   : '100',
                     '2fa'      : '101'}

# https://github.com/spesmilo/electrum/blob/master/lib/mnemonic.py
def electrum_mnemonic_from_raw_entropy(raw_entropy, words, version, lang = "en"):
  if type(raw_entropy) == str:
      raw_entropy = bytes.fromhex(raw_entropy)

  if type(raw_entropy) == bytes:
      raw_entropy = int.from_bytes(raw_entropy, 'big')
  elif type(raw_entropy) != int:
      raise ValueError("entropy must be bytes, hexstring, or int")

  required_bits = words*11

  assert version in MNEMONIC_VERSIONS, "unknown electrum mnemonic version"
  prefix = MNEMONIC_VERSIONS[version]
  invalid = True
  while invalid:
    entropy = bin(raw_entropy)[2:]
    entropy = entropy.zfill(required_bits*11)
    entropy = entropy[-required_bits:]
    indexes = mnemonic_dict.indexes_from_entropy(entropy)
    mnemonic = mnemonic_dict.mnemonic_from_indexes(indexes, lang)
    # validity check
    s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
    if s.startswith(prefix): invalid = False
    raw_entropy += 1
  
  return mnemonic


def electrum_seed_from_mnemonic(mnemonic, passphrase):
  prefix = 'electrum'
  return PBKDF2(mnemonic, prefix + passphrase, 2048, sha512).read(64) # 512 bits


def electrum_master_prvkey_from_mnemonic(mnemonic, passphrase):
  seed = electrum_seed_from_mnemonic(mnemonic, passphrase)

  s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
  if s.startswith(MNEMONIC_VERSIONS['standard']):
    mprv = bip32_master_prvkey_from_seed(seed)
  elif s.startswith(MNEMONIC_VERSIONS['segwit']):
    mprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    mprv = bip32_ckd(mprv, 0x80000000)
  else:
    raise ValueError("unmanaged electrum mnemonic version")
  return mprv


def electrum_master_prvkey_from_raw_entropy(raw_entropy, words, version, passphrase, lang = "en"):
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, words, version, lang)
  return electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)


def test_electrum_wallet():
  words = 12
  bits = words*11
  print("\nFor a", words, "words target:", bits, 'bits of entropy are needed. i.e.', bits//4, 'hexadecimal digits')

  raw_entropy = "f012003974d093eda670121023cd03bb"
  print(raw_entropy)

  version = 'standard'
  lang = "en"
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, words, version, lang)
  print('mnemonic:', mnemonic)

  passphrase = ''
  mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
  print('mprv:', mprv)


def electrum_test_vectors():
  test_vectors = [
    [
        "standard",
        "term gain fish all ivory talent gold either trap today balance kingdom",
        "",
        "xpub661MyMwAqRbcGJg6qHFEYXMkbKuREsjWXQJetGTYQuz8GLBPfUtKs53bAW1MP4JPUSEKK6m9dVzJhDbw5xf3NPbH7PHwXrkPY89cVLLTAk8"
    ],
    [
        "standard",
        "guard chat liar swallow zebra retire practice expand hood spider alert evolve",
        "",
        "xpub661MyMwAqRbcGi3axFUKX8iu4QFqP37XpXnXJPqY37wqyBaX64mERS3cXkoM8PRECUNUPP6foH9HdxHGriV2fFyPmDvjZ9eg2HTiPdM49rs"
    ],
    [
        "standard",
        "kind hazard heavy super novel book horn price bone misery moon depend",
        "danielefornaro",
        "xpub661MyMwAqRbcFv1yFk3WaqMFpHUKNvn1qGDyJhdp7yL18V9pwibKWVUebSCzwPSMEioVWKzcyktvyMaYN3Lips4zyu5idw7keWi7pmZSfwq"
    ],
    [
        "segwit",
        "glad shoulder possible elder route remind suit unable hedgehog pistol era define",
        "",
        "zpub6nnNomZvczQDUvRZh1xThQTcSaV54NJiQBhvswqC5jG32fWm2LnURBDSM1Argj2B2fR6xAKEAMj1PuZ2wEZzjGZcbAPhbGa2RtDoMKaTE7L"
    ],
    [
        "segwit",
        "slogan detect embark famous flip middle impact normal price artwork program power",
        "danielefornaro",
        "zpub6nC6GjnipUB41rp3yS2TozLkyoHiR4jCHJiZ69GhsJRNEeXJR63fV5sCoHTkhc999fevr5S78b6XPydetbe5w2b5HHpUoWCLHCfe55VknvX"
    ],
    [
        "segwit",
        "miss mixed vibrant cheap riot comfort pulse forum pet injury slogan fame",
        "fatti non foste a viver come bruti",
        "zpub6nfRLg2gunSr2LyRpGxzW5pdrvtHxLS5JzNtGWdef5M7wKs3m4CiyzPDe3zXGFLqABKK1gA41mXgKq3jyfgcH4nsCzWfBVsPSpJvFEDCUzT"
    ]
  ]
  for test_vector in test_vectors:
    mnemonic = test_vector[1]
    passphrase = test_vector[2]
    mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
    mpub = bip32_xpub_from_xprv(mprv)
    assert mpub.decode() == test_vector[3]

 
if __name__ == "__main__":
  electrum_test_vectors()
  test_electrum_wallet()
