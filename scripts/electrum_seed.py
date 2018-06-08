from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
from mnemonic import mnemonic_dict
import math

MNEMONIC_VERSIONS = {'standard' : '01',
                     'segwit'   : '100',
                     '2fa'      : '101'}

# raw entropy can be expresse in bytes, hex string or int
# entropy is expressed as binary string
# https://github.com/spesmilo/electrum/blob/master/lib/mnemonic.py
def electrum_mnemonic_from_raw_entropy(raw_entropy, words, version, lang):
  if type(raw_entropy) == str:
      raw_entropy = bytes.fromhex(raw_entropy)

  if type(raw_entropy) == bytes:
      raw_entropy = int.from_bytes(raw_entropy, 'big')
  elif type(raw_entropy) != int:
      raise ValueError("entropy must be bytes, hexstring, or int")

  bpw = 11 # fixme should/might be deduced from the dictionary
  required_bits = words*bpw

  assert version in MNEMONIC_VERSIONS, "unknown electrum mnemonic version"
  invalid = True
  while invalid:
    entropy = bin(raw_entropy)[2:]
    entropy = entropy.zfill(required_bits) # pad if shorter
    entropy = entropy[-required_bits:]     # cut if longer
    indexes = mnemonic_dict.indexes_from_entropy(entropy, lang)
    mnemonic = mnemonic_dict.mnemonic_from_indexes(indexes, lang)
    # version validity check
    s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
    if s.startswith(MNEMONIC_VERSIONS[version]): invalid = False
    # next trial
    raw_entropy += 1
  
  return mnemonic


def electrum_entropy_from_mnemonic(mnemonic, lang):
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)
    # entropy bit size
    entropy_bits = len(entropy)
    # return an hexstring
    entropy_bytes = math.ceil(entropy_bits/8)
    entropy_hexdigits = 2 * entropy_bytes
    entropy = int(entropy, 2)
    format_string = '0' + str(entropy_hexdigits) + 'x'
    entropy = format(entropy, format_string)
    return entropy


def electrum_seed_from_mnemonic(mnemonic, passphrase):
  return PBKDF2(mnemonic, 'electrum' + passphrase, 2048, sha512).read(64) # 512 bits


def electrum_master_prvkey_from_mnemonic(mnemonic, passphrase):
  seed = electrum_seed_from_mnemonic(mnemonic, passphrase)

  # verify that the mnemonic is versioned
  s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
  if s.startswith(MNEMONIC_VERSIONS['standard']):
    mprv = bip32_master_prvkey_from_seed(seed)
  elif s.startswith(MNEMONIC_VERSIONS['segwit']):
    # fixme parametrizazion of the prefix is needed
    mprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    mprv = bip32_ckd(mprv, 0x80000000)
  else:
    raise ValueError("unmanaged electrum mnemonic version")
  return mprv


def electrum_master_prvkey_from_raw_entropy(raw_entropy, words, version, passphrase, lang):
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, words, version, lang)
  return electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)


def test_electrum_wallet():
  words = 12
  bpw = 11
  bits = words*bpw
  print("\nFor a", words, "words target", bits, 'bits of entropy are needed, i.e.', bits//4, 'hexadecimal digits')

  raw_entropy = "110000003974d093eda670121023cd0772"
  print(int(len(raw_entropy)/2), "bytes raw entropy:", raw_entropy)

  version = 'standard'
  lang = "en"
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, words, version, lang)
  print('mnemonic:', mnemonic)

  passphrase = ''
  mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
  print('mprv:', mprv)

  entropy = electrum_entropy_from_mnemonic(mnemonic, lang)
  print(int(len(entropy)/2), "bytes     entropy:", entropy)

  # relevant entropy part
  raw_entropy = bin(int(raw_entropy, 16))[2:].zfill(bits)[-bits:]
  entropy     = bin(int(    entropy, 16))[2:].zfill(bits)[-bits:]
  #print(raw_entropy)
  #print(    entropy)
  #print(int(entropy, 2) - int(raw_entropy, 2))

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
    lang = "en"
    mnemonic = test_vector[1]
    passphrase = test_vector[2]
    mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
    mpub = bip32_xpub_from_xprv(mprv)
    assert mpub.decode() == test_vector[3]
    entropy = electrum_entropy_from_mnemonic(mnemonic, lang)
    words = len(mnemonic.split())
    assert mnemonic == electrum_mnemonic_from_raw_entropy(entropy, words, test_vector[0], lang)

 
if __name__ == "__main__":
  electrum_test_vectors()
  test_electrum_wallet()
