from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
from bip39_functions import bip39_seed_from_mnemonic, bip39_mnemonic_from_word_indexes

# source ?
def electrum_mnemonic_from_entropy(entropy_int, words, version, dict_txt = 'dict_eng.txt'):
  valid = False
  required_bits = words*11
  while not valid:
    entropy_bin = bin(entropy_int)[2:]
    entropy_bin = entropy_bin.zfill(required_bits*11)
    entropy = entropy_bin[-required_bits:]

    indexes = [0] * words
    for i in range(0, words):
      indexes[i] = int(entropy[i*11:(i+1)*11], 2)

    mnemonic = bip39_mnemonic_from_word_indexes(indexes, dict_txt)

    s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
    if s[0:2] == '01'  and version == "standard" or \
       s[0:3] == '100' and version == "segwit"   or \
       s[0:3] == '101' and version == "2FA":
       valid = True

    entropy_int += 1
  
  return mnemonic


def electrum_master_prvkey_from_mnemonic(mnemonic, passphrase):
  seed = bip39_seed_from_mnemonic(mnemonic, passphrase, "electrum")

  s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
  if s[0:2] == '01':    # standard
    mprv = bip32_master_prvkey_from_seed(seed)
  elif s[0:3] == '100': # segwit
    mprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    mprv = bip32_ckd(mprv, 0x80000000)
  else:
    raise ValueError("unknown " + s[0:3] + " version")
  return mprv


def electrum_master_prvkey_from_entropy(entropy_int, words, version, passphrase, dict_txt = 'dict_eng.txt'):
  mnemonic = electrum_mnemonic_from_entropy(entropy_int, words, version, dict_txt)
  return electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)

def test_electrum_wallet():

  # number of words chosen by the user:
  words = 12
  bits = words*11
  print("\nFor a", words, "words target:", bits, 'bits of entropy are needed. i.e.', bits//4, 'hexadecimal digits')

  # entropy is entered by the user
  entropy = 0xf012003974d093eda670121023cd03bb

  # dictionary chosen by the user:
  dict_txt = 'dict_ita.txt'
  dict_txt = 'dict_eng.txt'

  # version chosen by the user:
  version = 'standard'

  mnemonic = electrum_mnemonic_from_entropy(entropy, words, version, dict_txt)
  print('mnemonic:', mnemonic)

  # passphrase chosen by the user:
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
