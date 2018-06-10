from hashlib import sha512
from pbkdf2 import PBKDF2
import hmac
from bip32_functions import bip32_master_prvkey_from_seed, bip32_ckd, bip32_xpub_from_xprv
from mnemonic import mnemonic_dict
import math

MNEMONIC_VERSIONS = {'standard' : '01',
                     'segwit'   : '100',
                     '2fa'      : '101'}

# entropy can be expresses as binary string, bytes-like, or int
def electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang):
    # electrum consider entropy as integer, losing any leading zero
    # https://github.com/spesmilo/electrum/blob/master/lib/mnemonic.py

    if type(raw_entropy) == str:
        raw_entropy = int(raw_entropy, 2)
    elif type(raw_entropy) == bytes:
        raw_entropy = int.from_bytes(raw_entropy, 'big')
    elif type(raw_entropy) != int:
        raise ValueError("entropy must be bytes, hexstring, or int")

    assert version in MNEMONIC_VERSIONS, "unknown electrum mnemonic version"
    invalid = True
    while invalid:
        indexes = mnemonic_dict.indexes_from_entropy(raw_entropy, lang)
        mnemonic = mnemonic_dict.mnemonic_from_indexes(indexes, lang)
        # version validity check
        s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
        if s.startswith(MNEMONIC_VERSIONS[version]): invalid = False
        # next trial
        raw_entropy += 1
    
    return mnemonic

# entropy is returned as binary string
def electrum_entropy_from_mnemonic(mnemonic, lang):
    indexes = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
    entropy = mnemonic_dict.entropy_from_indexes(indexes, lang)
    return entropy


def electrum_seed_from_mnemonic(mnemonic, passphrase):
  seed = PBKDF2(mnemonic, 'electrum' + passphrase,
                2048, sha512).read(64) # 512 bits
  return seed


def electrum_master_prvkey_from_mnemonic(mnemonic, passphrase):
  seed = electrum_seed_from_mnemonic(mnemonic, passphrase)

  # verify that the mnemonic is versioned
  s = hmac.new(b"Seed version", mnemonic.encode('utf8'), sha512).hexdigest()
  if s.startswith(MNEMONIC_VERSIONS['standard']):
    return bip32_master_prvkey_from_seed(seed)
  elif s.startswith(MNEMONIC_VERSIONS['segwit']):
    # fixme parametrizazion of the prefix is needed
    mprv = bip32_master_prvkey_from_seed(seed, b'\x04\xb2\x43\x0c')
    # why this hardned derivation?
    return bip32_ckd(mprv, 0x80000000)
  else:
    raise ValueError("unmanaged electrum mnemonic version")


def electrum_master_prvkey_from_raw_entropy(raw_entropy, words, version, passphrase, lang):
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang)
  mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
  return mprv


def test_electrum_wallet():
  lang = "en"
  bpw = mnemonic_dict.bits_per_word(lang)
  words = 12
  bits = words*bpw
  print("\nFor a", words, "words target", bits,
        "bits of entropy are needed, i.e.", bits//8, "bytes")

  raw_entropy = int("110aaaa03974d093eda670121023cd0772", 16)
  hex_raw_entropy = hex(raw_entropy)
  print(int(len(hex_raw_entropy)/2), "bytes raw entropy:", hex_raw_entropy)

  version = 'standard'
  mnemonic = electrum_mnemonic_from_raw_entropy(raw_entropy, version, lang)
  print('mnemonic:', mnemonic)

  passphrase = ''
  mprv = electrum_master_prvkey_from_mnemonic(mnemonic, passphrase)
  print('mprv:', mprv)

  entropy = int(electrum_entropy_from_mnemonic(mnemonic, lang), 2)
  hex_entropy = hex(entropy)
  print(int(len(hex_entropy)/2), "bytes     entropy:", hex_entropy)

  # relevant entropy part
  hex_raw_entropy = bin(int(hex_raw_entropy, 16))[2:].zfill(bits)[-bits:]
  hex_entropy     = bin(int(    hex_entropy, 16))[2:].zfill(bits)[-bits:]
  #print(hex_raw_entropy)
  #print(hex_entropy)


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
    test_mnemonic = test_vector[1]
    passphrase = test_vector[2]
    test_mpub = test_vector[3]
    mprv = electrum_master_prvkey_from_mnemonic(test_mnemonic, passphrase)
    mpub = bip32_xpub_from_xprv(mprv).decode()
    if mpub != test_mpub:
        raise ValueError("\n" + mpub + "\n" + test_vector[3])
    
    lang = "en"
    entropy = int(electrum_entropy_from_mnemonic(test_mnemonic, lang), 2)
    version = test_vector[0]
    mnemonic = electrum_mnemonic_from_raw_entropy(entropy, version, lang)
    if mnemonic != test_mnemonic:
        raise ValueError("\n" + mnemonic + "\n" + test_mnemonic)

 
if __name__ == "__main__":
  electrum_test_vectors()
  test_electrum_wallet()
