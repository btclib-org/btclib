#!/usr/bin/python3
'''wifs and addresses

Implementation of Base58 encoding of private keys (wifs)
and public keys (addresses)
'''

from ECsecp256k1 import ec
from base58 import b58encode_check, b58decode_check
from hashlib import sha256, new as hnew


def scrub_privkey(p):
  """Return private key as 32 bytes"""
  
  if isinstance(p, str):
    p = int(p, 16)

  if isinstance(p, int):
    assert 0 < p           , "Invalid Private Key"
    assert     p < ec.order, "Invalid Private Key"
    return p.to_bytes(32, byteorder='big')

  if not isinstance(p, bytes):
    raise TypeError(
      "a bytes-like object is required (also str or int), not '%s'" %
       type(p).__name__)

  assert len(p) == 32, "wrong lenght"
  assert int.from_bytes(p, 'big') < ec.order
  return p


def wif_from_privkey(p, compressed=True):
  """private key to Wallet Import Format"""

  payload = b'\x80' + scrub_privkey(p)
  if compressed: payload += b'\x01'
  return b58encode_check(payload)


def privkey_from_wif(wif):
  """Wallet Import Format to private key"""

  payload = b58decode_check(wif)
  assert payload[0] == 0x80, "not a wif"

  if len(payload) == 34: # compressed
    assert payload[33] == 0x01, "not a wif"
    return scrub_privkey(payload[1:-1]), True
  else:                  # uncompressed
    assert len(payload) == 33, "not a wif"
    return scrub_privkey(payload[1:]), False


def pubkey_from_privkey(privkey, compressed = True):
  P = ec.pointMultiply(privkey)
  return ec.bytes_from_point(P, compressed)
  

def h160(pubkey):
  pubkey = ec.bytes_from_point(pubkey)
  t = sha256(pubkey).digest()
  return hnew('ripemd160', t).digest()


def address_from_pubkey(pubkey, version=b'\x00'):
    vh160 = version + h160(pubkey)
    return b58encode_check(vh160)


def hash160_from_address(addr):
    payload = b58decode_check(addr)
    assert len(payload) == 21
    assert payload[0] == 0x00, "not an address"
    return payload[1:]


################# tests

def test_wif():
  p_num = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
  p_bytes = scrub_privkey(p_num)
  p_hex = "C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"

  # private key as number
  wif = wif_from_privkey(p_num)
  assert wif == b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', "failure"
  p2 = privkey_from_wif(wif)
  assert p2[0] == p_bytes
  assert p2[1] == True
  wif = wif_from_privkey(p_num, False)
  assert wif == b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ', "failure"
  p3 = privkey_from_wif(wif)
  assert p3[0] == p_bytes
  assert p3[1] == False

  # private key as bytes, i.e. the preferred format
  wif = wif_from_privkey(p_bytes)
  assert wif == b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', "failure"
  p4 = privkey_from_wif(wif)
  assert p4[0] == p_bytes
  assert p4[1] == True
  wif = wif_from_privkey(p_bytes, False)
  assert wif == b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ', "failure"
  p5 = privkey_from_wif(wif)
  assert p5[0] == p_bytes
  assert p5[1] == False

  # private key as hex string
  wif = wif_from_privkey(p_hex)
  assert wif == b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617', "failure"
  p6 = privkey_from_wif(wif)
  assert p6[0] == p_bytes
  assert p6[1] == True
  wif = wif_from_privkey(p_hex, False)
  assert wif == b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ', "failure"
  p7 = privkey_from_wif(wif)
  assert p7[0] == p_bytes
  assert p7[1] == False

def test_address_from_pubkey():
  # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
  p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
  p = p % ec.order
  a = address_from_pubkey(pubkey_from_privkey(p, False))
  assert a == b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
  hash160_from_address(a)
  a = address_from_pubkey(pubkey_from_privkey(p, True))
  assert a == b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs'
  hash160_from_address(a)
  
def test_address_from_wif():
  wif1 = "5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
  a = address_from_pubkey(pubkey_from_privkey(*privkey_from_wif(wif1)))
  assert a == b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig'
  
  wif2 = "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162"
  a = address_from_pubkey(pubkey_from_privkey(*privkey_from_wif(wif2)))
  assert a == b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB'

  assert privkey_from_wif(wif1)[0] == privkey_from_wif(wif2)[0]
  
def main():
  test_wif()
  test_address_from_pubkey()
  test_address_from_wif()

if __name__ == "__main__":
  # execute only if run as a script
  main()
