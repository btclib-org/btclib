#! python3

from secp256k1 import G, order, pointMultiply
import hashlib
from base58 import b58encode, b58encode_check

# to be fixed for other version value
def private_key_to_public_key(private_key, version=0x04):
  p = pointMultiply(private_key)
  public_key = version+p[0]+p[1]
  return public_key

# https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
# 0 < k < order
assert 0 < p        , "Invalid Private Key"
assert     p < order, "Invalid Private Key"

print("\n*** [0] Private ECDSA Key:")
print(hex(p))

P = pointMultiply(p, G)
PubKey = b'\x04' + P[0].to_bytes(32, byteorder='big') + P[1].to_bytes(32, byteorder='big')
print("\n*** [1] Public Key (uncompressed):")
print(PubKey.hex())

print("\n*** [2] SHA-256 hashing of the public key:")
h1 = hashlib.sha256(PubKey).digest()
print(h1.hex())

print("\n*** [3] RIPEMD-160 hashing on the result of SHA-256:")
h2 = hashlib.new('ripemd160', h1).digest()
print(h2.hex())

version_byte = "\x00" #for mainnet
print("\n*** [4] version byte added in front of RIPEMD-160 hash:")
vh160 = b'\x00' + h2
print(vh160.hex())

print("\n*** [5] SHA-256 hashing of the extended RIPEMD-160 result:")
h3 = hashlib.sha256(vh160).digest()
print(h3.hex())

print("\n*** [6] SHA-256 hashing of the result of the previous SHA-256 hash:")
h4 = hashlib.sha256(h3).digest()
print(h4.hex())

print("\n*** [7] First 4 bytes of the second SHA-256 hash used as address checksum:")
print(h4[:4].hex())

print("\n*** [8] checksum added at the end of extended RIPEMD-160 hash:")
addr = vh160 + h4[:4]
print(addr.hex())

print("\n*** [9] Base58 encoded address from uncompressed PubKey")
base58EncodedAddress = b58encode(addr)
assert (base58EncodedAddress == '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
print(base58EncodedAddress)

print("\n*** steps [5]-[9] are also known as Base58Check encode")

def bc_address_to_hash_160(addr):
  bytes = b58decode(addr, 25)
  return bytes[1:21]

def h160(inp):
  h1 = hashlib.sha256(inp).digest()
  return hashlib.new('ripemd160', h1).digest()

def public_key_to_bc_address(inp, version=b'\x00'):
  vh160 = version + h160(inp)
  return b58encode_check(vh160)

print("\n*** [1] Public Key compressed:")
prefix = b'\x02' if (P[1] % 2 == 0) else b'\x03'
PubKey = prefix + P[0].to_bytes(32, byteorder='big')
print(PubKey.hex())

print("\n*** [9] base58 encoded address from compressed PubKey")
base58EncodedAddress = public_key_to_bc_address(PubKey)
assert (base58EncodedAddress == '1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
print(base58EncodedAddress)
