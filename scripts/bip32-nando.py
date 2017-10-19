
from secp256k1 import order, G, pointMultiply
from hmac import HMAC
from hashlib import sha512
from base58 import b58encode_check

seed = 0x000102030405060708090a0b0c0d0e0f
print("Seed:", hex(seed))

## master keys and chain code
hmacValue = HMAC(key=b"Bitcoin seed", msg=seed.to_bytes(16, byteorder='big'), digestmod=sha512).hexdigest()
mp = int(hmacValue[:64], 16)
MP = pointMultiply(mp, G)
chain_code = int(hmacValue[64:], 16)

# depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ...
depth = 0x00
# fingerprint of the parent's key (0x00000000 if master key)
fingerprint  = 0x00000000
# chid number: ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
child_number = 0x00000000
level = depth.to_bytes(1, byteorder='big') + \
        fingerprint.to_bytes(4, byteorder='big') + \
        child_number.to_bytes(4, byteorder='big') + \
        chain_code.to_bytes(32, byteorder='big')

# version bytes
# mainnet: 0x0488B21E -> xpub; 0x0488ADE4 xprv
# testnet: 0x043587CF -> tpub; 0x04358394 tprv
version = 0x0488ADE4 #xprv
ext_prv_bytes = version.to_bytes(4, byteorder='big') + level + b'\x00' + mp.to_bytes(32, byteorder='big')
ext_prv = b58encode_check(ext_prv_bytes)

version = 0x0488B21E #xpub
ext_pub_bytes = version.to_bytes(4, byteorder='big') + level + (b'\x02' if (MP[1] % 2 == 0) else b'\x03') + MP[0].to_bytes(32, byteorder='big')
ext_pub = b58encode_check(ext_pub_bytes)

print('\nm')
print('ext prv:', ext_prv)
assert ext_prv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "failure"
print('ext pub:', ext_pub)
assert ext_pub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "failure"


## first child keys and chain-code

print ('\nm/0\'')


