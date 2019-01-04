#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from hmac import HMAC
from hashlib import sha512

from btclib.ec import pointMult
from btclib.ecurves import secp256k1 as ec
from btclib.ecutils import point2octets
from btclib.base58 import b58encode_check
from btclib.wifaddress import h160

## https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

# version bytes
# mainnet: 0x0488B21E public  -> xpub; 0x0488ADE4 private -> xprv
# testnet: 0x043587CF public         ; 0x04358394 private
xprvn= 0x0488ADE4
xprv = xprvn.to_bytes(4, 'big')
xpubn= 0x0488B21E
xpub = xpubn.to_bytes(4, 'big')

seed = 0x000102030405060708090a0b0c0d0e0f
seed_bytes = 16
print("Seed:", hex(seed), "\nbytes:", seed_bytes)

# ==master ext private key==
# depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ...
depth = b'\x00'
# This is ser32(i) for i in xi = xpar/i, with xi the key being serialized. (0x00000000 if master key)
child_number = b'\x00\x00\x00\x00'
# the fingerprint of the parent's public key (0x00000000 if master key)
fingerprint  = b'\x00\x00\x00\x00'
idf = depth + fingerprint + child_number

# master private key, master public key, chain code
hd = HMAC(b"Bitcoin seed", seed.to_bytes(seed_bytes, byteorder='big'), sha512).digest()
qbytes = hd[:32]
q = int(qbytes.hex(), 16) % ec.n
qbytes = b'\x00' + q.to_bytes(32, byteorder='big')
Q = pointMult(ec, q, ec.G)
Qbytes = point2octets(ec, Q, True)
chain_code = hd[32:]

#extended keys
ext_prv = b58encode_check(xprv + idf + chain_code + qbytes)
print("\nm")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + Qbytes)
print("M")
print(ext_pub)
assert ext_prv == b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi", "failure"
assert ext_pub == b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8", "failure"

# ==first (0) hardened child==
depth = b'\x01'
child_n = 0 + 0x80000000 #hardened
child_number = child_n.to_bytes(4, byteorder='big')
fingerprint = h160(Qbytes)[:4]
idf = depth + fingerprint + child_number

key = qbytes if child_number[0]>127 else Qbytes
hd = HMAC(chain_code, key + child_number, sha512).digest()
q = (q + int(hd[:32].hex(), 16)) % ec.n
qbytes = b'\x00' + q.to_bytes(32, byteorder='big')
Q = pointMult(ec, q, ec.G)
Qbytes = point2octets(ec, Q, True)
chain_code = hd[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + qbytes)
print("\nm/0'")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + Qbytes)
print("M/0'")
print(ext_pub)
assert ext_prv == b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7", "failure"
assert ext_pub == b"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw", "failure"

# ==second (1) normal grandchild==
depth = b'\x02'
child_n = 1 + 0x00000000 #normal
child_number = child_n.to_bytes(4, byteorder='big')
fingerprint = h160(Qbytes)[:4]
idf = depth + fingerprint + child_number

key = qbytes if child_number[0]>127 else Qbytes
hd = HMAC(chain_code, key + child_number, sha512).digest()
q = (q + int(hd[:32].hex(), 16)) % ec.n
qbytes = b'\x00' + q.to_bytes(32, byteorder='big')
Q = pointMult(ec, q, ec.G)
Qbytes = point2octets(ec, Q, True)
chain_code = hd[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + qbytes)
print("\nm/0'/1")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + Qbytes)
print("M/0'/1")
print(ext_pub)
assert ext_prv == b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs", "failure"
assert ext_pub == b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ", "failure"

# ==third (2) hardened grand-grandchild==
depth = b'\x03'
child_n = 2 + 0x80000000 #hardened
child_number = child_n.to_bytes(4, byteorder='big')
fingerprint = h160(Qbytes)[:4]
idf = depth + fingerprint + child_number

key = qbytes if child_number[0]>127 else Qbytes
hd = HMAC(chain_code, key + child_number, sha512).digest()
q = (q + int(hd[:32].hex(), 16)) % ec.n
qbytes = b'\x00' + q.to_bytes(32, byteorder='big')
Q = pointMult(ec, q, ec.G)
Qbytes = point2octets(ec, Q, True)
chain_code = hd[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + qbytes)
print("\nm/0'/1/2'")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + Qbytes)
print("M/0'/1/2'")
print(ext_pub)
assert ext_prv == b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM", "failure"
assert ext_pub == b"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5", "failure"

# ==third (2) normal grand-grand-grandchild==
depth = b'\x04'
child_n = 2 + 0x00000000 #normal
child_number = child_n.to_bytes(4, byteorder='big')
fingerprint = h160(Qbytes)[:4]
idf = depth + fingerprint + child_number

key = qbytes if child_number[0]>127 else Qbytes
hd = HMAC(chain_code, key + child_number, sha512).digest()
q = (q + int(hd[:32].hex(), 16)) % ec.n
qbytes = b'\x00' + q.to_bytes(32, byteorder='big')
Q = pointMult(ec, q, ec.G)
Qbytes = point2octets(ec, Q, True)
chain_code = hd[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + qbytes)
print("\nm/0'/1/2'/2")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + Qbytes)
print("M/0'/1/2'/2")
print(ext_pub)
assert ext_prv == b"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334", "failure"
assert ext_pub == b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV", "failure"

# ==1000000001th (1000000000) normal grand-grand-grand-grandchild==
depth = b'\x05'
child_n = 1000000000 + 0x00000000 #normal
child_number = child_n.to_bytes(4, byteorder='big')
fingerprint = h160(Qbytes)[:4]
idf = depth + fingerprint + child_number

key = qbytes if child_number[0]>127 else Qbytes
hd = HMAC(chain_code, key + child_number, sha512).digest()
q = (q + int(hd[:32].hex(), 16)) % ec.n
qbytes = b'\x00' + q.to_bytes(32, byteorder='big')
Q = pointMult(ec, q, ec.G)
Qbytes = point2octets(ec, Q, True)
chain_code = hd[32:]

ext_prv = b58encode_check(xprv + idf + chain_code + qbytes)
print("\nm/0'/1/2'/2/1000000000")
print(ext_prv)
ext_pub = b58encode_check(xpub + idf + chain_code + Qbytes)
print("M/0'/1/2'/2/1000000000")
print(ext_pub)
assert ext_prv == b"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76", "failure"
assert ext_pub == b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy", "failure"
