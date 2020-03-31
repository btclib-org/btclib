
from btclib import btcmsg, der, dsa

msg = b'\xfc1\xfe\xfb\xe7\xc6\x00\xd7\xbe"u\xe1d5V)\xa3J\x84\xfd0\xed`2\x91\xe2]\xf1\xa3Y\xda\x05'
assert msg.hex() == "fc31fefbe7c600d7be2275e164355629a34a84fd30ed603291e25df1a359da05"
magic_msg = btcmsg._magic_hash(msg)

privkey1 = "4325cdb483c8cd28059bf35f2f73a2f89b7b0f46a11e595e7e5064c453eac994"
pubkey1 = "04c61aee8a81b18dc79a9a4afd33ea7bea296e4132e74d79826ef34616cdd33ed4437e0e4fade942d12d71548c7f83decf1adfe3efcd52496fc0de79ae54e76c09"
signature1 = "3045022100e8937210fee0329a70edf25f29dcfec4cac8cda83f2ca5be9a4c58508c4f0099022001141f2d35465595b4f0cf0494d01ce18a5253b778a50e5134ae0c88d299d718"
dsa._verify(magic_msg, pubkey1, signature1)

print(signature1)
tuplesig1 = dsa.sign(magic_msg, privkey1)
dersig1 = dsa.serialize(*tuplesig1, None)
dsa._verify(magic_msg, pubkey1, dersig1)
print(dersig1.hex())

privkey2 = "e3b40d15b5790d50934f1e23acea62d81234617ebb7770148ae2e698b8f750e9"
pubkey2 = "04ae3d0d5c669ed364636e79e72abc012a33be63e537babddf56bfd393256acf6dba0fac21da6386513674573a2d7baff4375c9b6d2498383853c52f0565f97f1a"
signature2 = "3045022100ccf2400a86493bceb7af8d0a71fa085abb3b9760fe18b1c40bc362e828b82d08022026cb40f1988d404f67a3d2437979e970341ee32361cf87ecddfaab42fe5715f8"
dsa._verify(magic_msg, pubkey2, signature2)

print(signature2)
tuplesig2 = dsa.sign(magic_msg, privkey2)
dersig2 = dsa.serialize(*tuplesig1, None)
dsa._verify(magic_msg, pubkey2, dersig2)
print(dersig2.hex())
