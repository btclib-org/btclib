import secrets
from hashlib import sha256

from btclib import base58wif, bip32, bip39, btcmsg, der, slip32
from btclib.secpoint import bytes_from_point, point_from_octets
from btclib.utils import bytes_from_octets

mnemonic = "token output grass below such awake census safe orphan device other meat"
passphrase = ""
seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
rxprv = bip32.rootxprv_from_seed(seed)
rxpub = bip32.xpub_from_xprv(rxprv)
assert rxpub == b"xpub661MyMwAqRbcFzL26X6G7bySxgU1oV6GviUrNnhbeAS3ULQq35KEV6uSf1aJXEHjFYy6LXUPrYnfR9bSKWdFZ5VnYaEb3AbHPmXFVAoKKYT", rxpub

firmware_xprv = bip32.derive(rxprv, "m/0")
firmware_xpub = bip32.derive(rxpub, "m/0")
assert firmware_xpub == bip32.xpub_from_xprv(bip32.derive(rxprv, "m/0"))
firmware_pubkey = bip32.deserialize(firmware_xpub)['key']
assert bytes_from_point(point_from_octets(firmware_pubkey), False).hex() == "042374b3b6b06b65a3b831f857634ea135bf10b014d5bba0f935cb9eb26a4b6547ed3b37f277427a0ab23bda0ca79c5785dc54d2387fa3f295f4d5674d5b637de2"
assert bytes_from_point(point_from_octets(firmware_pubkey), True).hex() == "022374b3b6b06b65a3b831f857634ea135bf10b014d5bba0f935cb9eb26a4b6547"
firmware_wif = base58wif.wif_from_xprv(firmware_xprv)
firmware_address = slip32.address_from_xpub(firmware_xpub)

app_xprv = bip32.derive(rxprv, "m/1")
app_xpub = bip32.derive(rxpub, "m/1")
assert app_xpub == bip32.xpub_from_xprv(bip32.derive(rxprv, "m/1"))
app_pubkey = bip32.deserialize(app_xpub)['key']
assert bytes_from_point(point_from_octets(app_pubkey), False).hex() == "04ae3d0d5c669ed364636e79e72abc012a33be63e537babddf56bfd393256acf6dba0fac21da6386513674573a2d7baff4375c9b6d2498383853c52f0565f97f1a"
app_wif = base58wif.wif_from_xprv(app_xprv)
app_address = slip32.address_from_xpub(app_xpub)
assert app_address == b'1J6674MtZBpfHytdNofLUX6sLHAUaG33uK'

msg = "hello world"
h = sha256(msg.encode())
h256 = h.digest()
assert h256.hex().upper() == "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9", h256.hex().upper()

# hex-string
ledger_sig = bytes.fromhex("3044022044487c80833b7025739f450751c1d6624118e32e5f922b5a40a407efb48382e202200f2b6e53448f8e219ee1c2f109fa5b0a2b8bae482a4a81cf8c54f8c168260886")

# from ledger signature style to (base64-encoded) compact signature standard
r, s, _ = der.deserialize(ledger_sig)
rec_flag = 27 + ledger_sig[0] - 44
print(rec_flag)
rec_flag = 27 + 4 + (ledger_sig[0] & 0x01)
print(rec_flag)
b64sig = btcmsg.serialize(rec_flag+1, r, s)
btcmsg._verify(msg, app_address, b64sig)

# from (tuple) compact signature standard to ledger signature style
rf, r, s = btcmsg.sign(msg, app_wif, app_address)
btcmsg._verify(msg, app_address, (rf+1, r, s))
ledger_sig_equivalent = der.serialize(r, s, None)
