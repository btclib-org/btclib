#!/usr/bin/python3
'''wifs and addresses

Implementation of Base58 encoding of private keys (wifs)
and public keys (addresses)
'''

from ECsecp256k1 import ec
from base58 import b58encode_check, b58decode_check, base58digits
from hashlib import sha256, new as hnew


def bytes_from_prvkey(prv):
    """Return private key as 32 bytes"""
    
    if isinstance(prv, int):
        assert 0 < prv           , "Invalid Private Key"
        assert     prv < ec.order, "Invalid Private Key"
        return prv.to_bytes(32, 'big')

    if isinstance(prv, str):
        # wif
        if len(prv) in (51, 52) and all(c in base58digits for c in prv):
          return prvkey_from_wif(prv)
        # hex string
        if prv[:2] == "0x":
          prv = prv[2:]
        assert len(prv) & 2 == 0, "odd-length hex string"
        prv = bytes.fromhex(prv)

    if isinstance(prv, bytes) or isinstance(prv, bytearray):
        assert len(prv) == 32, "wrong lenght"
        assert int.from_bytes(prv, 'big') < ec.order, "prvkey >= order"
        return prv
    else: 
        raise TypeError("a bytes-like object is required (also str or int)")


def int_from_prvkey(prv):
    """Return private key as int"""
    
    if isinstance(prv, str):
        # wif
        if len(prv) in (51, 52) and all(c in base58digits for c in prv):
            prv = prvkey_from_wif(prv)
        # hex string
        if prv[:2] == "0x":
            prv = prv[2:]
        assert len(prv) & 2 == 0, "odd-length hex string"
        prv = bytes.fromhex(prv)

    if isinstance(prv, bytes) or isinstance(prv, bytearray):
        assert len(prv) == 32, "wrong lenght"
        prv = int.from_bytes(prv, 'big')

    if isinstance(prv, int):
        assert 0 < prv           , "Invalid Private Key"
        assert     prv < ec.order, "Invalid Private Key"
        return prv
    else:
        raise TypeError("a bytes-like object is required (also str or int)")


def wif_from_prvkey(p, compressed=True):
    """private key to Wallet Import Format"""

    payload = b'\x80' + bytes_from_prvkey(p)
    if compressed: payload += b'\x01'
    return b58encode_check(payload)


def prvkey_from_wif(wif):
    """Wallet Import Format to (bytes) private key"""

    payload = b58decode_check(wif)
    assert payload[0] == 0x80, "not a wif"

    if len(payload) == 34: # compressed
        assert payload[33] == 0x01, "not a wif"
        return bytes_from_prvkey(payload[1:-1]), True
    else:                  # uncompressed
        assert len(payload) == 33, "not a wif"
        return bytes_from_prvkey(payload[1:]), False


def pubkey_from_prvkey(prvkey, compressed = True):
    P = ec.pointMultiply(prvkey)
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


import unittest

class TestKeys(unittest.TestCase):

    def test_wif_from_prvkey(self):
        p_num = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
        p_bytes = bytes_from_prvkey(p_num)
        p_hex = p_bytes.hex()

        # private key as number
        wif = wif_from_prvkey(p_num)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p2 = prvkey_from_wif(wif)
        self.assertEqual(p2[0], p_bytes)
        self.assertEqual(p2[1], True)
        wif = wif_from_prvkey(p_num, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p3 = prvkey_from_wif(wif)
        self.assertEqual(p3[0], p_bytes)
        self.assertEqual(p3[1], False)

        # private key as bytes, i.e. the preferred format
        wif = wif_from_prvkey(p_bytes)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p4 = prvkey_from_wif(wif)
        self.assertEqual(p4[0], p_bytes)
        self.assertEqual(p4[1], True)
        wif = wif_from_prvkey(p_bytes, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p5 = prvkey_from_wif(wif)
        self.assertEqual(p5[0], p_bytes)
        self.assertEqual(p5[1], False)

        # private key as hex string
        wif = wif_from_prvkey(p_hex)
        self.assertEqual(wif, b'KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
        p6 = prvkey_from_wif(wif)
        self.assertEqual(p6[0], p_bytes)
        self.assertEqual(p6[1], True)
        wif = wif_from_prvkey(p_hex, False)
        self.assertEqual(wif, b'5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
        p7 = prvkey_from_wif(wif)
        self.assertEqual(p7[0], p_bytes)
        self.assertEqual(p7[1], False)

    def test_address_from_pubkey(self):
        # https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
        p = 0x18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725
        p = p % ec.order
        a = address_from_pubkey(pubkey_from_prvkey(p, False))
        self.assertEqual(a, b'16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM')
        hash160_from_address(a)
        a = address_from_pubkey(pubkey_from_prvkey(p, True))
        self.assertEqual(a, b'1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs')
        hash160_from_address(a)
  
    def test_address_from_wif(self):
        wif1 = "5J1geo9kcAUSM6GJJmhYRX1eZEjvos9nFyWwPstVziTVueRJYvW"
        a = address_from_pubkey(pubkey_from_prvkey(*prvkey_from_wif(wif1)))
        self.assertEqual(a, b'1LPM8SZ4RQDMZymUmVSiSSvrDfj1UZY9ig')

        wif2 = "Kx621phdUCp6sgEXPSHwhDTrmHeUVrMkm6T95ycJyjyxbDXkr162"
        a = address_from_pubkey(pubkey_from_prvkey(*prvkey_from_wif(wif2)))
        self.assertEqual(a, b'1HJC7kFvXHepkSzdc8RX6khQKkAyntdfkB')

        self.assertEqual(prvkey_from_wif(wif1)[0], prvkey_from_wif(wif2)[0])
  
if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
