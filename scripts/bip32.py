#!/usr/bin/env python3

from hmac import HMAC
from hashlib import sha512
from base58 import b58encode_check, b58decode_check
from ellipticcurves import secp256k1 as ec
from WIF_address import h160, address_from_pubkey

# VERSION BYTES =      4 bytes        Base58 encode starts with
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4' # xprv
TESTNET_PRIVATE = b'\x04\x35\x83\x94' # tprv
SEGWIT_PRIVATE  = b'\x04\xb2\x43\x0c'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE, SEGWIT_PRIVATE]

MAINNET_PUBLIC  = b'\x04\x88\xB2\x1E' # xpub
TESTNET_PUBLIC  = b'\x04\x35\x87\xCF' # tpub
SEGWIT_PUBLIC   = b'\x04\xb2\x47\x46'
PUBLIC  = [MAINNET_PUBLIC,  TESTNET_PUBLIC,  SEGWIT_PUBLIC]

MAINNET_ADDRESS  = b'\x00'             # 1
TESTNET_ADDRESS  = b'\x6F'             # m or n
ADDRESS  = [MAINNET_ADDRESS,  TESTNET_ADDRESS]

# version                  : [  : 4]  4 bytes
# depth                    : [ 4: 5]  1 byte
# parent pubkey fingerprint: [ 5: 9]  4 bytes
# child index              : [ 9:13]  4 bytes
# chain code               : [13:45] 32 bytes
# key (private/public)     : [45:78] 33 bytes

def bip32_master_prvkey_from_seed(bip32_seed, version = PRIVATE[0]):
    """derive the master extended private key from the seed"""
    if type(bip32_seed) == str:
        bip32_seed = bytes.fromhex(bip32_seed)
    assert version in PRIVATE, "wrong version, master key must be private"
    xmprv = version                             # version
    xmprv += b'\x00'                            # depth
    xmprv += b'\x00\x00\x00\x00'                # parent's pubkey fingerprint
    xmprv += b'\x00\x00\x00\x00'                # child_index
    hashValue = HMAC(b"Bitcoin seed", bip32_seed, sha512).digest()
    xmprv += hashValue[32:]                     # chain_code
    mprv = int.from_bytes(hashValue[:32], 'big') % ec.order
    xmprv += b'\x00' + mprv.to_bytes(32, 'big') # private key
    return b58encode_check(xmprv)


def bip32_xpub_from_xprv(xprv):
    """derive the extended public key from the extended private key"""
    xprv = b58decode_check(xprv)
    assert len(xprv) == 78, "wrong length for decoded extended private key"
    assert xprv[45] == 0, "the extended key is not a private one"

    i = PRIVATE.index(xprv[:4])
    xpub = PUBLIC[i]                            # version

    # depth, fingerprint, child index, and chain code are left unchanged
    xpub += xprv[4:45]

    p = xprv[46:]
    P = ec.pointMultiply(p)
    xpub += ec.bytes_from_point(P, True)        # public key
    return b58encode_check(xpub)


def bip32_ckd(xparentkey, child_index):
    """Child Key Derivation

    Key derivation is normal if the extended parent key is public or
    child_index is less than 0x80000000.
    
    Key derivation is hardened if the extended parent key is private and
    child_index is not less than 0x80000000.
    """

    if isinstance(child_index, int):
        child_index = child_index.to_bytes(4, 'big')

    xparent = b58decode_check(xparentkey)
    assert len(xparent) == 78, "wrong length for extended parent key"

    version = xparent[:4]

    xkey = version                              # version
    xkey += (xparent[4] + 1).to_bytes(1, 'big') # (increased) depth

    if (version in PRIVATE):
        assert xparent[45] == 0, "version/key mismatch in extended parent key"
        parent_prvkey = xparent[46:]
        parent_pubkey = ec.bytes_from_point(ec.pointMultiply(parent_prvkey), True)
        xkey += h160(parent_pubkey)[:4]         # parent's pubkey fingerprint
        xkey += child_index                     # child index
        if (child_index[0] < 0x80): # normal derivation
            h = HMAC(xparent[13:45], parent_pubkey + child_index, sha512).digest()
        else:                       # hardened derivation
            h = HMAC(xparent[13:45], xparent[45:] + child_index, sha512).digest()
        xkey += h[32:]                          # chain code
        p = int.from_bytes(h[:32], 'big')
        p = (p + int.from_bytes(parent_prvkey, 'big')) % ec.order
        xkey += b'\x00' + p.to_bytes(32, 'big') # private key
    elif (version in PUBLIC):
        assert xparent[45] in (2, 3), "version/key mismatch in extended parent key"
        xkey += h160(xparent[45:])[:4]          # fingerprint of parent pubkey
        assert child_index[0] < 0x80, "No private/hardened derivation from pubkey"
        xkey += child_index                     # child index
        # normal derivation
        h = HMAC(xparent[13:45], xparent[45:] + child_index, sha512).digest()
        xkey += h[32:]                          # chain_code
        P = ec.pointMultiply(h[:32])
        parentPoint = ec.tuple_from_point(xparent[45:])
        P = ec.pointAdd(P, parentPoint)
        xkey += ec.bytes_from_point(P, True)    # public key
    else:
        raise ValueError("invalid extended key version")

    return b58encode_check(xkey)


def bip32_derive(xkey, path):
    """derive an extended key according to path like "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative) """

    indexes = []
    if isinstance(path, list):
        indexes = path
    elif isinstance(path, str):
        steps = path.split('/')
        if steps[0] not in {'m', '.'}:
            raise ValueError('Invalid derivation path: {}'.format(path))  
        if steps[0] == 'm':
            decoded = b58decode_check(xkey)
            t = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            assert decoded[4:13] == t, "Trying to derive absolute path from non-master key"

        for step in steps[1:]:
            hardened = False
            if step[-1] == "'" or step[-1] == "H":
                hardened = True
                step = step[:-1]
            index = int(step)
            index += 0x80000000 if hardened else 0
            indexes.append(index)
    else:
        raise TypeError("list of indexes or string like 'm/44'/0'/1'/0/10' expected")

    for index in indexes:
        xkey = bip32_ckd(xkey, index)

    return xkey

# FIXME: revise address_from_xpub / address_from_pubkey relation
def address_from_xpub(xpub, version=None):
    xpub = b58decode_check(xpub)
    assert len(xpub) == 78, "wrong length for decoded extended public key"
    assert xpub[45] in (2, 3), "the extended key is not a public one"
    # bitcoin: address version can be derived from xkey version
    # altcoin: address version cannot be derived from xkey version
    #          if xkey version bytes have not been specialized
    # FIXME use BIP44 here
    if version is None:
        xversion = xpub[:4]
        i = PUBLIC.index(xversion)
        version = ADDRESS[i]
    return address_from_pubkey(xpub[45:], version)


import unittest
import os
import json

class TestBIP32(unittest.TestCase):
    def test_bip32_vector1(self):
        seed = "000102030405060708090a0b0c0d0e0f"
        
        mprv = bip32_master_prvkey_from_seed(seed)
        self.assertEqual(mprv, b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        mpub = bip32_xpub_from_xprv(mprv)
        self.assertEqual(mpub, b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        mprv = bip32_derive(mprv, "m")
        self.assertEqual(mprv, b"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        mpub = bip32_derive(mpub, "m")
        self.assertEqual(mpub, b"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")

        xprv = bip32_derive(mprv, "m/0'")
        self.assertEqual(xprv, b"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7")
        xpub = bip32_xpub_from_xprv(xprv)
        self.assertEqual(xpub, b"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")

        xprv = bip32_derive(mprv, "m/0'/1")
        self.assertEqual(xprv, b"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs")
        xpub = bip32_derive(xpub, "./1")
        self.assertEqual(xpub, b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")
        xpub = bip32_xpub_from_xprv(xprv)
        self.assertEqual(xpub, b"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")

        xprv = bip32_derive(xprv, "./2H")
        self.assertEqual(xprv, b"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM")
        xpub = bip32_xpub_from_xprv(xprv)
        self.assertEqual(xpub, b"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")

        xprv = bip32_derive(xprv, "./2")
        self.assertEqual(xprv, b"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334")
        xpub = bip32_derive(xpub, "./2")
        self.assertEqual(xpub, b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")
        xpub = bip32_xpub_from_xprv(xprv)
        self.assertEqual(xpub, b"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")

        xprv = bip32_derive(mprv, "m/0'/1/2'/2/1000000000")
        self.assertEqual(xprv, b"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76")
        xpub = bip32_derive(xpub, "./1000000000")
        self.assertEqual(xpub, b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")
        xpub = bip32_xpub_from_xprv(xprv)
        self.assertEqual(xpub, b"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")


    def test_bip32_vector3(self):
        seed = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"

        mprv = bip32_master_prvkey_from_seed(seed)
        self.assertEqual(mprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        mpub = bip32_xpub_from_xprv(mprv)
        self.assertEqual(mpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

        mprv = bip32_derive(mprv, "m")
        self.assertEqual(mprv, b"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6")
        mpub = bip32_derive(mpub, "m")
        self.assertEqual(mpub, b"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")

        xprv = bip32_derive(mprv, "m/0'")
        self.assertEqual(xprv, b"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L")
        xpub = bip32_xpub_from_xprv(xprv)
        self.assertEqual(xpub, b"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")

    # BIP39 test vectors includes a BIP32 part
    def test_bip39_vectors(self):
        filename = "test_bip39_vectors.json"
        path_to_filename = os.path.join(os.path.dirname(__file__),
                                        "../data/",
                                        filename)
        with open(path_to_filename, 'r') as f:
            test_vectors = json.load(f)["english"]
        f.closed
        for test_vector in test_vectors:
            bip32_seed = test_vector[2]
            mprv = bip32_master_prvkey_from_seed(bip32_seed)
            self.assertEqual(mprv.decode(), test_vector[3])


    def test_mainnet(self):
        # bitcoin core derivation style
        mprv = b'xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS'

        # m/0'/0'/463'
        addr1 = b'1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5' 
        indexes = [0x80000000, 0x80000000, 0x80000000 + 463]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)))
        self.assertEqual(addr, addr1)
        path = "m/0'/0'/463'"
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, path)))
        self.assertEqual(addr, addr1)

        # m/0'/0'/267'
        addr2 = b'11x2mn59Qy43DjisZWQGRResjyQmgthki'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 267]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)))
        self.assertEqual(addr, addr2)
        path = "m/0'/0'/267'"
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, path)))
        self.assertEqual(addr, addr2)

        seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
        seed = bytes.fromhex(seed)
        xprv = bip32_master_prvkey_from_seed(seed)
        xpub = b'xpub661MyMwAqRbcFMYjmw8C6dJV97a4oLss6hb3v9wTQn2X48msQB61RCaLGtNhzgPCWPaJu7SvuB9EBSFCL43kTaFJC3owdaMka85uS154cEh'
        self.assertEqual(bip32_xpub_from_xprv(xprv), xpub)

        indexes = [0, 0]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, indexes)))
        self.assertEqual(addr, b'1FcfDbWwGs1PmyhMVpCAhoTfMnmSuptH6g')

        indexes = [0, 1]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, indexes)))
        self.assertEqual(addr, b'1K5GjYkZnPFvMDTGaQHTrVnd8wjmrtfR5x')

        indexes = [0, 2]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, indexes)))
        self.assertEqual(addr, b'1PQYX2uN7NYFd7Hq22ECMzfDcKhtrHmkfi')

        indexes = [1, 0]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, indexes)))
        self.assertEqual(addr, b'1BvSYpojWoWUeaMLnzbkK55v42DbizCoyq')

        indexes = [1, 1]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, indexes)))
        self.assertEqual(addr, b'1NXB59hF4QzYpFrB7o6usLBjbk2D3ZqxAL')

        indexes = [1, 2]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(xprv, indexes)))
        self.assertEqual(addr, b'16NLYkKtvYhW1Jp86tbocku3gxWcvitY1w')


    def test_testnet(self):
        # bitcoin core derivation style
        mprv = b'tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK'

        # m/0'/0'/51'
        addr1 = b'mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj'
        indexes = [0x80000000, 0x80000000, 0x80000000 + 51]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)))
        self.assertEqual(addr, addr1)
        path = "m/0'/0'/51'"
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, path)))
        self.assertEqual(addr, addr1)

        # m/0'/1'/150'
        addr2 = b'mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb'
        indexes = [0x80000000, 0x80000000 + 1, 0x80000000 + 150]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)))
        self.assertEqual(addr, addr2)
        path = "m/0'/1'/150'"
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, path)))
        self.assertEqual(addr, addr2)


    def test_altnet(self):
        # non-bitcoin address version
        version = 0x46.to_bytes(1, 'big')

        mprv = b'xprv9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L'

        # m/0'/0'/5'
        receive = b'VUqyLGVdUADWEqDqL2DeUBAcbPQwZfWDDY'
        indexes = [0x80000000, 0x80000000, 0x80000005]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)), version)
        self.assertEqual(addr, receive)
        path = "m/0'/0'/5'"
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, path)), version)
        self.assertEqual(addr, receive)

        # m/0'/1'/1'
        change = b'VMg6DpX7SQUsoECdpXJ8Bv6R7p11PfwHwy'
        indexes = [0x80000000, 0x80000001, 0x80000001]
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)), version)
        self.assertEqual(addr, change)
        path = "m/0'/1'/1'"
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, path)), version)
        self.assertEqual(addr, change)

        seed = "5b56c417303faa3fcba7e57400e120a0ca83ec5a4fc9ffba757fbe63fbd77a89a1a3be4c67196f57c39a88b76373733891bfaba16ed27a813ceed498804c0570"
        seed = bytes.fromhex(seed)
        mprv = bip32_master_prvkey_from_seed(seed)
        self.assertEqual(mprv, b'xprv9s21ZrQH143K3t4UZrNgeA3w861fwjYLaGwmPtQyPMmzshV2owVpfBSd2Q7YsHZ9j6i6ddYjb5PLtUdMZn8LhvuCVhGcQntq5rn7JVMqnie')

        indexes = [0x80000000, 0, 0] # receive
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)), version)
        self.assertEqual(addr, b'VTpEhLjvGYE16pLcNrMY53gQB9bbhn581W')

        indexes = [0x80000000, 1, 0] # change
        addr = address_from_xpub(bip32_xpub_from_xprv(bip32_derive(mprv, indexes)), version)
        self.assertEqual(addr, b'VRtaZvAe4s29aB3vuXyq7GYEpahsQet2B1')


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
