#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""BIP32 Hierarchical Deterministic Wallet functions.

A deterministic wallet is a hash-chain of private/public key pairs that
derives from a single root, which is the only element requiring backup.
Moreover, there are schemes where public keys can be calculated without
accessing private keys.

A hierarchical deterministic wallet is a tree of multiple hash-chains,
derived from a single root, allowing for selective sharing of keypair
chains.

Here, the HD wallet is implemented according to BIP32 bitcoin standard
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.

A BIP32 extended key is 78 bytes:

- [  : 4] version
- [ 4: 5] depth in the derivation path
- [ 5: 9] parent fingerprint
- [ 9:13] index
- [13:45] chain code
- [45:78] compressed pub_key or [0x00][prv_key]
"""

from __future__ import annotations

import copy
import hmac
from dataclasses import dataclass

from btclib import base58
from btclib.alias import INF, BinaryData, Octets, Point, String
from btclib.bip32.der_path import BIP32DerPath, indexes_from_bip32_path
from btclib.curves import (
    bytes_from_point,
    bytes_from_prv_key_int,
    mult,
    point_from_octets,
    secp256k1,
)
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS, XPRV_VERSIONS_ALL, XPUB_VERSIONS_ALL
from btclib.utils import bytes_from_octets, bytesio_from_binarydata, hex_string

# secp256k1 is written out at each use rather than aliased to a module
# global "ec": BIP32 is defined for secp256k1 and for nothing else, so
# the alias was not configuration, and rebinding btclib.bip32.bip32.ec
# changed key validation for every caller in the process


_KEY_SIZE = [("version", 4), ("parent_fingerprint", 4), ("chain_code", 32), ("key", 33)]
_REQUIRED_LENGTH = 78


@dataclass
class BIP32KeyData:
    version: bytes
    depth: int
    parent_fingerprint: bytes
    # index is an int, not bytes, to avoid any byteorder ambiguity
    index: int
    chain_code: bytes
    key: bytes

    @property
    def is_private(self) -> bool:
        return self.key[0] == 0

    def __repr__(self) -> str:
        # never echo private key material: mask key and chain_code
        # (key[:1], not is_private, so that repr cannot raise on an
        # invalid instance with an empty key)
        private = self.key[:1] == b"\x00"
        chain_code = "***" if private else self.chain_code.hex()
        key = "***" if private else self.key.hex()
        return (
            f"{type(self).__name__}("
            f"version={self.version.hex()}, "
            f"depth={self.depth}, "
            f"parent_fingerprint={self.parent_fingerprint.hex()}, "
            f"index={self.index}, "
            f"chain_code={chain_code}, "
            f"key={key})"
        )

    @property
    def is_hardened(self) -> bool:
        return self.index >= 0x80000000

    @property
    def is_root(self) -> bool:
        return (
            self.depth == 0
            and self.index == 0
            and self.parent_fingerprint == b"\x00" * 4
        )

    def __init__(
        self,
        version: Octets,
        depth: int,
        parent_fingerprint: Octets,
        index: int,
        chain_code: Octets,
        key: Octets,
        *,
        check_validity: bool = True,
    ) -> None:
        self.version = bytes_from_octets(version)
        # int(), where the annotation already says int, for the same reason
        # bytes_from_octets is called on the four Octets fields: from_dict
        # feeds this constructor a json object, where a whole number may
        # arrive as a float. assert_valid used to do the coercion, i.e. it
        # rewrote the object it was asked to inspect -- and it is called by
        # serialize() and to_dict(), so reading a key mutated it
        self.depth = int(depth)
        self.parent_fingerprint = bytes_from_octets(parent_fingerprint)
        self.index = int(index)
        self.chain_code = bytes_from_octets(chain_code)
        self.key = bytes_from_octets(key)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        for key, size in _KEY_SIZE:
            # bytes() is the type check, not a coercion: it raises
            # TypeError for a field rebound to a str, which would otherwise
            # pass the length test below and fail later on .hex(). What
            # this loop no longer does is assign the result back
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)

        # the same type check for the two int fields, which assert_valid
        # used to coerce instead -- repairing the mistake, and rewriting
        # the object to do it. Dropping it altogether would have let a
        # float reach to_bytes and leave through an AttributeError
        for key in ("depth", "index"):
            value_ = getattr(self, key)
            if not isinstance(value_, int):
                err_msg = f"invalid {key} type: {type(value_).__name__}"
                raise BTClibTypeError(err_msg)

        if not 0 <= self.index <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid index: {self.index}")

        if not 0 <= self.depth <= 255:
            raise BTClibValueError(f"invalid depth: {self.depth}")

        if self.depth == 0:
            if self.parent_fingerprint != b"\x00" * 4:
                err_msg = f"zero depth with non-zero parent fingerprint: 0x{self.parent_fingerprint.hex()}"
                raise BTClibValueError(err_msg)
            if self.index != 0:
                raise BTClibValueError(f"zero depth with non-zero index: {self.index}")

        if self.version in XPRV_VERSIONS_ALL:
            if self.key[0] != 0:
                raise BTClibValueError(
                    f"invalid private key prefix: 0x{self.key[:1].hex()}"
                )
            q = int.from_bytes(self.key[1:], byteorder="big", signed=False)
            if not 0 < q < secp256k1.n:
                # never echo the scalar: it is (attempted) key material
                raise BTClibValueError("invalid private key not in 1..n-1")
        elif self.version in XPUB_VERSIONS_ALL:
            if self.key[0] not in (2, 3):
                err_msg = f"invalid public key prefix not in (0x02, 0x03): 0x{self.key[:1].hex()}"
                raise BTClibValueError(err_msg)
            try:
                secp256k1.y(int.from_bytes(self.key[1:], byteorder="big", signed=False))
            except BTClibValueError as e:
                err_msg = f"invalid public key: 0x{self.key.hex()}"
                raise BTClibValueError(err_msg) from e
        else:
            raise BTClibValueError(
                f"unknown extended key version: 0x{self.version.hex()}"
            )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        return b"".join(
            [
                self.version,
                self.depth.to_bytes(1, byteorder="big", signed=False),
                self.parent_fingerprint,
                self.index.to_bytes(4, byteorder="big", signed=False),
                self.chain_code,
                self.key,
            ]
        )

    def b58encode(self, *, check_validity: bool = True) -> str:
        data_binary = self.serialize(check_validity=check_validity)
        return base58.b58encode(data_binary).decode("ascii")

    @classmethod
    def parse(
        cls: type[BIP32KeyData], xkey_bin: BinaryData, *, check_validity: bool = True
    ) -> BIP32KeyData:
        """Return a BIP32KeyData by parsing 78 bytes from binary data."""
        stream = bytesio_from_binarydata(xkey_bin)
        xkey_bin = stream.read(_REQUIRED_LENGTH)

        if check_validity and len(xkey_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(xkey_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise BTClibValueError(err_msg)

        return cls(
            version=xkey_bin[:4],
            depth=xkey_bin[4],
            parent_fingerprint=xkey_bin[5:9],
            index=int.from_bytes(xkey_bin[9:13], byteorder="big", signed=False),
            chain_code=xkey_bin[13:45],
            key=xkey_bin[45:78],
            check_validity=check_validity,
        )

    @classmethod
    def b58decode(
        cls: type[BIP32KeyData], address: String, *, check_validity: bool = True
    ) -> BIP32KeyData:
        if isinstance(address, str):
            address = address.strip()

        xkey_bin = base58.b58decode(address)
        return cls.parse(xkey_bin, check_validity=check_validity)


def _rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> BIP32KeyData:
    """Return BIP32 root master extended private key from seed."""
    seed = bytes_from_octets(seed)
    bit_length = len(seed) * 8
    # the bit count is diagnostic enough: never echo the seed itself
    if bit_length < 128:
        raise BTClibValueError(f"too few bits for seed: {bit_length}")
    if bit_length > 512:
        raise BTClibValueError(f"too many bits for seed: {bit_length}")
    hmac_ = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    k = b"\x00" + hmac_[:32]
    v = bytes_from_octets(version, 4)

    return BIP32KeyData(
        version=v,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        index=0,
        chain_code=hmac_[32:],
        key=k,
    )


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> str:
    """Return BIP32 root master extended private key from seed."""
    xkey = _rootxprv_from_seed(seed, version)
    return xkey.b58encode()


BIP32Key = BIP32KeyData | String


def _xpub_from_xprv(xprv: BIP32Key) -> BIP32KeyData:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign
    transactions).
    """
    if isinstance(xprv, BIP32KeyData):
        xkey = copy.copy(xprv)
    else:
        xkey = BIP32KeyData.b58decode(xprv)

    if xkey.key[0] != 0:
        # the offending key is public here, but never echo a
        # serialized xkey: the prefix already says what is wrong
        err_msg = f"not a private key: prefix 0x{xkey.key[:1].hex()}"
        raise BTClibValueError(err_msg)

    i = XPRV_VERSIONS_ALL.index(xkey.version)
    xkey.version = XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)
    xkey.key = bytes_from_prv_key_int(q)

    return xkey


def xpub_from_xprv(xprv: BIP32Key) -> str:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign
    transactions).
    """
    xkey = _xpub_from_xprv(xprv)
    return xkey.b58encode()


# repr=False: a generated __repr__ would print prv_key_int, the very
# scalar the inherited masking __repr__ exists to hide
@dataclass(repr=False)
class _BIP32KeyData(BIP32KeyData):
    # extensions used to cache intermediate results
    # in multi-level derivation: do not rely on them elsewhere

    prv_key_int: int  # non-zero for private key only
    pub_key_point: Point  # non-Infinity for public key only

    def __init__(
        self,
        version: Octets,
        depth: int,
        parent_fingerprint: Octets,
        index: int,
        chain_code: Octets,
        key: Octets,
        *,
        check_validity: bool = True,
    ) -> None:
        super().__init__(
            version,
            depth,
            parent_fingerprint,
            index,
            chain_code,
            key,
            check_validity=False,
        )

        if self.is_private:
            self.prv_key_int = int.from_bytes(self.key[1:], "big", signed=False)
            self.pub_key_point = INF
        else:
            self.prv_key_int = 0
            self.pub_key_point = point_from_octets(self.key, secp256k1)

        if check_validity:
            self.assert_valid()


def _invalid_child(index: int, reason: str) -> BTClibValueError:
    """Return the error for a child BIP32 declares invalid.

    BIP32 has three of these -- parse256(IL) >= n, a zero private child,
    a public child at infinity -- and tells the caller to "proceed with
    the next value for i". Raising says so rather than deriving that
    next index silently: this code is asked for one index, and returning
    the key of another is a substitution nothing downstream could
    detect. Bitcoin Core answers the same way, CKDpriv returning false
    and leaving the choice to whoever picked the path.

    At odds of about 2^-127 none of the three is reachable, so what this
    buys is a defined answer rather than a key no other wallet derives.
    """
    err_msg = f"invalid child index {index}: {reason}"
    err_msg += "; BIP32 mandates deriving the next index instead"
    return BTClibValueError(err_msg)


def __prv_key_derivation(xkey: _BIP32KeyData, index: int, pub_key: bytes) -> None:
    xb = (
        xkey.key
        if index >= 0x80000000
        else pub_key or bytes_from_prv_key_int(xkey.prv_key_int)
    )
    xb += index.to_bytes(4, byteorder="big", signed=False)
    hmac_ = hmac.new(xkey.chain_code, xb, "sha512").digest()
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    if offset >= secp256k1.n:
        raise _invalid_child(index, "the hmac left half is not a valid scalar")
    prv_key_int = (xkey.prv_key_int + offset) % secp256k1.n
    if prv_key_int == 0:
        raise _invalid_child(index, "the child private key is zero")

    # xkey is mutated only past the checks, so a rejected index leaves
    # it the key it was rather than half a derivation
    xkey.chain_code = hmac_[32:]
    xkey.prv_key_int = prv_key_int
    xkey.key = b"\x00" + prv_key_int.to_bytes(32, byteorder="big", signed=False)


def __pub_key_derivation(xkey: _BIP32KeyData, index: int) -> None:
    xb = xkey.key + index.to_bytes(4, byteorder="big", signed=False)
    hmac_ = hmac.new(xkey.chain_code, xb, "sha512").digest()
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    if offset >= secp256k1.n:
        raise _invalid_child(index, "the hmac left half is not a valid scalar")
    pub_key_point = secp256k1.add(xkey.pub_key_point, mult(offset))
    if pub_key_point[1] == 0:  # INF, the point at infinity, is (int, 0)
        raise _invalid_child(index, "the child public key is the point at infinity")

    xkey.chain_code = hmac_[32:]
    xkey.pub_key_point = pub_key_point
    xkey.key = bytes_from_point(pub_key_point)


def _derive(
    xkey: BIP32Key, der_path: BIP32DerPath, forced_version: Octets | None = None
) -> BIP32KeyData:
    if not isinstance(xkey, BIP32KeyData):
        xkey = BIP32KeyData.b58decode(xkey)

    indexes = indexes_from_bip32_path(der_path)

    final_depth = xkey.depth + len(indexes)
    if final_depth > 255:
        err_msg = f"final depth greater than 255: {final_depth}"
        raise BTClibValueError(err_msg)

    xkey = _BIP32KeyData(
        version=xkey.version,
        depth=final_depth,
        parent_fingerprint=xkey.parent_fingerprint,
        index=xkey.index,
        chain_code=xkey.chain_code,
        key=xkey.key,
    )

    if forced_version:
        if xkey.version in XPRV_VERSIONS_ALL:
            allowed_versions = XPRV_VERSIONS_ALL
        else:
            allowed_versions = XPUB_VERSIONS_ALL
        fversion = bytes_from_octets(forced_version, 4)
        if fversion not in allowed_versions:
            err_msg = "invalid version forced on the extended key"
            err_msg += f"{hex_string(fversion)}"
            raise BTClibValueError(err_msg)
        xkey.version = fversion

    if indexes:
        if xkey.is_private:
            for index in indexes[:-1]:
                __prv_key_derivation(xkey, index, b"")
            pub_key = bytes_from_prv_key_int(xkey.prv_key_int)
            xkey.parent_fingerprint = hash160(pub_key)[:4]
            __prv_key_derivation(xkey, indexes[-1], pub_key)
        else:
            if any(index >= 0x80000000 for index in indexes):
                raise BTClibValueError("invalid hardened derivation from public key")
            for index in indexes[:-1]:
                __pub_key_derivation(xkey, index)
            xkey.parent_fingerprint = hash160(xkey.key)[:4]
            __pub_key_derivation(xkey, indexes[-1])

        xkey.index = indexes[-1]

    return xkey


def derive(
    xkey: BIP32Key, der_path: BIP32DerPath, forced_version: Octets | None = None
) -> str:
    """Derive a BIP32 key across a path spanning multiple depth levels.

    Valid BIP32DerPath examples:

    - string like "m/44h/0'/1H/0/10"
    - iterable integer indexes
    - one single integer index
    - bytes in multiples of the 4-bytes index

    BIP32DerPath is case/blank/extra-slash insensitive
    (e.g. "M /44h / 0' /1H // 0/ 10 / ").
    """
    xkey = _derive(xkey, der_path, forced_version)
    return xkey.b58encode()


def _derive_from_account(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> BIP32KeyData:
    if not isinstance(mxkey, BIP32KeyData):
        mxkey = BIP32KeyData.b58decode(mxkey)

    if not mxkey.is_hardened:
        raise BTClibValueError("unhardened account/master key")

    if branch >= 0x80000000:
        raise BTClibValueError("invalid private derivation at branch level")
    if branch > max_index:
        err_msg = f"invalid branch number: {branch} is higher than {max_index}."
        raise BTClibValueError(err_msg)
    if branches_0_1_only and branch not in (0, 1):
        raise BTClibValueError(f"invalid branch number: {branch} not in (0, 1)")

    if address_index >= 0x80000000:
        raise BTClibValueError("invalid private derivation at address index level")
    if address_index > max_index:
        err_msg = f"invalid address index: {address_index} is higher than {max_index}."
        raise BTClibValueError(err_msg)

    return _derive(mxkey, f"m/{branch}/{address_index}")


def derive_from_account(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> str:
    """Derive a key with public derivation at the given branch and index.

    It also ensures that the master key is hardened, that the branch is
    a standard receive or change, and that the index is not arbitrarily
    high.
    """
    return _derive_from_account(
        mxkey, branch, address_index, branches_0_1_only, max_index
    ).b58encode()


def crack_prv_key(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> str:
    if isinstance(parent_xpub, BIP32KeyData):
        p = copy.copy(parent_xpub)
    else:
        p = BIP32KeyData.b58decode(parent_xpub)

    if p.key[0] not in (2, 3):
        raise BTClibValueError(_err_msg("parent", "not a public", p))
    if isinstance(child_xprv, BIP32KeyData):
        c = child_xprv
    else:
        c = BIP32KeyData.b58decode(child_xprv)

    if c.key[0] != 0:
        raise BTClibValueError(_err_msg("child", "not a private", c))
    # check depth
    if c.depth != p.depth + 1:
        raise BTClibValueError("not a parent's child: wrong depths")

    # check fingerprint
    if c.parent_fingerprint != hash160(p.key)[:4]:
        raise BTClibValueError("not a parent's child: wrong parent fingerprint")

    if c.is_hardened:
        raise BTClibValueError("hardened child derivation")

    p.version = c.version

    hmac_ = hmac.new(
        p.chain_code,
        p.key + c.index.to_bytes(4, byteorder="big", signed=False),
        "sha512",
    ).digest()
    child_q = int.from_bytes(c.key[1:], byteorder="big", signed=False)
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    parent_q = (child_q - offset) % secp256k1.n
    p.key = b"\x00" + parent_q.to_bytes(32, byteorder="big", signed=False)

    return p.b58encode()


def _err_msg(
    child_or_parent: str, not_a_private_or_public: str, key: BIP32KeyData
) -> str:
    # the "not a public" branch is reached with an xprv:
    # never echo a serialized xkey, the prefix says what is wrong
    return (
        f"extended {child_or_parent} key is {not_a_private_or_public} key: "
        f"prefix 0x{key.key[:1].hex()}"
    )
