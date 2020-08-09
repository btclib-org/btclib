#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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
- [45:78] compressed pubkey or [0x00][prvkey]
"""

import copy
import hmac
from typing import List, Optional, Tuple

from . import bip39, electrum
from .alias import INF, BIP32Key, BIP32KeyDict, Octets, Path, Point
from .base58 import b58decode, b58encode
from .curvemult import mult
from .curves import secp256k1 as ec
from .mnemonic import Mnemonic
from .network import (
    _NETWORKS,
    _P2WPKH_PRV_PREFIXES,
    _XPRV_PREFIXES,
    _XPRV_VERSIONS_ALL,
    _XPUB_VERSIONS_ALL,
    NETWORKS,
)
from .secpoint import bytes_from_point, point_from_octets
from .utils import bytes_from_octets, hash160, hex_string


def _check_version_key(version: bytes, key: bytes) -> None:

    if version in _XPRV_VERSIONS_ALL:
        if key[0] != 0:
            raise ValueError(f"invalid private key prefix: 0x{key[0:1].hex()}")
        q = int.from_bytes(key[1:], byteorder="big")
        if not 0 < q < ec.n:
            raise ValueError(f"private key not in 1..n-1: {hex(q)}")
    elif version in _XPUB_VERSIONS_ALL:
        if key[0] not in (2, 3):
            raise ValueError(f"invalid public key prefix: 0x{key[0:1].hex()}")
        try:
            ec.y(int.from_bytes(key[1:], byteorder="big"))
        except Exception:
            raise ValueError(f"invalid public key 0x{key.hex()}")
    else:
        raise ValueError(f"unknown extended key version 0x{version.hex()}")


def _check_depth_pfp_index(depth: int, pfp: bytes, i: bytes) -> None:

    if depth < 0 or depth > 255:
        raise ValueError(f"invalid depth {depth}")
    elif depth == 0:
        if pfp != b"\x00\x00\x00\x00":
            err_msg = f"zero depth with non-zero parent fingerprint 0x{pfp.hex()}"
            raise ValueError(err_msg)
        if i != b"\x00\x00\x00\x00":
            raise ValueError(f"zero depth with non-zero index 0x{i.hex()}")
    else:
        if pfp == b"\x00\x00\x00\x00":
            raise ValueError(f"zero parent fingerprint with non-zero depth {depth}")


def deserialize(xkey: BIP32Key) -> BIP32KeyDict:

    d: BIP32KeyDict
    if isinstance(xkey, dict):
        d = copy.copy(xkey)
        length = len(d["chain_code"])
        if length != 32:
            raise ValueError(f"invalid chain code length: {length}")
        if not isinstance(d["chain_code"], bytes):
            raise ValueError("invalid chain code")
    else:
        if isinstance(xkey, str):
            xkey = xkey.strip()
        xkey = b58decode(xkey, 78)
        d = {
            "version": xkey[:4],
            "depth": xkey[4],
            "parent_fingerprint": xkey[5:9],
            "index": xkey[9:13],
            "chain_code": xkey[13:45],
            "key": xkey[45:],
        }

    _check_version_key(d["version"], d["key"])
    _check_depth_pfp_index(d["depth"], d["parent_fingerprint"], d["index"])

    return d


def serialize(d: BIP32KeyDict) -> bytes:

    if len(d["key"]) != 33:
        m = f"invalid key length: {len(d['key'])}-bytes"
        raise ValueError(m)
    # version length is checked in _check_version_key
    _check_version_key(d["version"], d["key"])
    t = d["version"]

    if len(d["parent_fingerprint"]) != 4:
        m = "invalid parent fingerprint length: "
        m += f"{len(d['parent_fingerprint'])}-bytes "
        raise ValueError(m)
    if len(d["index"]) != 4:
        m = f"invalid index length: {len(d['index'])}-bytes"
        raise ValueError(m)
    _check_depth_pfp_index(d["depth"], d["parent_fingerprint"], d["index"])
    t += d["depth"].to_bytes(1, "big")
    t += d["parent_fingerprint"]
    t += d["index"]

    if len(d["chain_code"]) != 32:
        m = f"invalid chain code length: {len(d['chain_code'])}-bytes"
        raise ValueError(m)
    t += d["chain_code"]

    # already checked in _check_version_key
    t += d["key"]

    return b58encode(t, 78)


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"]["bip32_prv"]
) -> bytes:
    """Return BIP32 root master extended private key from seed."""

    seed = bytes_from_octets(seed)
    bitlenght = len(seed) * 8
    if bitlenght < 128:
        raise ValueError(f"too few bits for seed: {bitlenght} in '{hex_string(seed)}'")
    if bitlenght > 512:
        raise ValueError(f"too many bits for seed: {bitlenght} in '{hex_string(seed)}'")
    hd = hmac.digest(b"Bitcoin seed", seed, "sha512")
    k = b"\x00" + hd[:32]
    v = bytes_from_octets(version, 4)
    if v not in _XPRV_VERSIONS_ALL:
        raise ValueError(f"unknown private key version: {v.hex()}")

    d: BIP32KeyDict = {
        "version": v,
        "depth": 0,
        "parent_fingerprint": b"\x00\x00\x00\x00",
        "index": b"\x00\x00\x00\x00",
        "chain_code": hd[32:],
        "key": k,
    }
    return serialize(d)


def mxprv_from_bip39_mnemonic(
    mnemonic: Mnemonic, passphrase: str = "", network: str = "mainnet"
) -> bytes:
    """Return BIP32 root master extended private key from BIP39 mnemonic."""

    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
    version = NETWORKS[network]["bip32_prv"]
    return rootxprv_from_seed(seed, version)


def mxprv_from_electrum_mnemonic(
    mnemonic: Mnemonic, passphrase: str = "", network: str = "mainnet"
) -> bytes:
    """Return BIP32 master extended private key from Electrum mnemonic.

    Note that for a "standard" mnemonic the derivation path is "m",
    for a "segwit" mnemonic it is "m/0h" instead.
    """

    version, seed = electrum._seed_from_mnemonic(mnemonic, passphrase)
    network_index = _NETWORKS.index(network)

    if version == "standard":
        xversion = _XPRV_PREFIXES[network_index]
        return rootxprv_from_seed(seed, xversion)
    elif version == "segwit":
        xversion = _P2WPKH_PRV_PREFIXES[network_index]
        rootxprv = rootxprv_from_seed(seed, xversion)
        return derive(rootxprv, 0x80000000)  # "m/0h"
    else:
        raise ValueError(f"unmanaged electrum mnemonic version: {version}")


def xpub_from_xprv(xprv: BIP32Key) -> bytes:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    xkey_dict = copy.copy(xprv) if isinstance(xprv, dict) else deserialize(xprv)
    if xkey_dict["key"][0] != 0:
        raise ValueError(f"not a private key: {serialize(xkey_dict).decode()}")

    i = _XPRV_VERSIONS_ALL.index(xkey_dict["version"])
    xkey_dict["version"] = _XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey_dict["key"][1:], byteorder="big")
    Q = mult(q)
    xkey_dict["key"] = bytes_from_point(Q)

    return serialize(xkey_dict)


def _indexes_from_path(der_path: str) -> Tuple[List[bytes], bool]:

    steps = [x.strip() for x in der_path.split("/")]
    if steps[0] in ("m", "M"):
        absolute = True
    elif steps[0] == ".":
        absolute = False
    elif steps[0] == "":
        raise ValueError("empty derivation path root: must be m or .")
    else:
        raise ValueError(f"invalid derivation path root: {steps[0]}")

    indexes: List[bytes] = list()
    for step in steps[1:]:
        if step == "":  # extra slash
            continue
        if step[-1] in ("'", "H", "h"):
            index = int(step[:-1])
            if index < 0:
                raise ValueError(f"negative index in derivation path: {der_path}")
            index += 0x80000000
        else:
            index = int(step)
        indexes.append(index.to_bytes(4, "big"))

    if len(indexes) > 255:
        err_msg = f"derivation path depth greater than 255: {len(indexes)}"
        raise ValueError(err_msg)
    return indexes, absolute


def indexes_from_path(der_path: Path) -> Tuple[List[bytes], bool]:
    absolute = False
    if isinstance(der_path, str):
        der_path = der_path.strip()
        indexes, absolute = _indexes_from_path(der_path)
    elif isinstance(der_path, int):
        indexes = [der_path.to_bytes(4, byteorder="big")]
    elif isinstance(der_path, bytes):
        if len(der_path) != 4:
            raise ValueError(f"index must be 4-bytes, not {len(der_path)}")
        indexes = [der_path]
    else:  # Iterable[int]
        indexes = [i.to_bytes(4, byteorder="big") for i in der_path]

    return indexes, absolute


class _ExtendedBIP32KeyDict(BIP32KeyDict):
    # extensions used to cache intemediate results
    # in multi-level derivation: do not rely on them elsewhere
    q: int  # non-zero for private key only
    Q: Point  # non-Infinity for public key only


def __ckd(d: _ExtendedBIP32KeyDict, index: bytes) -> None:

    # FIXME the following check should be enforced
    # if d["depth"] == 0 and index[0] < 0x80:
    #    raise UserWarning("public derivation at depth one level")

    # d is a prvkey
    if d["key"][0] == 0:
        d["depth"] += 1
        Pbytes = bytes_from_point(mult(d["q"]))
        d["parent_fingerprint"] = hash160(Pbytes)[:4]
        d["index"] = index
        if index[0] >= 0x80:  # hardened derivation
            h = hmac.digest(d["chain_code"], d["key"] + index, "sha512")
        else:  # normal derivation
            h = hmac.digest(d["chain_code"], Pbytes + index, "sha512")
        d["chain_code"] = h[32:]
        offset = int.from_bytes(h[:32], byteorder="big")
        d["q"] = (d["q"] + offset) % ec.n
        d["key"] = b"\x00" + d["q"].to_bytes(32, "big")
        d["Q"] = INF
    # d is a pubkey
    else:
        if index[0] >= 0x80:
            raise ValueError("hardened derivation from public key")
        d["depth"] += 1
        d["parent_fingerprint"] = hash160(d["key"])[:4]
        d["index"] = index
        h = hmac.digest(d["chain_code"], d["key"] + index, "sha512")
        d["chain_code"] = h[32:]
        offset = int.from_bytes(h[:32], byteorder="big")
        Offset = mult(offset)
        d["Q"] = ec.add(d["Q"], Offset)
        d["key"] = bytes_from_point(d["Q"])
        d["q"] = 0


def _derive(
    xkey_dict: BIP32KeyDict, der_path: Path, forced_version: Optional[Octets] = None
) -> BIP32KeyDict:

    indexes, absolute = indexes_from_path(der_path)

    if absolute and xkey_dict["depth"] != 0:
        err_msg = "absolute derivation path for non-root master key"
        raise ValueError(err_msg)

    final_depth = xkey_dict["depth"] + len(indexes)
    if final_depth > 255:
        err_msg = f"derivation path final depth greater than 255: {final_depth}"
        raise ValueError(err_msg)

    if forced_version is not None:
        version = xkey_dict["version"]
        fversion = bytes_from_octets(forced_version, 4)
        if version in _XPRV_VERSIONS_ALL and fversion not in _XPRV_VERSIONS_ALL:
            err_msg = "invalid non-private version forced on a private key: "
            err_msg += f"{hex_string(fversion)}"
            raise ValueError(err_msg)
        if version in _XPUB_VERSIONS_ALL and fversion not in _XPUB_VERSIONS_ALL:
            err_msg = "invalid non-public version forced on a public key: "
            err_msg += f"{hex_string(fversion)}"
            raise ValueError(err_msg)

    is_prv = xkey_dict["key"][0] == 0
    # no idea why mypy does complain about the following cleaner line
    # d = {**xkey_dict, "q": 0, "Q": INF}
    # so, while waiting for the even better python 3.9
    # d = xkey_dict | {"q": 0, "Q": INF}
    # let's make mypy happy with boring code like the following
    d: _ExtendedBIP32KeyDict = {
        "version": xkey_dict["version"],
        "depth": xkey_dict["depth"],
        "parent_fingerprint": xkey_dict["parent_fingerprint"],
        "index": xkey_dict["index"],
        "chain_code": xkey_dict["chain_code"],
        "key": xkey_dict["key"],
        # extensions used for caching of intermediate results
        "q": (int.from_bytes(xkey_dict["key"][1:], byteorder="big") if is_prv else 0),
        "Q": (INF if is_prv else point_from_octets(xkey_dict["key"], ec)),
    }
    for index in indexes:
        __ckd(d, index)
    if forced_version is not None:
        d["version"] = fversion

    return d


def derive(
    xkey: BIP32Key, der_path: Path, forced_version: Optional[Octets] = None
) -> bytes:
    """Derive a BIP32 key across a path spanning multiple depth levels.

    Derivation is according to:

    - absolute derivation path as "m/44h/0'/1H/0/10" string
    - relative derivation path as "./0/10" string
    - relative derivation path as iterable integer indexes
    - relative one level child derivation with single integer index
    - relative one level child derivation with single 4-bytes index

    Path is case/blank/extra-slash insensitive
    (e.g. "M /44h / 0' /1H // 0/ 10 / ").
    """
    d = deserialize(xkey)
    d = _derive(d, der_path, forced_version)
    return serialize(d)


def _derive_from_account(
    d: BIP32KeyDict,
    branch: int,
    address_index: int,
    more_than_two_branches: bool = False,
) -> BIP32KeyDict:

    if more_than_two_branches and branch >= 0x80000000:
        raise ValueError("invalid private derivation at branch level")
    elif branch not in (0, 1):
        raise ValueError(f"invalid branch: {branch} not in (0, 1)")

    if address_index >= 0x80000000:
        raise ValueError("invalid private derivation at address index level")

    if d["index"][0] < 0x80:
        raise UserWarning("public derivation at account level")

    return _derive(d, f"./{branch}/{address_index}")


def derive_from_account(
    account_xkey: BIP32Key,
    branch: int,
    address_index: int,
    more_than_two_branches: bool = False,
) -> bytes:

    d = deserialize(account_xkey)
    d = _derive_from_account(d, branch, address_index, more_than_two_branches)
    return serialize(d)


def crack_prvkey(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> bytes:

    if isinstance(parent_xpub, dict):
        p = copy.copy(parent_xpub)
    else:
        p = deserialize(parent_xpub)

    if p["key"][0] not in (2, 3):
        m = "extended parent key is not a public key: "
        m += f"{serialize(p).decode()}"
        raise ValueError(m)

    c = child_xprv if isinstance(child_xprv, dict) else deserialize(child_xprv)
    if c["key"][0] != 0:
        m = f"extended child key is not a private key: {serialize(c).decode()}"
        raise ValueError(m)

    # check depth
    if c["depth"] != p["depth"] + 1:
        raise ValueError("not a parent's child: wrong depths")

    # check fingerprint
    if c["parent_fingerprint"] != hash160(p["key"])[:4]:
        raise ValueError("not a parent's child: wrong parent fingerprint")

    # check normal derivation
    if c["index"][0] >= 0x80:
        raise ValueError("hardened child derivation")

    p["version"] = c["version"]

    h = hmac.digest(p["chain_code"], p["key"] + c["index"], "sha512")
    child_q = int.from_bytes(c["key"][1:], byteorder="big")
    offset = int.from_bytes(h[:32], byteorder="big")
    parent_q = (child_q - offset) % ec.n
    p["key"] = b"\x00" + parent_q.to_bytes(32, byteorder="big")

    return serialize(p)
