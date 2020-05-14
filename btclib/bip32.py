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
from .utils import bytes_from_octets, hash160


class ExtendedBIP32KeyDict(BIP32KeyDict):
    # extensions used to cache intemediate results
    # in multi-level derivation: do not rely on them elsewhere
    q: int  # non-zero for private key only
    Q: Point  # non-Infinity for public key only


def _check_version_key(version: bytes, key: bytes) -> None:

    if version in _XPRV_VERSIONS_ALL:
        if key[0] != 0:
            raise ValueError("prv_version/pubkey mismatch")
    elif version in _XPUB_VERSIONS_ALL:
        if key[0] not in (2, 3):
            raise ValueError("pub_version/prvkey mismatch")
    else:
        raise ValueError(f"unknown extended key version {version.hex()}")


def _check_depth_pfp_index(depth: int, pfp: bytes, i: bytes) -> None:

    if depth < 0 or depth > 255:
        raise ValueError(f"Invalid BIP32 depth ({depth})")
    elif depth == 0:
        if pfp != b"\x00\x00\x00\x00":
            msg = f"Zero depth with non-zero parent_fingerprint ({pfp.hex()})"
            raise ValueError(msg)
        if i != b"\x00\x00\x00\x00":
            msg = f"Zero depth with non-zero index {i.hex()}"
            raise ValueError(msg)
    else:
        if pfp == b"\x00\x00\x00\x00":
            msg = f"Non-zero depth ({depth}) "
            msg += f"with zero parent_fingerprint ({pfp.hex()})"
            raise ValueError(msg)


def deserialize(xkey: BIP32Key) -> ExtendedBIP32KeyDict:

    d: ExtendedBIP32KeyDict
    if isinstance(xkey, dict):
        # no idea why mypy does complain about the following cleaner line
        # d = {**xkey, "q": 0, "Q": INF}
        # so, while waiting for the even better python 3.9
        # d = xkey | {"q": 0, "Q": INF}
        # let's make mypy happy with boring code like the following
        d = {
            "version": xkey["version"],
            "depth": xkey["depth"],
            "parent_fingerprint": xkey["parent_fingerprint"],
            "index": xkey["index"],
            "chain_code": xkey["chain_code"],
            "key": xkey["key"],
            # extensions
            "q": 0,  # non zero only if xprv
            "Q": INF,  # non INF only if xpub
        }
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
            # extensions
            "q": 0,  # non zero only if xprv
            "Q": INF,  # non INF only if xpub
        }

    _check_version_key(d["version"], d["key"])
    _check_depth_pfp_index(d["depth"], d["parent_fingerprint"], d["index"])

    # calculate d["q"] and d["Q"]
    if d["key"][0] == 0:
        q = int.from_bytes(d["key"][1:], byteorder="big")
        if not 0 < q < ec.n:
            raise ValueError(f"Private key {hex(q).upper()} not in [1, n-1]")
        d["q"] = q
        d["Q"] = INF
    else:  # must be public (already checked by _check_version_key)
        d["q"] = 0
        d["Q"] = point_from_octets(d["key"], ec)

    return d


def serialize(d: BIP32KeyDict) -> bytes:

    if len(d["key"]) != 33:
        m = f"Invalid {len(d['key'])}-bytes BIP32 key length"
        raise ValueError(m)
    # version length is checked in _check_version_key
    _check_version_key(d["version"], d["key"])
    t = d["version"]

    if len(d["parent_fingerprint"]) != 4:
        m = f"Invalid {len(d['parent_fingerprint'])}-bytes "
        m += "BIP32 parent_fingerprint length"
        raise ValueError(m)
    if len(d["index"]) != 4:
        m = f"Invalid {len(d['index'])}-bytes BIP32 index length"
        raise ValueError(m)
    _check_depth_pfp_index(d["depth"], d["parent_fingerprint"], d["index"])
    t += d["depth"].to_bytes(1, "big")
    t += d["parent_fingerprint"]
    t += d["index"]

    if len(d["chain_code"]) != 32:
        m = f"Invalid {len(d['chain_code'])}-bytes BIP32 chain_code length"
        raise ValueError(m)
    t += d["chain_code"]

    # FIXME: it is not really checked
    # already checked in _check_version_key
    t += d["key"]

    return b58encode(t, 78)


def rootxprv_from_seed(seed: Octets, version: Optional[Octets] = None) -> bytes:
    """Return BIP32 root master extended private key from seed."""

    seed = bytes_from_octets(seed)
    hd = hmac.digest(b"Bitcoin seed", seed, "sha512")
    k = b"\x00" + hd[:32]
    if version is None:
        v = NETWORKS["mainnet"]["bip32_prv"]
    else:
        v = bytes_from_octets(version)
    if v not in _XPRV_VERSIONS_ALL:
        raise ValueError(f"unknown extended private key version {v!r}")

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
    mnemonic: Mnemonic, passphrase: str = "", version: Optional[Octets] = None
) -> bytes:
    """Return BIP32 root master extended private key from BIP39 mnemonic."""

    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
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
        raise ValueError(f"Unmanaged electrum mnemonic version ({version})")


def xpub_from_xprv(xprv: BIP32Key) -> bytes:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    if isinstance(xprv, dict):
        xprv = copy.copy(xprv)
    else:
        xprv = deserialize(xprv)

    if xprv["key"][0] != 0:
        raise ValueError(f"Not a private key: {serialize(xprv).decode()}")

    i = _XPRV_VERSIONS_ALL.index(xprv["version"])
    xprv["version"] = _XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xprv["key"][1:], byteorder="big")
    Q = mult(q)
    xprv["key"] = bytes_from_point(Q)

    return serialize(xprv)


def _ckd(d: ExtendedBIP32KeyDict, index: bytes) -> None:

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
            raise ValueError("hardened derivation from pubkey is impossible")
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


def _indexes_from_path(path: str) -> Tuple[List[bytes], bool]:

    steps = [x.strip() for x in path.split("/")]
    if steps[0] in ("m", "M"):
        absolute = True
    elif steps[0] == ".":
        absolute = False
    elif steps[0] == "":
        raise ValueError("Empty derivation path")
    else:
        raise ValueError(f"Invalid derivation path root: {steps[0]}")

    indexes: List[bytes] = list()
    for step in steps[1:]:
        if step == "":  # extra slash
            continue
        elif step[-1] in ("'", "H", "h"):
            index = int(step[:-1]) + 0x80000000
        else:
            index = int(step)
        indexes.append(index.to_bytes(4, "big"))

    if len(indexes) > 255:
        raise ValueError(f"Derivation path depth {len(indexes)}>255")
    return indexes, absolute


def derive(xkey: BIP32Key, path: Path) -> bytes:
    """Derive an extended key across a path spanning multiple depth levels.

    Derivation is according to:

    - absolute path as "m/44h/0'/1H/0/10" string
    - relative path as "./0/10" string
    - relative path as iterable integer indexes
    - relative one level child derivation with single integer index
    - relative one level child derivation with single 4-bytes index

    Path is case/blank/extra-slash insensitive
    (e.g. "M /44h / 0' /1H // 0/ 10 / ").
    """

    xkey = deserialize(xkey)

    if isinstance(path, str):
        path = path.strip()
        indexes, absolute = _indexes_from_path(path)
        if absolute and xkey["depth"] != 0:
            msg = "Absolute derivation path for non-root master key"
            raise ValueError(msg)
    elif isinstance(path, int):
        indexes = [path.to_bytes(4, byteorder="big")]
    elif isinstance(path, bytes):
        if len(path) != 4:
            raise ValueError(f"Index must be 4-bytes, not {len(path)}")
        indexes = [path]
    else:
        indexes = [i.to_bytes(4, byteorder="big") for i in path]

    final_depth = xkey["depth"] + len(indexes)
    if final_depth > 255:
        raise ValueError(f"Derivation path final depth {final_depth}>255")

    for index in indexes:
        _ckd(xkey, index)

    return serialize(xkey)


def crack_prvkey(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> bytes:

    if isinstance(parent_xpub, dict):
        p = copy.copy(parent_xpub)
    else:
        p = deserialize(parent_xpub)

    if p["key"][0] not in (2, 3):
        m = "Extended parent key is not a public key: "
        m += f"{serialize(p).decode()}"
        raise ValueError(m)

    if isinstance(child_xprv, dict):
        c = child_xprv
    else:
        c = deserialize(child_xprv)
    if c["key"][0] != 0:
        m = f"Extended child key is not a private key: "
        m += f"{serialize(c).decode()}"
        raise ValueError(m)

    # check depth
    if c["depth"] != p["depth"] + 1:
        raise ValueError("not a parent's child: wrong depth relation")

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
