# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Functions for conversions between different public key formats."""

from __future__ import annotations

import contextlib

from btclib.alias import Point
from btclib.bip32.bip32 import BIP32Key, BIP32KeyData, _key_data_from_bip32_key
from btclib.curves import (
    Curve,
    bytes_from_point,
    bytes_from_prv_key_int,
    mult,
    point_from_octets,
    secp256k1,
)
from btclib.curves.sec_point import _sec_from_octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import (
    curve_from_xkeyversion,
    network_from_name,
    network_from_xkeyversion,
    xpubversions_from_network,
)
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.utils import bytes_from_octets

__all__ = [
    "Key",
    "PubKey",
    "PubkeyInfo",
    "fingerprint",
    "point_from_key",
    "point_from_pub_key",
    "pub_keyinfo_from_key",
    "pub_keyinfo_from_prv_key",
    "pub_keyinfo_from_pub_key",
]

# public key inputs:
# elliptic curve point as Union[Octets, BIP32Key, Point]
PubKey = bytes | str | BIP32KeyData | Point

# public or private key input,
# usable wherever a PubKey is logically expected
Key = int | bytes | str | BIP32KeyData | Point

# the two unions at run time, with the buffers bytes_from_octets accepts
# beside bytes. An int is in one and not the other on purpose: in this
# library an int is a private key, and never a public one
_PUB_KEY_TYPES = (bytes, bytearray, memoryview, str, BIP32KeyData, tuple)
_KEY_TYPES = (int, *_PUB_KEY_TYPES)


def _assert_pub_key_type(pub_key: PubKey) -> None:
    """Refuse a type no spelling of a public key has.

    Asked at the top of a converter, and not inferred from whichever
    spelling failed last, which is what these two used to do: every
    refusal was a BTClibValueError, so "this key is not on the curve"
    and "this is not a key at all" arrived as one class.

    The difference is what a boolean verification reads, and issue #814
    is where it is stated: `dsa.verify` answers False about a value of a
    declared type and refuses a type it does not declare, exactly as
    `script_pub_key.is_p2sh` does. The union is closed, so the question
    has an answer here; `ssa.point_from_bip340pub_key` ends in this same
    refusal for the same reason.

    Never echo the input: it may be private material passed by mistake,
    which is the very confusion issue #143 is about -- an int is a
    private key here, so it is refused as a type rather than reported as
    a public key that does not verify.
    """
    if not isinstance(pub_key, _PUB_KEY_TYPES):
        raise BTClibTypeError("not a public key")


def _assert_key_type(key: Key) -> None:
    """Refuse a type no spelling of a key has, private or public.

    `_assert_pub_key_type`'s wider twin, for the converters that take
    either: an int is a private key, and the two lists differ by it.
    """
    if not isinstance(key, _KEY_TYPES):
        raise BTClibTypeError("not a private or public key")


def _point_from_xpub(xpub: BIP32Key, ec: Curve) -> Point:
    """Return an elliptic curve point tuple from a xpub key."""
    xpub = _key_data_from_bip32_key(xpub)

    if xpub.is_private:
        # never echo the key, which is private here:
        # the prefix already says what is wrong
        raise BTClibValueError(f"not a public key: prefix 0x{xpub.key[:1].hex()}")
    ec2 = curve_from_xkeyversion(xpub.version)
    if ec != ec2:
        raise BTClibValueError(f"ec/xpub version ({xpub.version.hex()}) mismatch")
    return point_from_octets(xpub.key, ec)


def point_from_key(key: Key, ec: Curve = secp256k1) -> Point:
    """Return a point tuple from any possible key representation.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """
    _assert_key_type(key)

    if isinstance(key, tuple):
        return point_from_pub_key(key, ec)
    if isinstance(key, int):
        q, _, _ = prv_keyinfo_from_prv_key(key)
        return mult(q, ec.G, ec)
    try:
        q, net, _ = prv_keyinfo_from_prv_key(key)
    except BTClibValueError:
        pass
    else:
        if ec != network_from_name(net).curve:
            raise BTClibValueError("Curve mismatch")
        return mult(q, ec.G, ec)

    return point_from_pub_key(key, ec)


def point_from_pub_key(pub_key: PubKey, ec: Curve = secp256k1) -> Point:
    """Return an elliptic curve point tuple from a public key."""
    _assert_pub_key_type(pub_key)

    if isinstance(pub_key, tuple):
        if ec.is_on_curve(pub_key) and pub_key[1] != 0:
            return pub_key[0], pub_key[1]
        raise BTClibValueError(f"not a valid public key: {pub_key}")
    if isinstance(pub_key, BIP32KeyData):
        return _point_from_xpub(pub_key, ec)
    with contextlib.suppress(TypeError, BTClibValueError):
        return _point_from_xpub(pub_key, ec)
    # it must be octets
    try:
        return point_from_octets(pub_key, ec)
    except (TypeError, ValueError) as e:
        # never echo the input: it may be private material passed by
        # mistake; the chained exception carries the parsing reason
        raise BTClibValueError("not a public key") from e


# public key bytes representation, network
PubkeyInfo = tuple[bytes, str]


def _pub_keyinfo_from_xpub(
    xpub: BIP32Key, network: str | None, compressed: bool | None
) -> PubkeyInfo:
    """Return the pub_key tuple (SEC-bytes, network) from a BIP32 xpub.

    BIP32Key is always compressed and includes network information: here
    the 'network, compressed' input parameters are passed only to allow
    consistency checks.
    """
    compressed = True if compressed is None else compressed
    if not compressed:
        raise BTClibValueError("Uncompressed SEC / compressed BIP32 mismatch")

    xpub = _key_data_from_bip32_key(xpub)

    if xpub.key[0] not in {2, 3}:
        # this branch is reached with an xprv: never echo it,
        # the prefix already says what is wrong
        err_msg = f"not a public key: prefix 0x{xpub.key[:1].hex()}"
        raise BTClibValueError(err_msg)

    if network is None:
        return xpub.key, network_from_xkeyversion(xpub.version)

    allowed_versions = xpubversions_from_network(network)
    if xpub.version not in allowed_versions:
        # an xpub is not funds-critical, but it derives all child pub
        # keys: keep it out of exception messages (and logs) too
        err_msg = f"Not a {network} key: version 0x{xpub.version.hex()}"
        raise BTClibValueError(err_msg)

    return xpub.key, network


def pub_keyinfo_from_key(
    key: Key, network: str | None = None, compressed: bool | None = None
) -> PubkeyInfo:
    """Return the pub key tuple (SEC-bytes, network) from a pub/prv key."""
    _assert_key_type(key)

    if isinstance(key, tuple):
        return pub_keyinfo_from_pub_key(key, network, compressed)
    if isinstance(key, int):
        return pub_keyinfo_from_prv_key(key, network, compressed)
    with contextlib.suppress(BTClibValueError):
        return pub_keyinfo_from_pub_key(key, network, compressed)
    # it must be a prv_key
    try:
        return pub_keyinfo_from_prv_key(key, network, compressed)
    except BTClibValueError as e:
        err_msg = _err_msg(key, network, compressed)
        raise BTClibValueError(err_msg) from e


def _err_msg(key: Key, network: str | None, compressed: bool | None) -> str:
    # never echo the key: it may well be private material
    # (e.g. an xprv or WIF on the wrong network)
    err_msg = "not a private or"
    if compressed is not None:
        err_msg += " compressed" if compressed else " uncompressed"
    err_msg += " public key"
    if network is not None:
        err_msg += f" for {network}"
    return err_msg


def pub_keyinfo_from_pub_key(
    pub_key: PubKey, network: str | None = None, compressed: bool | None = None
) -> PubkeyInfo:
    """Return the pub key tuple (SEC-bytes, network) from a public key."""
    _assert_pub_key_type(pub_key)

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = network_from_name(net).curve

    if isinstance(pub_key, tuple):
        return bytes_from_point(pub_key, ec, compr), net
    if isinstance(pub_key, BIP32KeyData):
        return _pub_keyinfo_from_xpub(pub_key, network, compressed)
    with contextlib.suppress(TypeError, BTClibValueError):
        return _pub_keyinfo_from_xpub(pub_key, network, compressed)
    # it must be octets, and compressed is a filter on which form they may
    # be in rather than a conversion to it: the size below is required of
    # the input, so octets that pass come back in the form they came in
    try:
        if compressed is None:
            pub_key = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))
        else:
            size = ec.p_size + 1 if compressed else 2 * ec.p_size + 1
            pub_key = bytes_from_octets(pub_key, size)
    except (TypeError, ValueError) as e:
        # never echo the input: it may be private material passed by
        # mistake; the chained exception carries the parsing reason
        raise BTClibValueError("not a public key") from e

    # verify that it is a valid point, which is all there is left to do
    return _sec_from_octets(pub_key, ec), net


def pub_keyinfo_from_prv_key(
    prv_key: PrvKey, network: str | None = None, compressed: bool | None = None
) -> PubkeyInfo:
    """Return the pub key tuple (SEC-bytes, network) from a private key."""
    q, net, compr = prv_keyinfo_from_prv_key(prv_key, network, compressed)
    ec = network_from_name(net).curve
    return bytes_from_prv_key_int(q, ec, compr), net


def fingerprint(key: Key, network: str | None = None) -> bytes:
    """Return the public key fingerprint from a private/public key.

    The fingerprint is the first four bytes of the compressed public key
    HASH160, which is what BIP32 defines it as.
    """
    pub_key, _ = pub_keyinfo_from_key(key, network, compressed=True)
    return hash160(pub_key)[:4]
