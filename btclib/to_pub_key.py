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
    PreparedPoint,
    bytes_from_point,
    bytes_from_prv_key_int,
    mult,
    point_from_octets,
    secp256k1,
)
from btclib.curves.curve import _assert_valid_ec
from btclib.curves.sec_point import _sec_from_octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import (
    curve_from_xkeyversion,
    network_from_name,
    network_from_xkeyversion,
    xpubversions_from_network,
)
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "Key",
    "PubKey",
    "PubkeyInfo",
    "point_from_key",
    "point_from_pub_key",
    "pub_keyinfo_from_key",
    "pub_keyinfo_from_prv_key",
    "pub_keyinfo_from_pub_key",
]

# public key inputs:
# elliptic curve point as Union[Octets, BIP32Key, Point, PreparedPoint]
PubKey = bytes | str | BIP32KeyData | Point | PreparedPoint

# public or private key input,
# usable wherever a PubKey is logically expected
Key = int | bytes | str | BIP32KeyData | Point | PreparedPoint

# the two unions at run time, with the buffers bytes_from_octets accepts
# beside bytes. An int is in one and not the other on purpose: in this
# library an int is a private key, and never a public one
_PUB_KEY_TYPES = (bytes, bytearray, memoryview, str, BIP32KeyData, tuple, PreparedPoint)
_KEY_TYPES = (int, *_PUB_KEY_TYPES)


# **A prepared point is read as the point it holds, everywhere below.**
# `curves.PreparedPoint` is a `Point` plus a caller's word that it will
# be multiplied again, and the word is the whole of the difference: an
# address and a SEC encoding are the point's, so each converter answers
# a prepared point by asking itself about `.point`.
# What is *not* the point's is the memoized tables, and
# `dsa.assert_as_valid_` and `ssa.assert_as_valid_` are the two places
# that read those, off the object and not through here.
#
# Spelled as a one-line recursion at each site that unwraps one, rather
# than as one unwrapping helper, and the types are why: a helper would
# have to answer the union it was given minus PreparedPoint, a
# different union per converter and two overloads to keep in step,
# where re-asking the same function is exactly as narrow as the
# function already is.
#
# Nothing compares a curve on the way through: a prepared point of
# another curve fails the `is_on_curve` its tuple then faces, exactly as
# a bare `Point` of that curve does and with the same message.


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

    A bool is named here for the sentence and not for the refusal: with
    the line dropped it still does not become a key, `to_prv_key`'s own
    gate refusing it one frame down. What it draws there is "not a
    private key", which is half the union -- where a float, a None and
    anything else of no key type are refused here and told so. So this
    line is what makes a bool answer like the rest of them, and
    `tests/integer_policy_test.py` pins it by its wording, there being
    no outcome to pin (issue #1206).
    """
    if isinstance(key, bool) or not isinstance(key, _KEY_TYPES):
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
    # as in `point_from_pub_key` below and `to_prv_key.int_from_prv_key`:
    # a WIF is compared against the curve rather than parsed with it, and
    # an ec of no curve type compares unequal to every network's, which is
    # "Curve mismatch" for what is a caller's own mistake
    _assert_valid_ec(ec)
    _assert_key_type(key)
    if isinstance(key, PreparedPoint):
        return point_from_key(key.point, ec)

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
    _assert_valid_ec(ec)
    _assert_pub_key_type(pub_key)
    if isinstance(pub_key, PreparedPoint):
        return point_from_pub_key(pub_key.point, ec)

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
    if isinstance(key, PreparedPoint):
        return pub_keyinfo_from_key(key.point, network, compressed)

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


def _sec_from_key(key: Key) -> bytes:
    """Return the SEC octets of a public or private key, unproven.

    `_sec_from_pub_key` for a caller that takes both, and the same trade:
    the octets are not proved a point here, because what they are handed
    to proves them -- `script.taproot` is the caller, and
    `xonly.tweak_add` is the parse that would otherwise be the second
    lift of one x.

    What that costs is which refusal a caller sees for octets of the right
    size that are no point: `pub_keyinfo_from_key` reads them as a public
    key, fails to prove one, and tries them as a private key, so the
    message names both; here the call this feeds refuses them as the
    public key they were meant to be. Neither is a key, and the second
    says so more nearly.
    """
    _assert_key_type(key)
    if isinstance(key, PreparedPoint):
        return _sec_from_key(key.point)
    if isinstance(key, tuple):
        return _sec_from_pub_key(key)
    if isinstance(key, int):
        return pub_keyinfo_from_prv_key(key)[0]
    with contextlib.suppress(BTClibValueError):
        return _sec_from_pub_key(key)
    try:
        return pub_keyinfo_from_prv_key(key)[0]
    except BTClibValueError as e:
        raise BTClibValueError(_err_msg(key, None, None)) from e


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
    (sec, net), to_prove = _pub_keyinfo_from_pub_key(pub_key, network, compressed)
    if not to_prove:
        return sec, net
    # verify that it is a valid point, which is all there is left to do
    return _sec_from_octets(sec, network_from_name(net).curve), net


def _sec_from_pub_key(pub_key: PubKey) -> bytes:
    """Return the SEC octets of a public key, unproven, however spelled.

    `pub_keyinfo_from_pub_key` proves the octets a point of the curve --
    for a compressed key a field square root -- and a caller going on to
    verify a signature under them, or to tweak a taproot key with them,
    hands them to a call whose own parse is that same proof: the two
    together lift one x twice, which is issue 887.

    So this is that conversion with the proof left out, and it is private
    because the guarantee is the caller's to complete: whatever these
    octets are handed to is what refuses a key that is no point, and it is
    the caller that turns the `ValueError` into btclib's own.

    A `Point` comes back uncompressed, which is the cheap form to parse --
    0.26 us against the 2.34 of a compressed key, both coordinates being
    there to read -- where `pub_keyinfo_from_pub_key` answers the
    compressed one, `compressed=None` meaning "whatever the key says" and
    a point saying nothing. No network and no compressed filter either,
    which is what the callers ask for: a verification takes the key as the
    key says it is, and the curve it is asked about is the signature's.
    """
    if isinstance(pub_key, PreparedPoint):
        return _sec_from_pub_key(pub_key.point)
    if isinstance(pub_key, tuple):
        # bytes_from_point is btclib's own arithmetic and not a parse: it
        # refuses what is not a point of the curve, and infinity
        return bytes_from_point(pub_key, secp256k1, False)
    return _pub_keyinfo_from_pub_key(pub_key, None, None)[0][0]


def _pub_keyinfo_from_pub_key(
    pub_key: PubKey, network: str | None, compressed: bool | None
) -> tuple[PubkeyInfo, bool]:
    """Return the pub key tuple, and whether it is still to be proved a point.

    The body of `pub_keyinfo_from_pub_key`, and of `_sec_from_pub_key`
    above: the dispatch over the spellings of a public key stays written
    once, and the two differ in what they do with the answer.

    True for octets, which arrive unproven and are proved by the public
    spelling; False for a `Point`, which `bytes_from_point` has just
    refused if it was not one, and for an extended key, whose 33 octets
    are validated as a BIP32 key rather than as a point -- neither has a
    proof left for a caller to make, and neither is one this would add.
    """
    _assert_pub_key_type(pub_key)
    if isinstance(pub_key, PreparedPoint):
        return _pub_keyinfo_from_pub_key(pub_key.point, network, compressed)
    # as in `to_prv_key.prv_keyinfo_from_prv_key`: None means "whatever
    # the key says", and every other spelling of a truth is refused
    if compressed is not None:
        assert_type(compressed, bool, "compressed")

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = network_from_name(net).curve

    if isinstance(pub_key, tuple):
        return (bytes_from_point(pub_key, ec, compr), net), False
    if isinstance(pub_key, BIP32KeyData):
        return _pub_keyinfo_from_xpub(pub_key, network, compressed), False
    with contextlib.suppress(TypeError, BTClibValueError):
        return _pub_keyinfo_from_xpub(pub_key, network, compressed), False
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

    return (pub_key, net), True


def pub_keyinfo_from_prv_key(
    prv_key: PrvKey, network: str | None = None, compressed: bool | None = None
) -> PubkeyInfo:
    """Return the pub key tuple (SEC-bytes, network) from a private key."""
    q, net, compr = prv_keyinfo_from_prv_key(prv_key, network, compressed)
    ec = network_from_name(net).curve
    return bytes_from_prv_key_int(q, ec, compr), net
