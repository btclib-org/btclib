# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Functions for conversions between different private key formats.

A WIF is not among the formats: it is `b58`'s object, read by
`b58.prv_key_data_from_wif` and written by `b58.wif_from_prv_key`, and
this module -- which `b58` imports through `to_pub_key` -- has no way to
reach a parser living there (issue #1188).
"""

from __future__ import annotations

from btclib.alias import Octets
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _key_data_from_bip32_key,
    _prv_keyinfo_from_xprv,
)
from btclib.curves import Curve, secp256k1
from btclib.curves.curve import _assert_valid_ec
from btclib.exceptions import BTClibTypeError, BTClibValueError, NotAPrvKeyError
from btclib.network import network_from_name
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "PrvKey",
    "PrvkeyInfo",
    "int_from_prv_key",
    "prv_keyinfo_from_prv_key",
]

# private key inputs:
# integer as Union[int, Octets]
# BIP32key as BIP32Key
#
# BIP32key also provides extra info about
# network and (un)compressed-pub_key-derivation
PrvKey = int | Octets | BIP32KeyData

# the union at run time, with the buffers bytes_from_octets accepts beside
# bytes. `to_pub_key._PUB_KEY_TYPES` is the counterpart, and is where the
# int this list holds and that one does not is explained
_PRV_KEY_TYPES = (int, bytes, bytearray, memoryview, str, BIP32KeyData)


def _assert_prv_key_type(prv_key: PrvKey) -> None:
    """Refuse a type no spelling of a private key has.

    `to_pub_key._assert_pub_key_type`'s twin, and asked for the same
    reason: a type the union does not declare is the caller's own
    mistake, where a value of a declared type that is no key is a
    NotAPrvKeyError -- "wrong format, try the next one", which is what
    the guessing below is for. Without this the two would be one class:
    a float reported as "not a private key: not a BIP32 xkey (...); not
    octets (...)", every format tried against a value no format could
    have held.

    A bool is refused here rather than answered as the number one.
    `utils.is_integer` is where that rule is stated -- issue #326 gave it
    to the fields of this library whose contract is an integer quantity,
    and `int_from_integer` carries it for every `Integer` parameter. A
    `PrvKey` is not one of those: the int branch below takes the value as
    it comes rather than coercing it, so this line and not
    `int_from_integer` is what refuses a bool spelled as a `PrvKey`
    (issue #1206). What made it worth a refusal there makes it worth one
    here and more so: `true` decodes from json to `True`, and a key of
    one is a key an attacker knows.

    Never echo the input, every message in this module being about
    candidate key material.
    """
    if isinstance(prv_key, bool) or not isinstance(prv_key, _PRV_KEY_TYPES):
        raise BTClibTypeError("not a private key")


def int_from_prv_key(prv_key: PrvKey, ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - integer (native int or hex-string)

    Network and compressed information from the input key
    are not used.
    """
    # before the key, because every branch below reaches the curve: an
    # xprv is compared against it rather than parsed with it, and an ec
    # of no curve type compares unequal to every network's -- which is
    # "ec / network mismatch" for what is a caller's own mistake
    _assert_valid_ec(ec)
    _assert_prv_key_type(prv_key)

    if isinstance(prv_key, int):
        q = prv_key
    elif isinstance(prv_key, BIP32KeyData):
        q, network, _ = _prv_keyinfo_if_xprv(prv_key, None, None)
        # q has been validated on the xprv network
        return _q_if_network_and_ec_match(q, network, ec)
    else:
        reasons = []
        try:
            q, network, _ = _prv_keyinfo_if_xprv(prv_key, None, None)
        except NotAPrvKeyError as e:
            # an InvalidPrvKeyError is not caught: the format was
            # recognised, so trying the input as octets and reporting "not
            # a private key" would replace the answer with a worse one
            reasons.append(str(e))
        else:
            # q has been validated on the xprv network
            return _q_if_network_and_ec_match(q, network, ec)
        # it must be octets
        try:
            prv_key = bytes_from_octets(prv_key, ec.n_size)
            q = int.from_bytes(prv_key, "big")
        # both, as `to_pub_key` catches both here: what is neither octets
        # nor a spelling of them is a TypeError, and it means the same
        # thing as a wrong size does -- this input is not a private key
        except (TypeError, ValueError) as e:
            # never echo the input: it is candidate key material. What the
            # reasons carry is why each format rejected it -- a checksum, a
            # prefix, a size -- none of which is secret
            reasons.append(f"not octets ({e})")
            raise NotAPrvKeyError("not a private key: " + "; ".join(reasons)) from e

    # libsecp256k1's keys.prvkey_verify is the C answer to this check,
    # here and at the two other sites in this module, and it is not called
    # for want of anything to gain: the foreign call costs more than the
    # comparison it would replace, on a value that is already a Python
    # int, and no constant-time argument to pay it with, since whether a
    # key is in
    # range is precisely what the caller is being told. The comparison
    # also serves every curve, where the binding is secp256k1 alone.
    if not 0 < q < ec.n:
        raise BTClibValueError("private key not in 1..n-1")

    return q


def _q_if_network_and_ec_match(q: int, network: str, ec: Curve) -> int:
    # q has been validated on the xprv network
    ec2 = network_from_name(network).curve
    if ec != ec2:
        raise BTClibValueError(f"ec / network ({network}) mismatch")
    return q


PrvkeyInfo = tuple[int, str, bool]


def _prv_keyinfo_if_xprv(
    xprv: BIP32Key, network: str | None, compressed: bool | None
) -> PrvkeyInfo:
    """Return `bip32.prv_keyinfo_from_xprv`, or say it is another format.

    The parse is bip32's and the guessing is this module's, which is the
    whole of what this adds: base58, 78 bytes, and a known xkey version
    or not -- a negative answer leaves the input free to be octets or an
    int, so it is NotAPrvKeyError, carrying the reason rather than
    discarding it. A fault inside a key that did decode is an
    InvalidPrvKeyError and stops the guessing, which is why the decode
    and not the whole call is what is caught here.

    Both classes on the decode, as everywhere a format is guessed here: a
    type the decode refuses says this is not an xkey, not that the caller
    is owed a TypeError from inside the guessing.

    `bip32._prv_keyinfo_from_xprv` and not the public spelling beside it:
    the decode above is the validation that one makes, and asking for it
    again validates the key a second time. An xpub decodes here and is
    declined a frame later, and `_assert_valid_key`'s on-curve test is
    most of what validating one costs.
    """
    if isinstance(xprv, BIP32KeyData):
        # the caller has already committed to the format by building one
        key_data = _key_data_from_bip32_key(xprv)
    else:
        try:
            key_data = _key_data_from_bip32_key(xprv)
        except (TypeError, ValueError) as e:
            raise NotAPrvKeyError(f"not a BIP32 xkey ({e})") from e

    return _prv_keyinfo_from_xprv(key_data, network, compressed)


def prv_keyinfo_from_prv_key(
    prv_key: PrvKey, network: str | None = None, compressed: bool | None = None
) -> PrvkeyInfo:
    """Return (int key, network, compressed) from a private key spelling.

    An xprv carries its own network and compression, and a contradicting
    argument is refused rather than overridden; an int or octets carry
    neither, so the arguments -- mainnet, compressed -- fill in. A WIF
    carries both too, and is `b58.prv_key_data_from_wif`'s to read.
    """
    _assert_prv_key_type(prv_key)
    # None is a declared value here and means "whatever the key says", so
    # it is the one non-bool this position takes
    if compressed is not None:
        assert_type(compressed, bool, "compressed")

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = network_from_name(net).curve

    if isinstance(prv_key, int):
        q = prv_key
    elif isinstance(prv_key, BIP32KeyData):
        return _prv_keyinfo_if_xprv(prv_key, network, compressed)
    else:
        reasons = []
        # NotAPrvKeyError only, letting an InvalidPrvKeyError through
        try:
            return _prv_keyinfo_if_xprv(prv_key, network, compressed)
        except NotAPrvKeyError as e:
            reasons.append(str(e))
        # it must be octets
        try:
            prv_key = bytes_from_octets(prv_key, ec.n_size)
            q = int.from_bytes(prv_key, byteorder="big", signed=False)
        except (TypeError, ValueError) as e:
            # never echo the input: it is candidate key material. The
            # reasons say why each format rejected it, and none of them is
            # secret
            reasons.append(f"not octets ({e})")
            raise NotAPrvKeyError("not a private key: " + "; ".join(reasons)) from e

    if not 0 < q < ec.n:
        raise BTClibValueError("private key not in 1..n-1")

    return q, net, compr
