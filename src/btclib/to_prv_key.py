# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Functions for conversions between different private key formats.

The formats are the scalar and its octets, and a spelling that carries
more than a scalar is read where it is defined. A WIF is `b58`'s object,
read by `b58.prv_key_data_from_wif` and written by
`b58.wif_from_prv_key`; an xprv is `bip32`'s, read by
`bip32.prv_keyinfo_from_xprv`. Neither is reachable from here: `b58` sits
above this module, and an extended key resolved here would be `bip32`'s
format parsed somewhere else (issue #1188).
"""

from __future__ import annotations

from btclib.alias import Octets
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

# private key inputs: the scalar, as an int or as its octets
PrvKey = int | Octets

# the union at run time, with the buffers bytes_from_octets accepts beside
# bytes. `to_pub_key._PUB_KEY_TYPES` is the counterpart, and is where the
# int this list holds and that one does not is explained
_PRV_KEY_TYPES = (int, bytes, bytearray, memoryview, str)


def _assert_prv_key_type(prv_key: PrvKey) -> None:
    """Refuse a type no spelling of a private key has.

    `to_pub_key._assert_pub_key_type`'s twin, and asked for the same
    reason: a type the union does not declare is the caller's own
    mistake, where a value of a declared type that is no key is a
    NotAPrvKeyError. Without this the two would be one class: a float
    reported as "not a private key: not octets (...)", a format tried
    against a value no format could have held.

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

    It supports the scalar as a native int, and as the `ec.n_size`
    octets or hex-string of one.
    """
    # before the key, because the branches below reach the curve for the
    # size they require and for the range they check
    _assert_valid_ec(ec)
    _assert_prv_key_type(prv_key)

    if isinstance(prv_key, int):
        q = prv_key
    else:
        try:
            prv_key = bytes_from_octets(prv_key, ec.n_size)
            q = int.from_bytes(prv_key, "big")
        # both, as `to_pub_key` catches both here: what is neither octets
        # nor a spelling of them is a TypeError, and it means the same
        # thing as a wrong size does -- this input is not a private key
        except (TypeError, ValueError) as e:
            # never echo the input: it is candidate key material. What the
            # reason carries is why the format rejected it -- a size, a
            # character outside hex -- which is not secret
            raise NotAPrvKeyError(f"not a private key: not octets ({e})") from e

    # libsecp256k1's keys.prvkey_verify is the C answer to this check,
    # here and at the other site in this module, and it is not called
    # for want of anything to gain: the foreign call costs more than the
    # comparison it would replace, on a value that is already a Python
    # int, and no constant-time argument to pay it with, since whether a
    # key is in
    # range is precisely what the caller is being told. The comparison
    # also serves every curve, where the binding is secp256k1 alone.
    if not 0 < q < ec.n:
        raise BTClibValueError("private key not in 1..n-1")

    return q


PrvkeyInfo = tuple[int, str, bool]


def prv_keyinfo_from_prv_key(
    prv_key: PrvKey, network: str | None = None, compressed: bool | None = None
) -> PrvkeyInfo:
    """Return (int key, network, compressed) from a private key spelling.

    A scalar carries neither a network nor a compression, so the
    arguments -- mainnet, compressed -- are what the record is filled in
    with rather than checked against. The two spellings that carry both
    are read where they are defined: a WIF by
    `b58.prv_key_data_from_wif`, an xprv by `bip32.prv_keyinfo_from_xprv`.
    """
    _assert_prv_key_type(prv_key)
    # None is a declared value here and means "the default", so it is the
    # one non-bool this position takes
    if compressed is not None:
        assert_type(compressed, bool, "compressed")

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = network_from_name(net).curve

    if isinstance(prv_key, int):
        q = prv_key
    else:
        try:
            prv_key = bytes_from_octets(prv_key, ec.n_size)
            q = int.from_bytes(prv_key, byteorder="big", signed=False)
        except (TypeError, ValueError) as e:
            # never echo the input: it is candidate key material. The
            # reason says why the format rejected it, and it is not secret
            raise NotAPrvKeyError(f"not a private key: not octets ({e})") from e

    if not 0 < q < ec.n:
        raise BTClibValueError("private key not in 1..n-1")

    return q, net, compr
