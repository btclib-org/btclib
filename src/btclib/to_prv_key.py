# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The (int, network, compressed) record a private key is filled into.

The scalar itself is not read here: `curves.scalar_from_prv_key` is what
takes an int, its octets or their hex, a scalar in 1..n-1 being a fact
about the curve (issue #1188). What is left to this module is the record
above it, which a scalar carries none of.

A spelling that does carry a network and a compression is read where it
is defined. A WIF is `b58`'s object, read by `b58.prv_key_data_from_wif`
and written by `b58.wif_from_prv_key`; an xprv is `bip32`'s, read by
`bip32.prv_keyinfo_from_xprv`. Neither is reachable from here: `b58` sits
above this module, and an extended key resolved here would be `bip32`'s
format parsed somewhere else.
"""

from __future__ import annotations

from btclib.alias import Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError, NotAPrvKeyError
from btclib.network import network_from_name
from btclib.utils import assert_type, bytes_from_octets

__all__ = [
    "PrvKey",
    "PrvkeyInfo",
    "prv_keyinfo_from_prv_key",
]

# private key inputs: the scalar, as an int or as its octets
PrvKey = int | Octets

# the union at run time, with the buffers bytes_from_octets accepts beside
# bytes. `curves.sec_point._PUB_KEY_TYPES` is the counterpart, and is
# where the int this list holds and that one does not is explained
_PRV_KEY_TYPES = (int, bytes, bytearray, memoryview, str)


def _assert_prv_key_type(prv_key: PrvKey) -> None:
    """Refuse a type no spelling of a private key has.

    `curves.sec_point._assert_pub_key_type`'s twin, and asked for the same
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
