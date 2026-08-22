# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Functions for conversions between different private key formats."""

from __future__ import annotations

from btclib.alias import Octets, String
from btclib.base58 import decode as b58decode
from btclib.bip32.bip32 import BIP32Key, BIP32KeyData, _key_data_from_bip32_key
from btclib.curves import Curve, secp256k1
from btclib.curves.curve import _assert_valid_ec
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    InvalidPrvKeyError,
    NotAPrvKeyError,
)
from btclib.network import (
    network_from_key_value,
    network_from_name,
    network_from_xkeyversion,
    xprvversions_from_network,
)
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
# WIF as String
#
# BIP32key and WIF also provide extra info about
# network and (un)compressed-pub_key-derivation
PrvKey = int | Octets | BIP32KeyData

# the union at run time, with the buffers bytes_from_octets accepts beside
# bytes. `to_pub_key._PUB_KEY_TYPES` is the same list plus a Point and
# minus nothing: a public key can be a point, a private key cannot
_PRV_KEY_TYPES = (int, bytes, bytearray, memoryview, str, BIP32KeyData)


def _assert_prv_key_type(prv_key: PrvKey) -> None:
    """Refuse a type no spelling of a private key has.

    `to_pub_key._assert_pub_key_type`'s twin, and asked for the same
    reason: a type the union does not declare is the caller's own
    mistake, where a value of a declared type that is no key is a
    NotAPrvKeyError -- "wrong format, try the next one", which is what
    the guessing below is for. Without this the two were one class: a
    float was reported as "not a private key: not a WIF (...); not a
    BIP32 xkey (...); not octets (...)", three formats tried against a
    value no format could have held.

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

    - WIF (bytes or string)
    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - integer (native int or hex-string)

    Network and compressed information from the input key
    are not used.
    """
    # before the key, because every branch below reaches the curve: an
    # xprv or a WIF is compared against it rather than parsed with it, and
    # an ec of no curve type compares unequal to every network's -- which
    # is "ec / network mismatch" for what is a caller's own mistake
    _assert_valid_ec(ec)
    _assert_prv_key_type(prv_key)

    if isinstance(prv_key, int):
        q = prv_key
    elif isinstance(prv_key, BIP32KeyData):
        q, network, _ = _prv_keyinfo_from_xprv(prv_key, None, None)
        # q has been validated on the xprv/wif network
        return _q_if_network_and_ec_match(q, network, ec)
    else:
        reasons = []
        try:
            q, network, _ = _prv_keyinfo_from_xprvwif(prv_key, None, None)
        except NotAPrvKeyError as e:
            # an InvalidPrvKeyError is not caught: the format was
            # recognised, so trying the input as octets and reporting "not
            # a private key" would replace the answer with a worse one
            reasons.append(str(e))
        else:
            # q has been validated on the xprv/wif network
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
    # for want of anything to gain: 0.11 us against the 0.024 of the
    # comparison, on a value that is already a Python int, and no
    # constant-time argument to pay it with, since whether a key is in
    # range is precisely what the caller is being told. The comparison
    # also serves every curve, where the binding is secp256k1 alone.
    if not 0 < q < ec.n:
        raise BTClibValueError("private key not in 1..n-1")

    return q


def _q_if_network_and_ec_match(q: int, network: str, ec: Curve) -> int:
    # q has been validated on the xprv/wif network
    ec2 = network_from_name(network).curve
    if ec != ec2:
        raise BTClibValueError(f"ec / network ({network}) mismatch")
    return q


PrvkeyInfo = tuple[int, str, bool]


def _wif_network(prefix: bytes, network: str | None) -> str:
    """Return the network a WIF version prefix belongs to.

    NotAPrvKeyError for a prefix no network claims: the input is not a
    WIF, and the format-guessing caller is free to try it as octets or
    as an int. InvalidPrvKeyError once a network has claimed it and the
    caller asked for another one: that is a WIF, and the wrong one.
    """
    net = network_from_key_value("wif", prefix)
    if net is None:
        raise NotAPrvKeyError(f"not a WIF (invalid prefix 0x{prefix.hex()})")

    if network is None:
        return net

    # the forward check, and not a `net != network` name comparison:
    # the reverse lookup answers "testnet" for the 0xef that testnet,
    # regtest, signet and testnet4 all use, so comparing names would
    # reject a signet WIF as "not a signet wif: prefix 0xef" --
    # naming the very prefix signet asks for (issue #207).
    # _prv_keyinfo_from_xprv below makes the same membership check
    if prefix != network_from_name(network).wif:
        raise InvalidPrvKeyError(f"not a {network} wif: prefix 0x{prefix.hex()}")
    # the declared network, not the lookup's guess: for a caller who
    # said "signet" the answer is signet, and it is the one that ends
    # up in the returned tuple
    return network


def _wif_prv_key_and_compression(
    payload: bytes, n_size: int, compressed: bool | None
) -> tuple[bytes, bool]:
    """Return the key bytes of a WIF payload, and whether it is compressed.

    The size is what says which of the two it is, the compressed
    spelling carrying one byte more; the caller's `compressed`, if it
    said anything, then has to agree with the answer.
    """
    if len(payload) == n_size + 2:  # compressed WIF
        compr = True
        if payload[-1] != 0x01:  # must have a trailing 0x01
            raise InvalidPrvKeyError("not a compressed WIF: missing trailing 0x01")
        prv_key = payload[1:-1]
    elif len(payload) == n_size + 1:  # uncompressed WIF
        compr = False
        prv_key = payload[1:]
    else:
        raise InvalidPrvKeyError(f"wrong WIF size: {len(payload)}")

    if compressed is not None and compr != compressed:
        raise InvalidPrvKeyError("compression requirement mismatch")

    return prv_key, compr


def _prv_keyinfo_from_wif(
    wif: String, network: str | None, compressed: bool | None
) -> PrvkeyInfo:
    """Return private key tuple(int, compressed, network) from a WIF.

    WIF is always compressed and includes network information: here the
    'network, compressed' input parameters are passed only to allow
    consistency checks.

    The two helpers below are the two questions in refusal order, and
    the order is what the error types are about: everything up to and
    including the version prefix answers "is this a WIF at all", and
    everything after it answers "is this WIF sound".
    """
    if isinstance(wif, str):
        wif = wif.strip()

    # base58 or not is the first question, and a negative answer leaves the
    # input free to be octets or an int: NotAPrvKeyError, carrying the
    # reason, so a mistyped WIF is reported as the bad checksum it is
    # instead of being swallowed. None of the messages in this function
    # echoes the input, which is candidate key material -- a checksum, a
    # prefix and a size are not secret.
    #
    # both classes, as the octets branch of the two public converters
    # catches both: what is neither a base58 string nor bytes is a
    # TypeError, and it means here what a bad checksum means -- this input
    # is not a WIF, and the caller is free to try it as something else
    try:
        payload = b58decode(wif)
    except (TypeError, ValueError) as e:
        raise NotAPrvKeyError(f"not a WIF ({e})") from e

    # from here on the version prefix says WIF, so a fault in what follows
    # is a fault in a WIF: InvalidPrvKeyError, which the format-guessing
    # callers let through instead of trying the input as something else
    net = _wif_network(payload[:1], network)
    ec = network_from_name(net).curve
    prv_key, compr = _wif_prv_key_and_compression(payload, ec.n_size, compressed)

    q = int.from_bytes(prv_key, byteorder="big")
    if not 0 < q < ec.n:
        raise InvalidPrvKeyError("private key not in 1..n-1")

    return q, net, compr


def _prv_keyinfo_from_xprv(
    xprv: BIP32Key, network: str | None, compressed: bool | None
) -> PrvkeyInfo:
    """Return prv_key tuple (int, compressed, network) from BIP32 xprv.

    BIP32Key is always compressed and includes network information: here
    the 'network, compressed' input parameters are passed only to allow
    consistency checks.
    """
    if isinstance(xprv, BIP32KeyData):
        # the caller has already committed to the format by building one
        xprv = _key_data_from_bip32_key(xprv)
    else:
        # base58, 78 bytes, and a known xkey version or not: a negative
        # answer leaves the input free to be octets or an int, so it is
        # NotAPrvKeyError, carrying the reason rather than discarding it.
        # Both classes, as everywhere a format is guessed here: a type the
        # decode refuses says this is not an xkey, not that the caller is
        # owed a TypeError from inside the guessing
        try:
            xprv = _key_data_from_bip32_key(xprv)
        except (TypeError, ValueError) as e:
            raise NotAPrvKeyError(f"not a BIP32 xkey ({e})") from e

    # a BIP32 key is always compressed, so a caller asking for uncompressed
    # is asking about another format. This follows the decode rather than
    # preceding it: for a str or bytes input the decode is what decides
    # whether there is an xkey here at all, and 32 raw bytes with
    # compressed=False are octets -- which the guessing callers must
    # stay free to try, or every uncompressed SEC key stops resolving
    if compressed is not None and not compressed:
        raise InvalidPrvKeyError("uncompressed SEC / compressed BIP32 mismatch")

    # from here it is an xkey, so what follows is a fault in one
    if xprv.key[0] != 0:
        # the offending key is public here, but never echo a
        # serialized xkey: the prefix already says what is wrong
        err_msg = f"not a private key: prefix 0x{xprv.key[:1].hex()}"
        raise InvalidPrvKeyError(err_msg)

    if network is None:
        network = network_from_xkeyversion(xprv.version)

    allowed_versions = xprvversions_from_network(network)
    if xprv.version not in allowed_versions:
        # never echo the xprv, which is a private key:
        # the version is the mismatching, non-secret, part
        err_msg = f"not a {network} key: version 0x{xprv.version.hex()}"
        raise InvalidPrvKeyError(err_msg)

    q = int.from_bytes(xprv.key[1:], byteorder="big")
    return q, network, True


def _prv_keyinfo_from_xprvwif(
    xprvwif: BIP32Key, network: str | None, compressed: bool | None
) -> PrvkeyInfo:
    """Return prv_key tuple (int, compressed, network) from WIF/BIP32.

    Support WIF or BIP32 xprv.
    """
    reasons = []
    if not isinstance(xprvwif, BIP32KeyData):
        # NotAPrvKeyError only, letting an InvalidPrvKeyError through: a
        # WIF whose prefix and checksum are right and whose payload is the
        # wrong size is not something the xprv branch might accept
        try:
            return _prv_keyinfo_from_wif(xprvwif, network, compressed)
        except NotAPrvKeyError as e:
            reasons.append(str(e))
    try:
        return _prv_keyinfo_from_xprv(xprvwif, network, compressed)
    except NotAPrvKeyError as e:
        # both reasons, not the last one: which format the caller meant is
        # exactly what is unknown here, so guessing would drop the answer
        reasons.append(str(e))
        raise NotAPrvKeyError("; ".join(reasons)) from e


def prv_keyinfo_from_prv_key(
    prv_key: PrvKey, network: str | None = None, compressed: bool | None = None
) -> PrvkeyInfo:
    """Return (int key, network, compressed) from any private key spelling.

    A WIF or an xprv carries its own network and compression, and a
    contradicting argument is refused rather than overridden; an int
    or octets carry neither, so the arguments -- mainnet, compressed
    -- fill in.
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
        return _prv_keyinfo_from_xprv(prv_key, network, compressed)
    else:
        reasons = []
        # NotAPrvKeyError only, letting an InvalidPrvKeyError through
        try:
            return _prv_keyinfo_from_xprvwif(prv_key, network, compressed)
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
