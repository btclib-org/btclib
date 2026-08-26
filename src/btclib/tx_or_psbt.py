# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""One entry point for a transaction or a psbt, in whatever it arrives as.

A transaction copied from a block explorer is hex, a
`walletcreatefundedpsbt` reply is base64, a QR code and a file are
bytes -- and which of `Tx.parse`, `Psbt.parse` and `Psbt.b64decode`
applies is a question a caller holding one of them should not have to
answer first. It is also a question with an unambiguous answer:
BIP174's five-byte `<magic>` is what a psbt begins with and what a
transaction cannot, which is the very reason the `0xff` is in it.

So this module sniffs, and delegates. The parsers stay whole -- one
refuses what does not deserialize, the other refuses what follows a
psbt (issue #179) -- and no byte either of them reads is read here:
merging the two into one lenient reader is how a dispatcher stops being
a dispatcher, and it is the parsers that would pay for it.

It sits above `tx` and `psbt` rather than inside either, because its
answer is one or the other and `tx` may not import `psbt`.
"""

from __future__ import annotations

import base64
import binascii

from btclib.alias import String
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import PSBT_MAGIC_BYTES, Psbt
from btclib.tx import Tx
from btclib.utils import bytes_from_octets

__all__ = [
    "tx_or_psbt_from_any",
]


def _octets_from_text(text: str) -> bytes:
    """Return the bytes a hex-string or a base64 string encodes.

    Hex first, because a hex-string whose length is a multiple of four
    is also a valid base64 encoding -- of something else entirely. The
    other way round there is nothing to resolve: base64's alphabet has
    every letter, so a base64 string is almost never hex, and BIP174's
    magic makes one of them start with `cHNidP8`.
    """
    # whitespace and nothing else is dropped, since base64 arrives
    # wrapped as often as not -- and bytes.fromhex has skipped it since
    # python 3.7 anyway, so this only makes the two consistent
    packed = "".join(text.split())

    try:
        return bytes.fromhex(packed)
    except ValueError:
        pass

    try:
        # validate=True: without it b64decode drops whatever is outside
        # the alphabet instead of refusing it, so text that is not base64
        # at all decodes to bytes that are not anything
        return base64.b64decode(packed, validate=True)
    except binascii.Error as e:
        raise BTClibValueError("neither hex nor base64") from e


def _octets_from_any(data: String) -> bytes:
    """Return the bytes behind hex, base64, or bytes.

    Bytes are text when they are ascii and decode as hex or base64, and
    are themselves otherwise: `Path.read_bytes` is how a psbt or a
    transaction comes out of a file, whichever of the three encodings
    the file holds, and a caller who read one that way should not have
    to know which. Nothing is lost to the ambiguity -- a serialized
    transaction begins with a four-byte version that is not printable,
    and a serialized psbt with a `0xff` that is not ascii at all.
    """
    if isinstance(data, str):
        return _octets_from_text(data)

    # the refusal of what is neither text nor bytes is bytes_from_octets's
    # to give, `split` below being str's and `decode` bytes'
    raw = bytes_from_octets(data)
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return raw
    try:
        return _octets_from_text(text)
    except BTClibValueError:
        return raw


def tx_or_psbt_from_any(data: String, *, check_validity: bool = True) -> Tx | Psbt:
    """Return the Psbt or the Tx the data holds, in whatever encoding.

    hex, base64 or bytes; a `Psbt` when BIP174's magic is what the bytes
    begin with, a `Tx` when it is not.
    """
    octets = _octets_from_any(data)

    if not octets:
        # what Tx.parse would answer here is "not enough binary data for
        # var_int", which describes a field the caller never had
        raise BTClibValueError("no data")

    if octets.startswith(PSBT_MAGIC_BYTES):
        return Psbt.parse(octets, check_validity=check_validity)

    return Tx.parse(octets, check_validity=check_validity)
