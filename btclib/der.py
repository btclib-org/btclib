#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Strict ASN.1 DER format for ECDSA signature representation.

The original Bitcoin implementation used OpenSSL to verify
ECDSA signatures in ASN.1 DER representation.
However, OpenSSL does not do strict validation
(e.g. extra padding is ignored) and this changes the transaction
hash value, leading to transaction malleability.
This was fixed by BIP66, activated on block 363,724.

source:
https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki

BIP66 mandates a strict DER format:

Format:
[0x30] [data-size][0x02][r-size][r][0x02][s-size][s]

* 0x30: header byte to indicate compound structure
* data-size: 1-byte size descriptor of the following data
* 0x02: header byte indicating an integer
* r-size: 1-byte size descriptor of the r value that follows
* r: arbitrary-size big-endian r value.
    It must use the shortest possible encoding for
    a positive integers (which means no null bytes at the start,
    except a single one when the next byte has its highest bit set
    to avoid being interpreted as a negative number)
* 0x02: header byte indicating an integer
* s-size: 1-byte size descriptor of the s value that follows
* s: arbitrary-size big-endian s value. Same rules as for r apply

There are 7 bytes of meta-data:

* compound header, compound size,
* value header, r-value size,
* value header, s-value size

The ECDSA signature (r, s) should be 64 bytes,
r and s being 32 bytes integers each;
however, integers in DER are signed,
so if the value being encoded is greater than 2^128,
a 33rd byte is added in front.
Bitcoin has a "low s" rule for the s value to be below ec.n,
but it is only a standardness rule miners are allowed to ignore.
Moreover, no such rule exists for r.
"""

from dataclasses import InitVar, dataclass, field
from io import BytesIO
from typing import Type, TypeVar

from dataclasses_json import DataClassJsonMixin, config

from . import var_bytes
from .alias import BinaryData
from .curve import Curve, secp256k1
from .exceptions import BTClibValueError
from .utils import bytesio_from_binarydata, hex_string

_DER_SCALAR_MARKER = b"\x02"
_DER_SIG_MARKER = b"\x30"


def _serialize_scalar(scalar: int) -> bytes:
    # scalar is assumed to be in [1, n-1]
    elen = scalar.bit_length()
    esize = elen // 8 + 1  # not a bug: 'highest bit set' padding included here
    scalar_bytes = scalar.to_bytes(esize, byteorder="big", signed=True)
    return _DER_SCALAR_MARKER + var_bytes.serialize(scalar_bytes)


def _deserialize_scalar(sig_data_stream: BytesIO) -> int:
    marker = sig_data_stream.read(1)
    if marker != _DER_SCALAR_MARKER:
        err_msg = f"invalid value header: {marker.hex()}"
        err_msg += f", instead of integer element {_DER_SCALAR_MARKER.hex()}"
        raise BTClibValueError(err_msg)
    r_bytes = var_bytes.deserialize(sig_data_stream, forbid_zero_size=True)
    if r_bytes[0] == 0 and r_bytes[1] & 0x80 != 0x80:
        err_msg = "invalid null byte at the start of scalar"
        raise BTClibValueError(err_msg)

    return int.from_bytes(r_bytes, byteorder="big", signed=True)


_Sig = TypeVar("_Sig", bound="Sig")


@dataclass(frozen=True)
class Sig(DataClassJsonMixin):
    # 32 bytes
    r: int = field(
        default=-1, metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    # 32 bytes
    s: int = field(
        default=-1, metadata=config(encoder=lambda v: v.hex(), decoder=bytes.fromhex)
    )
    ec: Curve = field(
        default=secp256k1,
        metadata=config(encoder=lambda v: v.name(), decoder=bytes.fromhex),
    )
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        # Fail if r is not [1, n-1]
        if not 0 < self.r < self.ec.n:
            err_msg = "scalar r not in 1..n-1: "
            err_msg += f"'{hex_string(self.r)}'" if self.r > 0xFFFFFFFF else f"{self.r}"
            raise BTClibValueError(err_msg)

        # Fail if s is not [1, n-1]
        if not 0 < self.s < self.ec.n:
            err_msg = "scalar s not in 1..n-1: "
            err_msg += f"'{hex_string(self.s)}'" if self.s > 0xFFFFFFFF else f"{self.s}"
            raise BTClibValueError(err_msg)

    def serialize(self, check_validity: bool = True) -> bytes:
        "Serialize an ECDSA signature to strict ASN.1 DER representation"

        if check_validity:
            self.assert_valid()

        out = _serialize_scalar(self.r)
        out += _serialize_scalar(self.s)
        return _DER_SIG_MARKER + var_bytes.serialize(out)

    @classmethod
    def deserialize(
        cls: Type[_Sig], data: BinaryData, check_validity: bool = True
    ) -> _Sig:
        """Return a Sig by parsing binary data.

        Deserialize a strict ASN.1 DER representation of an ECDSA signature.
        """

        stream = bytesio_from_binarydata(data)
        ec = secp256k1

        # [0x30] [data-size][0x02][r-size][r][0x02][s-size][s]
        marker = stream.read(1)
        if marker != _DER_SIG_MARKER:
            err_msg = f"invalid compound header: {marker.hex()}"
            err_msg += f", instead of DER sequence tag {_DER_SIG_MARKER.hex()}"
            raise BTClibValueError(err_msg)

        # [data-size][0x02][r-size][r][0x02][s-size][s]
        sig_data = var_bytes.deserialize(stream, forbid_zero_size=True)

        # [0x02][r-size][r][0x02][s-size][s]
        sig_data_substream = bytesio_from_binarydata(sig_data)
        r = _deserialize_scalar(sig_data_substream)
        s = _deserialize_scalar(sig_data_substream)

        # to prevent malleability
        # the sig_data_substream must have been consumed entirely
        if sig_data_substream.read(1) != b"":
            err_msg = "invalid DER sequence length"
            raise BTClibValueError(err_msg)

        return cls(r, s, ec, check_validity)
