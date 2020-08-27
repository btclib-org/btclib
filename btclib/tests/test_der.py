#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.der` module."

import pytest

from btclib import script
from btclib.curves import secp256k1 as ec
from btclib.der import _deserialize, _serialize


def test_der_size() -> None:

    sig8 = 1, 1
    sig72 = ec.n - 1, ec.n - 1
    sig71 = 2 ** 255 - 1, ec.n - 1
    sig70 = 2 ** 255 - 1, 2 ** 255 - 1
    sig70b = 2 ** 255 - 1, 2 ** 248 - 1
    sig69 = 2 ** 255 - 1, 2 ** 247 - 1
    sig68 = 2 ** 247 - 1, 2 ** 247 - 1
    sigs = [sig8, sig72, sig71, sig70, sig70b, sig69, sig68]
    lenghts = [8, 72, 71, 70, 70, 69, 68]  # not including script.SIGHASHES

    for lenght, sig in zip(lenghts, sigs):
        for sighash in script.SIGHASHES:
            der_sig = _serialize(*sig, sighash)
            r, s, sighash2 = _deserialize(der_sig)
            assert sig == (r, s)
            assert sighash == sighash2
            assert len(der_sig) == lenght + 1

    # with the last one only...
    assert (r, s, sighash) == _deserialize((r, s, sighash))


def test_der_deserialize() -> None:

    err_msg = "non-hexadecimal number found "
    with pytest.raises(ValueError, match=err_msg):
        _deserialize("not a sig")

    sig = 2 ** 255 - 1, 2 ** 247 - 1
    for sighash in script.SIGHASHES:
        der_sig = _serialize(*sig, sighash)
        r_size = der_sig[3]

        bad_der_sig = b"\x00" * 74
        err_msg = "invalid DER size: "
        with pytest.raises(ValueError, match=err_msg):
            _deserialize(bad_der_sig)

        bad_der_sig = b"\x31" + der_sig[1:]
        err_msg = "DER type must be 0x30 "
        with pytest.raises(ValueError, match=err_msg):
            _deserialize(bad_der_sig)

        bad_der_sig = der_sig[:1] + b"\x41" + der_sig[2:]
        err_msg = "Declared size incompatible with actual size: "
        with pytest.raises(ValueError, match=err_msg):
            _deserialize(bad_der_sig)

        bad_der_sig = der_sig + b"\x01"
        err_msg = "Declared size incompatible with actual size: "
        with pytest.raises(ValueError, match=err_msg):
            _deserialize(bad_der_sig)

        bad_der_sig = der_sig[:-1] + b"\x00"
        err_msg = "invalid sighash: 0x"
        with pytest.raises(ValueError, match=err_msg):
            _deserialize(bad_der_sig)

        # r and s scalars
        for offset in (4, 6 + r_size):
            bad_der_sig = der_sig[: offset - 2] + b"\x00" + der_sig[offset - 1 :]
            err_msg = "scalar must be an integer"
            with pytest.raises(ValueError, match=err_msg):
                _deserialize(bad_der_sig)

            bad_der_sig = der_sig[: offset - 1] + b"\x00" + der_sig[offset:]
            err_msg = "scalar has size zero"
            with pytest.raises(ValueError, match=err_msg):
                _deserialize(bad_der_sig)

            bad_der_sig = der_sig[: offset - 1] + b"\x80" + der_sig[offset:]
            err_msg = "Size of scalar is too large: "
            with pytest.raises(ValueError, match=err_msg):
                _deserialize(bad_der_sig)

            bad_der_sig = der_sig[:offset] + b"\x80" + der_sig[offset + 1 :]
            err_msg = "Negative number not allowed for scalar"
            with pytest.raises(ValueError, match=err_msg):
                _deserialize(bad_der_sig)

            bad_der_sig = der_sig[:offset] + b"\x00\x7f" + der_sig[offset + 2 :]
            err_msg = "invalid null bytes at the start of scalar"
            with pytest.raises(ValueError, match=err_msg):
                _deserialize(bad_der_sig)

        data_size = der_sig[1]
        malleated_size = (data_size + 1).to_bytes(1, byteorder="big")
        bad_der_sig = der_sig[:1] + malleated_size + der_sig[2:] + b"\x01"
        err_msg = "Too big DER size for "
        with pytest.raises(ValueError, match=err_msg):
            _deserialize(bad_der_sig)


def test_der_serialize() -> None:

    sig = 2 ** 247 - 1, 2 ** 247 - 1
    err_msg = "invalid sighash: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _serialize(*sig, 0x85)

    for sighash in script.SIGHASHES:
        err_msg = "scalar r not in 1..n-1: "
        for r in (0, ec.n):
            bad_sig = r, sig[1]
            with pytest.raises(ValueError, match=err_msg):
                _serialize(*bad_sig, sighash)

        for s in (0, ec.n):
            bad_sig = sig[0], s
            err_msg = "scalar s not in 1..n-1: "
            with pytest.raises(ValueError, match=err_msg):
                _serialize(*bad_sig, sighash)
