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

from btclib.curves import secp256k1 as ec
from btclib.der import _deserialize, _serialize


def test_der():

    sighash_all = 1

    sig9 = 1, 1
    sig73 = ec.n - 1, ec.n - 1
    sig72 = 2 ** 255 - 1, ec.n - 1
    sig71 = 2 ** 255 - 1, 2 ** 255 - 1
    sig71b = 2 ** 255 - 1, 2 ** 248 - 1
    sig70 = 2 ** 255 - 1, 2 ** 247 - 1
    sig69 = 2 ** 247 - 1, 2 ** 247 - 1
    sigs = [sig9, sig73, sig72, sig71, sig71b, sig70, sig69]
    lenghts = [9, 73, 72, 71, 71, 70, 69]

    for lenght, sig in zip(lenghts, sigs):
        dersig = _serialize(*sig, sighash_all)
        r, s, sighash = _deserialize(dersig)
        assert sig == (r, s)
        assert sighash_all == sighash
        assert len(dersig) == lenght
        # without sighash
        r, s, no_sighash = _deserialize(dersig[:-1])
        assert sig == (r, s)
        assert no_sighash is None

    # with the last one

    assert (r, s, sighash) == _deserialize((r, s, sighash))

    badsig = dersig[:-1] + b"\x00"
    err_msg = "Invalid sighash: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(badsig)

    dersig2 = dersig + b"\x00" * 70
    err_msg = "Invalid DER signature size: "
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = b"\x00" + dersig[1:]
    err_msg = "DER signature type must be 0x30 "
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[:1] + b"\x41" + dersig[2:]
    err_msg = "Declared signature length incompatible with actual length: "
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    Rsize = dersig[3]
    dersig2 = dersig[:3] + b"\x00" + dersig[4:]
    err_msg = "Zero-size integer is not allowed for scalar r"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[:3] + b"\x80" + dersig[4:]
    err_msg = "Size of scalar s does not fit inside the signature"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[: Rsize + 5] + b"\x00" + dersig[Rsize + 6 :]
    err_msg = "Zero-size integer is not allowed for scalar s"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[: Rsize + 5] + b"\x4f" + dersig[Rsize + 6 :]
    err_msg = "Signature size does not match with size of scalars"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[:2] + b"\x00" + dersig[3:]
    err_msg = "Scalar r must be an integer"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[:4] + b"\x80" + dersig[5:]
    err_msg = "Negative number not allowed for scalar r"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[:4] + b"\x00\x00" + dersig[6:]
    err_msg = "Invalid null bytes at the start of scalar r"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[: Rsize + 4] + b"\x00" + dersig[Rsize + 5 :]
    err_msg = "Scalar s must be an integer"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    dersig2 = dersig[: Rsize + 6] + b"\x80" + dersig[Rsize + 7 :]
    err_msg = "Negative number not allowed for scalar s"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    # Invalid null bytes at the start of s
    dersig2 = dersig[: Rsize + 6] + b"\x00\x00" + dersig[Rsize + 8 :]
    err_msg = "Invalid null bytes at the start of scalar s"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig2)

    err_msg = "Invalid sighash: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _serialize(*sig, 0x85)

    sig2 = 0, sig[1]
    err_msg = "Scalar r not in 1..n-1: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _serialize(*sig2, sighash_all)

    sig2 = ec.n, sig[1]
    err_msg = "Scalar r not in 1..n-1: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _serialize(*sig2, sighash_all)

    sig2 = sig[0], 0
    err_msg = "Scalar s not in 1..n-1: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _serialize(*sig2, sighash_all)

    sig2 = sig[0], ec.n
    err_msg = "Scalar s not in 1..n-1: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _serialize(*sig2, sighash_all)

    err_msg = "Invalid sighash: 0x"
    with pytest.raises(ValueError, match=err_msg):
        _deserialize(dersig[:-1] + b"\x00")
