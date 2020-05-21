#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.hashes` module."

from btclib import bip32
from btclib.hashes import fingerprint


def test_fingerprint():

    xpub = "xpub661MyMwAqRbcFMYjmw8C6dJV97a4oLss6hb3v9wTQn2X48msQB61RCaLGtNhzgPCWPaJu7SvuB9EBSFCL43kTaFJC3owdaMka85uS154cEh"
    pf = fingerprint(xpub)
    child_key = bip32.derive(xpub, 0)
    pf2 = bip32.deserialize(child_key)["parent_fingerprint"]
    assert pf == pf2
