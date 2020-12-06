#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.psbt_in` module"

from btclib.psbt_in import PsbtIn


def test_compatibility() -> None:
    psbt_in = PsbtIn()
    assert not psbt_in.sig_hash
