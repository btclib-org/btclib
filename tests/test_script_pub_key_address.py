#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script_pub_key_address` module"

from btclib.script_pub_key_address import has_segwit_prefix


def test_has_segwit_prefix() -> None:
    addr = b"bc1q0hy024867ednvuhy9en4dggflt5w9unw4ztl5a"
    assert has_segwit_prefix(addr)
    assert has_segwit_prefix(addr.decode("ascii"))
    addr = b"1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    assert not has_segwit_prefix(addr)
    assert not has_segwit_prefix(addr.decode("ascii"))
