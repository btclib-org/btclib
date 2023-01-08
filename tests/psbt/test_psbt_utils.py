#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Tests for the `btclib.psbt.psbt_utils` module."""

import pytest

from btclib.exceptions import BTClibValueError
from btclib.psbt import serialize_hd_key_paths


def test_invalid_serialize_hd_key_paths() -> None:
    with pytest.raises(BTClibValueError, match="invalid type marker lenght: "):
        serialize_hd_key_paths(b"\x01\x01", [])  # type: ignore[arg-type]
