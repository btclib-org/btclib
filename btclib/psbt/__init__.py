#!/usr/bin/env python3

# Copyright (C) 2020-2023 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""btclib.psbt submodule."""

from btclib.psbt.psbt import Psbt, combine_psbts, extract_tx, finalize_psbt
from btclib.psbt.psbt_in import HdKeyPaths, PsbtIn, Tx
from btclib.psbt.psbt_out import (
    PsbtOut,
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    encode_dict_bytes_bytes,
    serialize_dict_bytes_bytes,
)
from btclib.psbt.psbt_utils import serialize_hd_key_paths
