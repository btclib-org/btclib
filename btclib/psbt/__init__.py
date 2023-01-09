#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Module btclib.psbt."""

from btclib.psbt.psbt import Psbt, combine_psbts, extract_tx, finalize_psbt, join_psbts
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import (
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    deserialize_int,
    deserialize_map,
    deserialize_tx,
    encode_dict_bytes_bytes,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
)

__all__ = [
    "assert_valid_unknown",
    "combine_psbts",
    "decode_dict_bytes_bytes",
    "deserialize_int",
    "deserialize_map",
    "deserialize_tx",
    "encode_dict_bytes_bytes",
    "encode_dict_bytes_bytes",
    "extract_tx",
    "finalize_psbt",
    "join_psbts",
    "Psbt",
    "PsbtIn",
    "PsbtOut",
    "serialize_bytes",
    "serialize_dict_bytes_bytes",
    "serialize_hd_key_paths",
]
