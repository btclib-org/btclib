#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Partially signed bitcoin transactions and the BIP174/BIP370 roles.

What this package exports is the format and the roles: the three maps a
psbt is made of, the Combiner, the Finalizer, the Extractor, the outputs
an unsigned psbt spends, and the size estimation a fee rate is applied to.
`musig2` is named as a module, being the BIP373 role rather than one
function, the way btclib.ecc names dsa.

btclib.psbt.psbt_utils is not exported, and this is where that decision is
recorded: serialize_bytes, deserialize_map, deserialize_tx,
the encode/decode_dict_bytes_bytes pair,
serialize_dict_bytes_bytes, serialize_hd_key_paths and
assert_valid_unknown are how one field of one map is written and read.
They are called by psbt_in, psbt_out and psbt itself and by nothing
outside this package, and there were more of them in __all__ than there
were names for the format -- so a caller reading btclib.psbt was offered
the plumbing of a file format ahead of the psbt. Each is importable from
the module that defines it, which is where the test suite takes the other
half of that module from already.
"""

from btclib.psbt import musig2
from btclib.psbt.psbt import (
    Psbt,
    combine,
    extract_tx,
    finalize,
    join,
    prevouts,
)
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_size import estimated_input_sizes

__all__ = [
    "Psbt",
    "PsbtIn",
    "PsbtOut",
    "combine",
    "estimated_input_sizes",
    "extract_tx",
    "finalize",
    "join",
    "musig2",
    "prevouts",
]
