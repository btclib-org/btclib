#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""BIP32 extended keys, derivation, key origins, and SLIP132 versions."""

from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    crack_prv_key,
    derive,
    derive_from_account,
    pub_key_derivation_tweaks,
    rootxprv_from_seed,
    xpub_from_xprv,
)
from btclib.bip32.der_path import (
    bytes_from_der_path,
    indexes_from_der_path,
    int_from_index_str,
    str_from_der_path,
    str_from_index_int,
)
from btclib.bip32.key_origin import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)

# btclib.bip32.slip132 is not here, and cannot be: it is the one submodule
# of this package that sits *above* the address encodings -- it imports
# btclib.b58 and btclib.b32, which import btclib.to_pub_key, which imports
# this package -- so an import of it in this file is a cycle, and
# `cannot import name 'BIP32Key' from partially initialized module
# 'btclib.bip32'` is what every caller then gets. tests/imports_test.py,
# which imports each module of the library with nothing else in sys.modules,
# is what reports it.
# `from btclib.bip32 import slip132` works regardless, a submodule not
# needing its parent's __all__ to be importable, and is what every caller in
# the tree writes. What the absence from this list costs is that nothing
# states the layering it comes from, which is what this comment is for:
# btclib.bip44 has the same shape -- bip32 plus both address encodings --
# and lives at the top level for that very reason
__all__ = [
    "BIP32Key",
    "BIP32KeyData",
    "BIP32KeyOrigin",
    "HdKeyPaths",
    "assert_valid_hd_key_paths",
    "bytes_from_der_path",
    "crack_prv_key",
    "decode_from_bip32_derivs",
    "decode_hd_key_paths",
    "derive",
    "derive_from_account",
    "encode_to_bip32_derivs",
    "indexes_from_der_path",
    "int_from_index_str",
    "pub_key_derivation_tweaks",
    "rootxprv_from_seed",
    "str_from_der_path",
    "str_from_index_int",
    "xpub_from_xprv",
]
