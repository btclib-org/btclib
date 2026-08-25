# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP32 extended keys, derivation, and key origins."""

from btclib.bip32.bip32 import (
    BIP328_CHAIN_CODE,
    BIP32Key,
    BIP32KeyData,
    crack_prv_key_var,
    derive,
    derive_,
    derive_from_account,
    derive_from_account_,
    derive_from_account_range,
    derive_from_account_range_,
    fingerprint,
    pub_key_derivation_tweaks,
    rootxprv_from_seed,
    rootxprv_from_seed_,
    xpub_from_xprv,
    xpub_from_xprv_,
)
from btclib.bip32.der_path import (
    bytes_from_der_path,
    hardenings_from_der_path,
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

__all__ = [
    "BIP328_CHAIN_CODE",
    "BIP32Key",
    "BIP32KeyData",
    "BIP32KeyOrigin",
    "HdKeyPaths",
    "assert_valid_hd_key_paths",
    "bytes_from_der_path",
    "crack_prv_key_var",
    "decode_from_bip32_derivs",
    "decode_hd_key_paths",
    "derive",
    "derive_",
    "derive_from_account",
    "derive_from_account_",
    "derive_from_account_range",
    "derive_from_account_range_",
    "encode_to_bip32_derivs",
    "fingerprint",
    "hardenings_from_der_path",
    "indexes_from_der_path",
    "int_from_index_str",
    "pub_key_derivation_tweaks",
    "rootxprv_from_seed",
    "rootxprv_from_seed_",
    "str_from_der_path",
    "str_from_index_int",
    "xpub_from_xprv",
    "xpub_from_xprv_",
]
