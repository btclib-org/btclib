# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Elliptic Curve Digital Signature Algorithm.

ellipticcurves.ecc.dsa's: every name here is that module's own object,
bound again so that `btclib.ecc.dsa` keeps answering for it (issue
#2282).
"""

from ellipticcurves.ecc.dsa import (
    Sig,
    Signer,
    anti_exfil_host_commit,
    anti_exfil_host_verify,
    anti_exfil_sign,
    anti_exfil_signer_commit,
    assert_as_valid,
    assert_as_valid_,
    crack_prv_key_var,
    crack_prv_key_var_,
    gen_keys,
    recover_pub_key,
    recover_pub_key_,
    recover_pub_keys,
    recover_pub_keys_,
    recover_sec,
    recover_sec_,
    sign,
    sign_,
    sign_recoverable,
    sign_recoverable_,
    verify,
    verify_,
)

__all__ = [
    "Sig",
    "Signer",
    "anti_exfil_host_commit",
    "anti_exfil_host_verify",
    "anti_exfil_sign",
    "anti_exfil_signer_commit",
    "assert_as_valid",
    "assert_as_valid_",
    "crack_prv_key_var",
    "crack_prv_key_var_",
    "gen_keys",
    "recover_pub_key",
    "recover_pub_key_",
    "recover_pub_keys",
    "recover_pub_keys_",
    "recover_sec",
    "recover_sec_",
    "sign",
    "sign_",
    "sign_recoverable",
    "sign_recoverable_",
    "verify",
    "verify_",
]
