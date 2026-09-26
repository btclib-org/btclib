# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP340 Schnorr signatures.

ellipticcurves.ecc.ssa's: every name here is that module's own object,
bound again so that `btclib.ecc.ssa` keeps answering for it (issue
#2282).
"""

from ellipticcurves.ecc.ssa import (
    BIP340PubKey,
    Sig,
    Signer,
    anti_exfil_host_commit,
    anti_exfil_host_verify,
    anti_exfil_sign,
    anti_exfil_signer_commit,
    assert_as_valid,
    assert_as_valid_,
    assert_batch_as_valid,
    assert_batch_as_valid_,
    batch_verify,
    batch_verify_,
    challenge_,
    gen_keys,
    point_from_bip340pub_key,
    sign,
    sign_,
    verify,
    verify_,
)

__all__ = [
    "BIP340PubKey",
    "Sig",
    "Signer",
    "anti_exfil_host_commit",
    "anti_exfil_host_verify",
    "anti_exfil_sign",
    "anti_exfil_signer_commit",
    "assert_as_valid",
    "assert_as_valid_",
    "assert_batch_as_valid",
    "assert_batch_as_valid_",
    "batch_verify",
    "batch_verify_",
    "challenge_",
    "gen_keys",
    "point_from_bip340pub_key",
    "sign",
    "sign_",
    "verify",
    "verify_",
]
