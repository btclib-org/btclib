# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The legacy signature check operation count of a script.

Bitcoin Core's `CScript::GetSigOpCount(false)`, which `GetLegacySigOpCount`
sums over the input and output scripts of a transaction and `CheckBlock`
sums again over the transactions of a block, to bound it by
`MAX_BLOCK_SIGOPS_COST`. That is the one sigop rule a block can be held to
from its own bytes, and it is why the count is here: `Tx.sig_op_count` and
`Block.sig_op_count` are the two sums, each reading this.

The count underestimates, and Core's comment where it is summed says so:
the p2sh count needs the redeem script the input pushes, the witness count
needs the `script_pub_key` being spent, and both are outputs of blocks that
are not this one. `fAccurate` is not a parameter here for that same reason
-- accurate means `OP_CHECKMULTISIG` costing the number of keys pushed
before it rather than the twenty of `MAX_PUBKEYS_PER_MULTISIG`, and Core
only ever asks for it under p2sh and segwit, where the script counted comes
from the UTXO set.

A module of its own rather than the bottom of `script.py`, which is the
encoding and reads no limit: `MAX_PUBKEYS_PER_MULTISIG` is a rule about
executing a script, and a decoder that need not import the limits is what
`script/limits.py` exists to say. What it does share with the decoder is
the walk -- `op_code_spans`, i.e. Core's `GetOp` -- because the boundary
between one op code and the next is the only thing the count depends on.
"""

from __future__ import annotations

from btclib.alias import Octets
from btclib.script.limits import MAX_PUBKEYS_PER_MULTISIG
from btclib.script.script import BYTE_FROM_OP_CODE_NAME, op_code_spans
from btclib.utils import bytes_from_octets

__all__ = [
    "sig_op_count",
]

# read out of the table rather than written as bytes, so that these stay
# the op codes those names stand for
_CHECKSIG = {
    BYTE_FROM_OP_CODE_NAME[name][0] for name in ("OP_CHECKSIG", "OP_CHECKSIGVERIFY")
}
_CHECKMULTISIG = {
    BYTE_FROM_OP_CODE_NAME[name][0]
    for name in ("OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY")
}


def sig_op_count(script: Octets) -> int:
    """Return the number of legacy signature checks a script announces.

    One for `OP_CHECKSIG` and `OP_CHECKSIGVERIFY`,
    `MAX_PUBKEYS_PER_MULTISIG` for `OP_CHECKMULTISIG` and
    `OP_CHECKMULTISIGVERIFY` however many keys the script actually pushes,
    and nothing for the rest -- the count is announced by the bytes and is
    not what executing them would do.

    Where the script stops parsing the count stops too, and no exception
    is raised: Core's loop `break`s when `GetOp` returns false, which is a
    push running past the end, and `op_code_spans` ends the same way. The
    coinbase output script of testnet block 987,876 is that case on chain
    -- it ends `...d8 3d 0aa68688ac`, and the `OP_CHECKSIG` of that final
    `ac` is five bytes inside the 61-byte push `3d` announces, so neither
    implementation ever reaches it and the answer for that script is zero.
    """
    script_ = bytes_from_octets(script)
    count = 0
    for op_code, _, _ in op_code_spans(script_):
        if op_code in _CHECKSIG:
            count += 1
        elif op_code in _CHECKMULTISIG:
            count += MAX_PUBKEYS_PER_MULTISIG
    return count
