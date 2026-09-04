# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Whether an output can ever be spent, from its script_pub_key alone.

Bitcoin Core's `CScript::IsUnspendable` (`script/script.h:563-566`, at
bitcoin/bitcoin@9be056a8a7, tag v31.1): a leading OP_RETURN, or a script
longer than `MAX_SCRIPT_SIZE`. `CCoinsViewCache::AddCoin`
(`coins.cpp:91`) returns without adding such an output to the UTXO set
at all, so it is what a node's own set never carries and what an output
worth anything at all still cannot be paid out of.

A module of its own rather than part of `script_pub_key.py`, which is
the classification of the standard shapes and pairs an `assert_x` with
every `is_x` it publishes: unspendable is not a shape, and an
`assert_unspendable` refusing a script for being spendable is not a
question anybody asks. Beside `sig_ops.py` instead, which is here for
the same reason -- a rule about a script that is neither its encoding
nor its type -- and reads `limits.py` the same way.

`is_nulldata` in `script_pub_key.py` answers a narrower question and is
not this one (issue #211): a bare OP_RETURN, and an OP_RETURN followed
by several pushes, are not the standard nulldata shape and are
unspendable to a node all the same. `fee.dust_threshold` and
`coinstats.CoinStats` are the two callers, and they would each be wrong
in the same way if they asked the classifier instead -- one handing a
dust threshold to an output nothing can spend, the other counting an
output Core's own set never held.
"""

from __future__ import annotations

from btclib.alias import Octets
from btclib.script.limits import MAX_SCRIPT_SIZE
from btclib.script.script import BYTE_FROM_OP_CODE_NAME
from btclib.utils import bytes_from_octets

__all__ = [
    "is_unspendable",
]

# read out of the table rather than written as a byte, so that this stays
# the op code that name stands for, as `sig_ops.py` reads its own
_OP_RETURN = BYTE_FROM_OP_CODE_NAME["OP_RETURN"]


def is_unspendable(script_pub_key: Octets) -> bool:
    """Answer whether no transaction can ever spend such an output.

    Sliced and not indexed, so that an empty script is a script with no
    leading OP_RETURN rather than an IndexError; and the length is
    compared with `>`, so a script of exactly `MAX_SCRIPT_SIZE` bytes is
    spendable, as it is to a node.
    """
    script_pub_key = bytes_from_octets(script_pub_key)
    return script_pub_key[:1] == _OP_RETURN or len(script_pub_key) > MAX_SCRIPT_SIZE
