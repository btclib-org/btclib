# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Verification of a merkle branch against a block header's merkle root.

The verifier's side of the tree `btclib.block.Block` builds: given a
txid, the siblings on its way up and its position among the block's
transactions, recompute the root and compare it with the header's. That
is what Core's verifytxoutproof answers and what gettxoutproof produces
the input for, and it is the arithmetic every light client runs.

The arithmetic itself is `hashes.merkle_root_from_branch`, next to the
functions that build a root; what lives here is the half of the
hardening that has to know what a transaction is, CVE-2017-12842, plus
the byte-order convention. A txid and a header's merkle_root are handled
here the way `Tx.id` and `BlockHeader.merkle_root` give them -- reversed
for display, which is also how an explorer or an RPC prints them -- and
so is every sibling of the branch.

A proof is evidence only together with the header that carries the root:
this module answers "the tree with this root contained this leaf", and
nothing about whether that root is on the most-work chain.
"""

from __future__ import annotations

from collections.abc import Sequence

from btclib.alias import Octets
from btclib.exceptions import (
    BTClibRuntimeError,
    BTClibTypeError,
    BTClibValueError,
)
from btclib.hashes import hash256, merkle_root_from_branch
from btclib.tx import Tx
from btclib.utils import assert_type, bytes_from_octets, is_octets

__all__ = [
    "assert_as_valid",
    "verify",
]

_HF = hash256


def _assert_inner_node_is_not_a_tx(inner_node: bytes) -> None:
    """Refuse an inner node that is also a serialized transaction.

    CVE-2017-12842. An inner node is the 64 bytes of its two children,
    and a transaction can be made to be exactly those 64 bytes: presented
    as a leaf, it gets a proof one level shorter than the tree really is,
    so a light client can be shown a "transaction" that was never in the
    block. Core's fix is on the other side -- a 64-byte transaction is
    non-standard and, since BIP141 blocks commit to the transaction
    count, unusable in a valid block -- but a verifier holding a branch
    and nothing else can only refuse the shape.
    """
    try:
        tx = Tx.parse(inner_node, check_validity=False)
        # a prefix that happens to parse is refused by the parser itself,
        # octets being one whole transaction; what is left for the
        # round-trip to catch is an encoding of a transaction that is not
        # the one btclib writes -- a segwit marker with no witness behind
        # it -- which is not the shape a leaf can be forged into either
        is_a_tx = tx.serialize(include_witness=True, check_validity=False) == inner_node
    except (BTClibValueError, BTClibTypeError, BTClibRuntimeError):
        # the exception contract of btclib/exceptions.py, which is what
        # tests/fuzz_test.py holds every parser to: these three mean "not
        # a transaction", the ordinary answer for every honest inner node
        # in every block, and anything else is a bug worth propagating
        return

    # `no branch` rather than a test: a false `is_a_tx` would be 64 octets
    # that parse and that btclib writes back differently, and there are
    # none. Every field is read as it was written -- the counts and the
    # lengths are var_ints, and `var_int.parse` takes only the canonical
    # width of each -- and the one encoding that would not round-trip, a
    # BIP144 marker over empty witnesses, is what `Tx.parse` refuses on
    # its own. The comparison stays because that is a property of the
    # parser rather than of this module, and a parser that stopped
    # refusing that shape would need it here
    if is_a_tx:  # pragma: no branch
        err_msg = "inner node of the merkle branch is a valid transaction"
        raise BTClibValueError(err_msg)


def assert_as_valid(
    txid: Octets, branch: Sequence[Octets], index: int, merkle_root: Octets
) -> None:
    """Raise unless the branch proves that txid is in the tree of merkle_root.

    `index` is the transaction's position in the block, counted from
    zero; `branch` is one sibling per level, bottom-up. txid, the
    siblings and merkle_root are all in the reversed order they are
    displayed in, which is what `Tx.id` and `BlockHeader.merkle_root`
    hold.
    """
    # the branch before it is walked: what is not a sequence went to the
    # comprehension below untouched, so a None left it as "not iterable"
    # -- a complaint about iteration and not about a branch (issue #814).
    # An Octets is itself a Sequence, so assert_type alone lets one
    # through -- zipped through its bytes and treated as one sibling per
    # byte -- and is_octets is what refuses that shape (issue #1405)
    if is_octets(branch):
        raise BTClibTypeError(f"invalid branch type: {type(branch).__name__}")
    assert_type(branch, Sequence, "branch")

    root = bytes_from_octets(merkle_root, 32)
    computed = merkle_root_from_branch(
        bytes_from_octets(txid, 32)[::-1],
        [bytes_from_octets(sibling, 32)[::-1] for sibling in branch],
        index,
        _HF,
        _assert_inner_node_is_not_a_tx,
    )
    if computed[::-1] != root:
        err_msg = f"invalid merkle branch: {computed[::-1].hex()}"
        err_msg += f" instead of: {root.hex()}"
        raise BTClibValueError(err_msg)


def verify(
    txid: Octets, branch: Sequence[Octets], index: int, merkle_root: Octets
) -> bool:
    """Return True if the branch proves that txid is in the tree of merkle_root.

    See assert_as_valid, which this wraps and which says why a branch
    was refused.
    """
    # ValueError and not Exception: a branch that does not prove what it
    # claims is False, and so is one that is malformed, but a TypeError
    # is neither -- an index passed as a string is a caller error
    try:
        assert_as_valid(txid, branch, index, merkle_root)
    except ValueError:
        return False

    return True
