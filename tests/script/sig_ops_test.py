# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.script.sig_ops` module.

Bitcoin Core's `CScript::GetSigOpCount(false)`, the count the block rule
`bad-blk-sigops` bounds. Every case here is a script, because that is what
the function reads: the two sums over it are asserted where they live,
`Tx.sig_op_count` in `tests/tx/tx_test.py` and `Block.sig_op_count` in
`tests/block/block_test.py` and `tests/block/blockfilters_test.py`.
"""

import pytest

from btclib.script import serialize, sig_op_count
from btclib.script.limits import MAX_PUBKEYS_PER_MULTISIG

_KEY = bytes.fromhex(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

_MAX = MAX_PUBKEYS_PER_MULTISIG


@pytest.mark.parametrize(
    "count, script",
    [
        pytest.param(0, b"", id="an-empty-script-announces-nothing"),
        pytest.param(1, serialize([_KEY, "OP_CHECKSIG"]), id="p2pk"),
        pytest.param(1, serialize([_KEY, "OP_CHECKSIGVERIFY"]), id="the-verify-form"),
        pytest.param(
            2,
            serialize([_KEY, "OP_CHECKSIG", _KEY, "OP_CHECKSIG"]),
            id="one-each",
        ),
        pytest.param(
            _MAX,
            serialize(["OP_1", _KEY, _KEY, "OP_2", "OP_CHECKMULTISIG"]),
            id="a-1-of-2-costs-twenty-not-two",
        ),
        pytest.param(
            _MAX,
            serialize(["OP_1", _KEY, "OP_1", "OP_CHECKMULTISIGVERIFY"]),
            id="and-so-does-the-verify-form",
        ),
        pytest.param(
            2 * _MAX + 1,
            serialize(["OP_CHECKMULTISIG", "OP_CHECKMULTISIGVERIFY", "OP_CHECKSIG"]),
            id="the-op-codes-alone-are-what-is-counted",
        ),
        pytest.param(0, bytes.fromhex("01ac"), id="an-op-code-byte-pushed-is-data"),
        pytest.param(
            1, bytes.fromhex("01acac"), id="and-the-byte-after-the-push-is-not"
        ),
        pytest.param(0, bytes.fromhex("4bac"), id="a-truncated-push-ends-the-walk"),
        pytest.param(
            1, bytes.fromhex("ac4bac"), id="what-was-read-before-it-is-counted"
        ),
    ],
)
def test_sig_op_count(count: int, script: bytes) -> None:
    """The four op codes that count, and the three things that do not.

    Data is not an op code; a truncated push ends the walk without an
    exception, Core's loop `break`ing where `GetOp` returns false; and the
    keys a multisig pushes do not change its cost, `fAccurate` being false
    here, so every `OP_CHECKMULTISIG` costs `MAX_PUBKEYS_PER_MULTISIG`
    whatever it would actually check.

    An `OP_CHECKSIG` with nothing to check is still an `OP_CHECKSIG`: the
    count is what the bytes announce, which is what makes it computable
    without the outputs being spent.
    """
    assert sig_op_count(script) == count
    # Octets, as the rest of the public surface takes them
    assert sig_op_count(script.hex()) == count
