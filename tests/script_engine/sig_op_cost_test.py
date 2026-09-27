# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.script.engine.sig_op_cost`.

Core's `GetTxSigOpCost` test case, in src/test/sigopcount_tests.cpp,
re-expressed: each case builds the output a transaction creates and the
transaction spending it, as Core's `BuildTxs` does, and asks the cost of
either under Core's flags. What each term counts of a single input is
`tests/script/sig_ops_test.py`'s.
"""

import pytest

from btclib.consensus import WITNESS_SCALE_FACTOR
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.script import Witness, serialize
from btclib.script.engine import NO_FLAGS, ScriptFlag, ScriptFlags, sig_op_cost
from btclib.script.limits import MAX_PUBKEYS_PER_MULTISIG
from btclib.tx import OutPoint, Tx, TxIn
from btclib.tx.tx_out import TxOut

_KEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)

# Core's default flags in that test case
_FLAGS = "P2SH,WITNESS"

# the multisig every case of Core's builds its scripts from
_MULTISIG = serialize(["OP_1", _KEY, _KEY, "OP_2", "OP_CHECKMULTISIGVERIFY"])


def _p2sh(redeem_script: bytes) -> bytes:
    return serialize(["OP_HASH160", hash160(redeem_script), "OP_EQUAL"])


_P2WPKH = serialize(["OP_0", hash160(_KEY)])
_P2WSH = serialize(["OP_0", sha256(_MULTISIG)])


def _build_txs(
    script_pub_key: bytes, script_sig: bytes, stack: list[bytes]
) -> tuple[Tx, Tx]:
    """Return Core's `BuildTxs`: the coinbase creating, the input spending.

    The coinbase's script_sig is empty, as Core leaves it, which is not a
    valid coinbase to `Tx.assert_valid`: the cost does not ask.
    """
    creation = Tx(
        1,
        0,
        [TxIn(OutPoint(), b"", check_validity=False)],
        [TxOut(1, script_pub_key)],
        check_validity=False,
    )
    spending = Tx(
        1,
        0,
        [TxIn(OutPoint(creation.id, 0), script_sig, 0, Witness(stack))],
        [TxOut(1, b"")],
    )
    return creation, spending


def test_multisig() -> None:
    """Legacy counting reads what a transaction carries, and not accurately.

    The spending transaction carries no signature check; the creating one
    carries an `OP_CHECKMULTISIGVERIFY`, at `MAX_PUBKEYS_PER_MULTISIG`.
    """
    creation, spending = _build_txs(_MULTISIG, serialize(["OP_0", "OP_0"]), [])
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 0
    cost = MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR
    assert sig_op_cost([], creation, _FLAGS) == cost


def test_multisig_nested_in_p2sh() -> None:
    """The redeem script counts accurately, and only under P2SH."""
    script_sig = serialize(["OP_0", "OP_0", _MULTISIG])
    creation, spending = _build_txs(_p2sh(_MULTISIG), script_sig, [])
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 2 * WITNESS_SCALE_FACTOR
    assert sig_op_cost(creation.vout, spending, NO_FLAGS) == 0


def test_p2wpkh() -> None:
    """One, at one; nothing without WITNESS, for version 1, or in a coinbase."""
    creation, spending = _build_txs(_P2WPKH, b"", [b"", b""])
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 1
    assert sig_op_cost(creation.vout, spending, "P2SH") == 0

    creation, spending = _build_txs(b"\x51" + _P2WPKH[1:], b"", [b"", b""])
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 0

    creation, spending = _build_txs(_P2WPKH, b"", [b"", b""])
    coinbase = Tx(
        1,
        0,
        [TxIn(OutPoint(), b"", 0, Witness([b"", b""]), check_validity=False)],
        spending.vout,
        check_validity=False,
    )
    assert coinbase.is_coinbase
    assert sig_op_cost(creation.vout, coinbase, _FLAGS) == 0


def test_p2wpkh_nested_in_p2sh() -> None:
    """The program is the redeem script, and costs what it costs bare."""
    creation, spending = _build_txs(_p2sh(_P2WPKH), serialize([_P2WPKH]), [b"", b""])
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 1


def test_p2wsh() -> None:
    """The witness script counts accurately, at one, and only under WITNESS."""
    creation, spending = _build_txs(_P2WSH, b"", [b"", b"", _MULTISIG])
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 2
    assert sig_op_cost(creation.vout, spending, "P2SH") == 0


def test_p2wsh_nested_in_p2sh() -> None:
    """The program is the redeem script, and costs what it costs bare."""
    creation, spending = _build_txs(
        _p2sh(_P2WSH), serialize([_P2WSH]), [b"", b"", _MULTISIG]
    )
    assert sig_op_cost(creation.vout, spending, _FLAGS) == 2


@pytest.mark.parametrize(
    "flags",
    [
        pytest.param(None, id="the-default-flags"),
        pytest.param(ScriptFlag.P2SH | ScriptFlag.WITNESS, id="the-bitmask"),
        pytest.param(["P2SH", "WITNESS"], id="the-names"),
    ],
)
def test_every_spelling_of_the_flags(flags: ScriptFlags | None) -> None:
    """`flags` is what `verify_transaction` takes, and None is ALL_FLAGS."""
    creation, spending = _build_txs(_P2WSH, b"", [b"", b"", _MULTISIG])
    assert sig_op_cost(creation.vout, spending, flags) == 2


def test_witness_without_p2sh() -> None:
    """Refused, where Core's `CountWitnessSigOps` asserts against it."""
    creation, spending = _build_txs(_P2WSH, b"", [b"", b"", _MULTISIG])
    with pytest.raises(BTClibValueError, match="WITNESS without P2SH"):
        sig_op_cost(creation.vout, spending, "WITNESS")


def test_one_prevout_per_input() -> None:
    """A prevout is the output an input spends, so they pair one to one."""
    creation, spending = _build_txs(_P2WSH, b"", [b"", b"", _MULTISIG])
    with pytest.raises(BTClibValueError, match="2 prevouts for 1 transaction inputs"):
        sig_op_cost(creation.vout * 2, spending, _FLAGS)
