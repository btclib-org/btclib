# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""One key signs behind successive OP_CODESEPARATORs of a tapscript leaf.

BIP342 commits each signature to the position of the last executed
OP_CODESEPARATOR. The leaf `<key> (OP_TUCK OP_CHECKSIGVERIFY
OP_CODESEPARATOR) x (n-1) OP_CHECKSIG`, with n = 3 here, makes one key sign n
different messages, one per position.
"""

import itertools

import pytest
from btclib_ecc.ecc import ssa

from btclib.exceptions import ScriptError, ScriptErrorCode
from btclib.script import Witness, sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.taproot import leaf_hash, output_pubkey_from_merkle_root
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_OP_TUCK = b"\x7d"
_OP_CHECKSIGVERIFY = b"\xad"
_OP_CODESEPARATOR = b"\xab"
_OP_CHECKSIG = b"\xac"

_LEAF_VERSION = 0xC0
_INTERNAL_KEY = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
_N = 3
_PRV_KEY, _PUB_KEY_INT = ssa.gen_keys(0x1234)
_PUB_KEY = _PUB_KEY_INT.to_bytes(32, "big")

_LEAF = (
    bytes([len(_PUB_KEY)])
    + _PUB_KEY
    + (_OP_TUCK + _OP_CHECKSIGVERIFY + _OP_CODESEPARATOR) * (_N - 1)
    + _OP_CHECKSIG
)
# op code indices of the separators: the key push is index 0, and each
# group of three op codes ends with one. BIP342 numbers op codes, not bytes.
# The first signature is checked before any separator ran, which BIP342
# marks with 0xFFFFFFFF.
_CODESEP_POSITIONS = [0xFFFFFFFF, 3, 6]

_OUTPUT_KEY, _PARITY = output_pubkey_from_merkle_root(
    _INTERNAL_KEY, leaf_hash(_LEAF_VERSION, _LEAF)
)
_PREVOUT = TxOut(10_000, b"\x51\x20" + _OUTPUT_KEY)
_CONTROL = bytes([_LEAF_VERSION | _PARITY]) + _INTERNAL_KEY


def _spend(signatures: list[bytes]) -> Tx:
    """Return the spend of the leaf; `signatures` are in the order checked."""
    # the first signature checked is the one nearest the key on the stack
    witness = Witness([*reversed(signatures), _LEAF, _CONTROL])
    tx_in = TxIn(OutPoint("01" * 32, 0), b"", 0xFFFFFFFF, witness)
    return Tx(2, 0, [tx_in], [TxOut(9_000, b"\x6a")])


def _sig_hashes(tx: Tx) -> list[bytes]:
    """Return the messages signed at each separator position."""
    tapleaf_hash = leaf_hash(_LEAF_VERSION, _LEAF)
    return [
        sig_hash.taproot(
            tx,
            0,
            [_PREVOUT],
            0,
            1,
            b"",
            tapleaf_hash + b"\x00" + pos.to_bytes(4, "little"),
        )
        for pos in _CODESEP_POSITIONS
    ]


def _signatures() -> list[bytes]:
    return [
        ssa.sign_(msg, _PRV_KEY).serialize() for msg in _sig_hashes(_spend([b""] * _N))
    ]


def test_the_sig_hashes_at_successive_separators_are_pairwise_distinct() -> None:
    """The message differs at each position, so no signature serves two."""
    sig_hashes = _sig_hashes(_spend([b""] * _N))
    assert len(sig_hashes) == _N
    for a, b in itertools.combinations(sig_hashes, 2):
        assert a != b


def test_one_key_signing_each_separator_position_validates() -> None:
    """Each signature is made over the message of its own separator position."""
    verify_transaction([_PREVOUT], _spend(_signatures()))


@pytest.mark.parametrize("a, b", list(itertools.combinations(range(_N), 2)))
def test_swapping_two_signatures_fails(a: int, b: int) -> None:
    """A signature checked at another position does not verify."""
    signatures = _signatures()
    signatures[a], signatures[b] = signatures[b], signatures[a]
    with pytest.raises(ScriptError) as exc_info:
        verify_transaction([_PREVOUT], _spend(signatures))
    assert exc_info.value.code is ScriptErrorCode.SCHNORR_SIG
