# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `sig_hash.PrecomputedTxData`.

No vector file here: what is asserted is that computing the
transaction-wide hashes once answers exactly what computing them per
input did, on every branch of both segwit sig_hash flavours, and that a
loop over the inputs now hashes the transaction once instead of N times
(issue #164). The hashes themselves are pinned against the BIP143 and
BIP341 vectors by the three test modules beside this one.
"""

from dataclasses import FrozenInstanceError

import pytest

from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash256, sha256
from btclib.script import ScriptPubKey, Witness, sig_hash
from btclib.script.engine import ALL_FLAGS, verify_transaction
from btclib.script.script import serialize
from btclib.script.sig_hash import PrecomputedTxData
from btclib.script.taproot import output_prvkey
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut

PRV_KEY = 0xC28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
PUB_KEY = pub_keyinfo_from_prv_key(PRV_KEY)[0]

WITNESS_SCRIPT = serialize([PUB_KEY, "OP_CHECKSIG"])
P2WPKH_SCRIPT = ScriptPubKey.p2wpkh(PUB_KEY).script
P2WSH_SCRIPT = ScriptPubKey.p2wsh(WITNESS_SCRIPT).script

# no signature is verified by a sig_hash, so any 64 bytes will do: what
# it reads off the witness is the length of the stack, and the annex
SIGNATURE = b"\x01" * 64
CONTROL = b"\xc0" + b"\x02" * 32
ANNEX = b"\x50" + b"\x03" * 10

# one input of every kind from_tx dispatches on, the two taproot ones
# covering the key path and a script path carrying an annex
INPUTS: list[tuple[str, ScriptPubKey, bytes, Witness]] = [
    ("p2pkh", ScriptPubKey.p2pkh(PUB_KEY), b"", Witness()),
    ("p2sh", ScriptPubKey.p2sh(WITNESS_SCRIPT), serialize([WITNESS_SCRIPT]), Witness()),
    ("p2wpkh", ScriptPubKey.p2wpkh(PUB_KEY), b"", Witness([SIGNATURE])),
    (
        "p2wsh",
        ScriptPubKey.p2wsh(WITNESS_SCRIPT),
        b"",
        Witness([SIGNATURE, WITNESS_SCRIPT]),
    ),
    (
        "p2sh-p2wpkh",
        ScriptPubKey.p2sh(P2WPKH_SCRIPT),
        serialize([P2WPKH_SCRIPT]),
        Witness([SIGNATURE]),
    ),
    (
        "p2sh-p2wsh",
        ScriptPubKey.p2sh(P2WSH_SCRIPT),
        serialize([P2WSH_SCRIPT]),
        Witness([SIGNATURE, WITNESS_SCRIPT]),
    ),
    ("p2tr-key-path", ScriptPubKey.p2tr(PUB_KEY), b"", Witness([SIGNATURE])),
    (
        "p2tr-script-path",
        ScriptPubKey.p2tr(PUB_KEY),
        b"",
        Witness([SIGNATURE, WITNESS_SCRIPT, CONTROL, ANNEX]),
    ),
]

# the four inputs above that reach segwit_v0 plus the two that reach
# taproot: the two legacy ones commit to no transaction-wide hash at all
SEGWIT_INPUTS = 6

INPUT_PARAMS = [pytest.param(i, id=kind) for i, (kind, *_) in enumerate(INPUTS)]


def spending_tx() -> tuple[Tx, list[TxOut]]:
    """Build a transaction spending one output of each kind, and the utxos.

    The sequences differ input by input and the amounts output by
    output, so that a hash taken over the wrong one of them, or in the
    wrong order, cannot come out equal by accident. There are as many
    outputs as inputs because SIGHASH_SINGLE needs one per input --
    taproot refuses the spend outright where it has none.
    """
    vin = [
        TxIn(OutPoint(bytes([i + 1]) * 32, i), script_sig, 0xFFFFFFF0 + i, witness)
        for i, (_, _, script_sig, witness) in enumerate(INPUTS)
    ]
    vout = [TxOut(1000 + i, ScriptPubKey.p2pkh(PUB_KEY)) for i in range(len(INPUTS))]
    prevouts = [TxOut(10000 + i, spk) for i, (_, spk, _, _) in enumerate(INPUTS)]
    return Tx(2, 500000, vin, vout), prevouts


@pytest.mark.parametrize("hash_type", sig_hash.SIG_HASH_TYPES)
@pytest.mark.parametrize("vin_i", INPUT_PARAMS)
def test_precomputed_answers_the_same(vin_i: int, hash_type: int) -> None:
    """The precomputed data must not change a single sig_hash.

    Every input of the transaction against every hash type of BIP143
    and BIP341: the pairs cover the ANYONECANPAY branch, which commits
    to no transaction-wide hash, and the SINGLE one, which commits to
    one output only and so cannot be precomputed either.
    """
    tx, prevouts = spending_tx()
    precomputed = PrecomputedTxData(tx, prevouts)
    assert sig_hash.from_tx(
        prevouts, tx, vin_i, hash_type, precomputed
    ) == sig_hash.from_tx(prevouts, tx, vin_i, hash_type)


def test_bip143_hashes_the_same_serializations_as_bip341() -> None:
    """hash256 is sha256 twice, and the two BIPs hash the same bytes.

    Which is why there are five serializations and not ten: the BIP143
    `hash_` properties are one further sha256 over the BIP341 `sha_`
    attributes. Asserted against each BIP's own definition, spelled out
    here from the transaction rather than taken from the module.
    """
    tx, prevouts = spending_tx()
    precomputed = PrecomputedTxData(tx, prevouts)

    prev_outs = b"".join(vin.prev_out.serialize() for vin in tx.vin)
    sequences = b"".join(
        vin.sequence.to_bytes(4, byteorder="little", signed=False) for vin in tx.vin
    )
    outputs = b"".join(vout.serialize() for vout in tx.vout)

    assert precomputed.sha_prevouts == sha256(prev_outs)
    assert precomputed.sha_sequences == sha256(sequences)
    assert precomputed.sha_outputs == sha256(outputs)
    assert precomputed.hash_prev_outs == hash256(prev_outs)
    assert precomputed.hash_seqs == hash256(sequences)
    assert precomputed.hash_outputs == hash256(outputs)

    # the two BIP341 adds, which come from the utxo set and not from the
    # transaction. The length prefix is written out rather than taken
    # from var_bytes: every script here is shorter than 253 bytes
    assert precomputed.sha_amounts == sha256(
        b"".join(
            prevout.value.to_bytes(8, byteorder="little", signed=False)
            for prevout in prevouts
        )
    )
    assert precomputed.sha_script_pub_keys == sha256(
        b"".join(
            len(prevout.script_pub_key.script).to_bytes(1, "little")
            + prevout.script_pub_key.script
            for prevout in prevouts
        )
    )


def test_prevouts_must_match_the_inputs() -> None:
    """A prevout list of the wrong length hashes the wrong utxo set."""
    tx, prevouts = spending_tx()
    with pytest.raises(BTClibValueError, match="prevouts for "):
        PrecomputedTxData(tx, prevouts[:-1])


def test_precomputed_is_a_snapshot() -> None:
    """It must be a snapshot of the transaction, not a view onto it.

    `Tx` is mutable, so a hash computed lazily out of the caller's
    transaction would be issue #140 again: a sig_hash that changed under
    the caller between two calls. The instance is frozen, and everything
    in it was computed by the constructor.
    """
    tx, prevouts = spending_tx()
    precomputed = PrecomputedTxData(tx, prevouts)
    before = (precomputed.sha_prevouts, precomputed.sha_sequences)

    tx.vin[0].prev_out = OutPoint(b"\xff" * 32, 7)
    tx.vin[0].sequence = 0
    assert (precomputed.sha_prevouts, precomputed.sha_sequences) == before

    with pytest.raises(FrozenInstanceError):
        precomputed.sha_prevouts = b""  # type: ignore[misc]


def test_precomputed_must_describe_this_transaction() -> None:
    """Nothing checks that it does, and this is what it costs.

    It is the documented contract, and the reason the class holds no
    reference to the transaction: an instance outliving its transaction
    is a wrong answer waiting to be given. The assertion is that the
    wrong one really does give a different hash, i.e. that the sig_hash
    uses what it was handed rather than quietly recomputing it.
    """
    tx, prevouts = spending_tx()
    one_input = Tx(2, 500000, tx.vin[:1], tx.vout, check_validity=False)

    vin_i = 2  # the p2wpkh input
    honest = sig_hash.from_tx(prevouts, tx, vin_i, sig_hash.ALL)
    wrong = sig_hash.from_tx(
        prevouts, tx, vin_i, sig_hash.ALL, PrecomputedTxData(one_input, prevouts[:1])
    )
    assert honest != wrong


def count_prevout_hashings(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count how often the prevouts of the whole transaction get serialized."""
    calls = [0]
    serialized_prevouts = sig_hash._serialized_prevouts

    def counted(tx: Tx) -> bytes:
        calls[0] += 1
        return serialized_prevouts(tx)

    monkeypatch.setattr(sig_hash, "_serialized_prevouts", counted)
    return calls


def test_from_tx_loop_hashes_the_transaction_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Θ(N²) of issue #164, and its absence.

    Without the precomputed data every segwit input rebuilds the
    prevouts of the whole transaction: N passes over N inputs, which is
    what the issue measured as 15 μs per input at N=1 and 414 μs at
    N=400. With it there is one pass, in the constructor.
    """
    tx, prevouts = spending_tx()
    calls = count_prevout_hashings(monkeypatch)

    for vin_i in range(len(tx.vin)):
        sig_hash.from_tx(prevouts, tx, vin_i, sig_hash.ALL)
    assert calls[0] == SEGWIT_INPUTS

    calls[0] = 0
    precomputed = PrecomputedTxData(tx, prevouts)
    for vin_i in range(len(tx.vin)):
        sig_hash.from_tx(prevouts, tx, vin_i, sig_hash.ALL, precomputed)
    assert calls[0] == 1


def signed_tx(kind: str) -> tuple[Tx, list[TxOut]]:
    """Three inputs of one kind, spent and signed, for the engine to verify.

    `verify_transaction` is the caller that owns the loop over the
    inputs, so it is where the sharing has to hold end to end: a
    transaction it accepts with the midstates computed per input must
    still be one it accepts with them computed once.
    """
    p2wpkh = kind == "p2wpkh"
    script_pub_key = (
        ScriptPubKey.p2wpkh(PUB_KEY) if p2wpkh else ScriptPubKey.p2tr(PUB_KEY)
    )
    prevouts = [TxOut(10000 + i, script_pub_key) for i in range(3)]
    # a placeholder witness of the right length: neither sig_hash commits
    # to a signature, so signing below can replace it
    vin = [
        TxIn(
            OutPoint(bytes([i + 1]) * 32, i), b"", 0xFFFFFFF0 + i, Witness([SIGNATURE])
        )
        for i in range(3)
    ]
    tx = Tx(2, 0, vin, [TxOut(9000, ScriptPubKey.p2pkh(PUB_KEY))])

    for i in range(len(vin)):
        if p2wpkh:
            msg_hash = sig_hash.from_tx(prevouts, tx, i, sig_hash.ALL)
            der = dsa.sign_(msg_hash, PRV_KEY).serialize()
            tx.vin[i].script_witness = Witness([der + b"\x01", PUB_KEY])
        else:
            msg_hash = sig_hash.from_tx(prevouts, tx, i, sig_hash.DEFAULT)
            signature = ssa.sign_(msg_hash, output_prvkey(PRV_KEY)).serialize()
            tx.vin[i].script_witness = Witness([signature])

    return tx, prevouts


@pytest.mark.parametrize("kind", ["p2wpkh", "p2tr"])
def test_verify_transaction_hashes_the_transaction_once(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`verify_transaction` builds the midstates once for its whole loop.

    The signatures are real, so the count is asserted on a transaction
    that verifies: were the shared data the wrong data, this would fail
    as an invalid signature before reaching the assertion.
    """
    tx, prevouts = signed_tx(kind)
    calls = count_prevout_hashings(monkeypatch)

    verify_transaction(prevouts, tx, ALL_FLAGS)

    assert calls[0] == 1
