# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.psbt_size` module.

What an estimate has to be checked against is transactions that were
really signed, so the vectors here are exactly that: BIP174's own
example, taken to the psbt an Updater hands to a Signer and compared
against the network serialization BIP174 publishes; BIP371's key path
psbt, compared against the signature it carries; and two whole blocks,
whose every spend is turned back into the psbt it was signed from.

The last of those is where the arithmetic is really exercised -- some
two thousand inputs of five types -- and it is exact rather than
approximate: the estimate of an input equals what the input really
took, with every signature in it at the assumed 72 bytes. Which is the
whole claim of the module, in the one form that cannot be satisfied by
a table copied out of it.
"""

from __future__ import annotations

from copy import deepcopy
from itertools import starmap

import pytest

from btclib.bip32 import BIP32KeyOrigin
from btclib.block import Block
from btclib.curves import mult
from btclib.curves.sec_point import bytes_from_point
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt, PsbtIn, PsbtOut, extract_tx
from btclib.psbt.psbt_size import (
    SCHNORR_SIG_SIZE,
    SIG_SIZE,
    estimated_input_sizes,
)
from btclib.script import ScriptPubKey, Witness, is_p2ms, parse, serialize
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import load, load_bin, vector_id

# BIP174's example, at the two stages this file needs it: what the
# Signer was given, and what the Extractor produced. Both are the
# vectors psbt_test.py carries -- the second in test_extract_tx, the
# first in test_finalize -- and here for what they are rather than for
# what they parse to
BIP174_SIGNED_PSBT = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
BIP174_FINALIZED_PSBT = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="

# block 170's transaction and the p2pk output it spends: the pair
# sig_hash_legacy_test.py reads, and the suite's only signed p2pk
BLOCK_170_TX = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000"
BLOCK_170_UTXO = "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"

# the fingerprint and path of a derivation nobody derives from here: what
# an updater fills in beside a pub key, and what the estimate reads that
# pub key out of
DUMMY_KEY_ORIGIN = BIP32KeyOrigin("deadbeef", "m/0")


def bip371_psbt(index: int) -> Psbt:
    """Return the BIP371 valid psbt at this index, decoded."""
    vectors = load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"]
    return Psbt.b64decode(vectors[index]["encoded psbt"])


def unsigned(psbt: Psbt) -> Psbt:
    """Return the psbt as the Updater left it: the signatures dropped."""
    psbt = deepcopy(psbt)
    for psbt_in in psbt.inputs:
        psbt_in.partial_sigs = {}
        psbt_in.taproot_key_spend_signature = b""
    return psbt


def pushes(script: bytes) -> list[bytes] | None:
    """Return the byte strings the script pushes, None if it is not that."""
    out: list[bytes] = []
    for command in parse(script):
        if command == "OP_0":
            out.append(b"")
        elif isinstance(command, str) and all(c in "0123456789ABCDEF" for c in command):
            out.append(bytes.fromhex(command))
        else:
            # unreached by either block: a coinbase is skipped before it
            # gets here, and every other script_sig in the two is pushes
            # and nothing else. The guard is what keeps the answer None
            # rather than a misreading the day a corpus grows a spend
            # whose script_sig executes something
            return None  # pragma: no cover
    return out


def is_sig(element: bytes) -> bool:
    """Whether a stack element is a DER signature and a sig_hash byte.

    strict=False and check_validity=False, because the question is what
    the signer put there and not whether it would be accepted today:
    block 200000 predates BIP66, and a third of its signatures encode an
    r with the high bit set and no leading zero. Validating instead of
    parsing would also cost a modular square root per element, `r` being
    checked against the curve.
    """
    try:
        dsa.Sig.parse(element[:-1], strict=False, check_validity=False)
    except BTClibValueError:
        return False
    return True


def psbt_input_from_spend(tx_in: TxIn) -> tuple[PsbtIn, bytes] | None:  # noqa: PLR0911
    """Rebuild the PsbtIn an Updater would have, read off the signed input.

    A spend says what it spent: the pub key of a p2pkh script_sig
    hash160s to the payload of the script_pub_key, the redeem script is
    the last push, the witness script the last stack element. None where
    the shape is one this cannot invert -- and the estimate of an input
    is what this is for, so where it answers None nothing is claimed.
    """
    script_sig = tx_in.script_sig
    stack = list(tx_in.script_witness.stack)
    script_sig_pushes = pushes(script_sig) if script_sig else []
    if script_sig_pushes is None or (script_sig and not script_sig_pushes):
        return None  # pragma: no cover
    redeem_script = script_sig_pushes[-1] if script_sig_pushes else b""

    if stack:
        if len(stack) == 2 and len(stack[1]) in {33, 65}:
            program = ScriptPubKey.p2wpkh(stack[1]).script
            witness_script = b""
        elif is_p2ms(stack[-1]):
            program = ScriptPubKey.p2wsh(stack[-1]).script
            witness_script = stack[-1]
        else:
            # the witness shapes below are the ones the corpus holds; a
            # key path taproot spend is what would reach this, and the
            # blocks predate it
            return None  # pragma: no cover
        # the script_sig of a segwit input is empty, or the push of the
        # program and nothing else, which is what p2sh-wrapping is. One
        # comparison rather than three, the push being what says both
        # that there is a single one and that it is the program
        if script_sig and script_sig != serialize([program]):
            return None  # pragma: no cover
        script_pub_key = ScriptPubKey.p2sh(program).script if script_sig else program
        psbt_in = PsbtIn(
            witness_utxo=TxOut(1000, script_pub_key, check_validity=False),
            redeem_script=redeem_script,
            witness_script=witness_script,
            check_validity=False,
        )
        return psbt_in, script_pub_key

    if len(script_sig_pushes) == 2 and len(script_sig_pushes[1]) in {33, 65}:
        pub_key = script_sig_pushes[1]
        psbt_in = PsbtIn(hd_key_paths={pub_key: DUMMY_KEY_ORIGIN}, check_validity=False)
        return psbt_in, ScriptPubKey.p2pkh(pub_key).script

    if is_p2ms(redeem_script):
        psbt_in = PsbtIn(redeem_script=redeem_script, check_validity=False)
        return psbt_in, ScriptPubKey.p2sh(redeem_script).script

    return None


def psbt_from_spend(tx: Tx) -> Psbt | None:
    """Rebuild the psbt the transaction was signed from, None if unreadable.

    check_validity=False throughout: the psbt is built to be measured
    and not to be signed again, and validating it would decompress a
    pub key per input for nothing.
    """
    tx = deepcopy(tx)
    inputs: list[PsbtIn] = []
    for i, tx_in in enumerate(tx.vin):
        built = psbt_input_from_spend(tx_in)
        if built is None:
            return None
        psbt_in, script_pub_key = built
        if psbt_in.witness_utxo is None:
            # a legacy input carries the whole previous transaction, and
            # a psbt whose non_witness_utxo does not hash to the outpoint
            # is one assert_valid refuses -- so the outpoint is moved to
            # the transaction built here, which changes no size: an
            # outpoint is 36 bytes whatever is in it.
            # One such transaction per input, told apart by the index it
            # spends: two inputs paying the same script_pub_key would
            # otherwise be funded by the same transaction and left naming
            # one outpoint twice, which is `bad-txns-inputs-duplicate`
            prev_tx = Tx(
                1,
                0,
                [TxIn(OutPoint(b"\x01" * 32, i))],
                [TxOut(1000, script_pub_key, check_validity=False)],
                check_validity=False,
            )
            tx_in.prev_out = OutPoint(prev_tx.id, 0)
            psbt_in.non_witness_utxo = prev_tx
        inputs.append(psbt_in)
        tx_in.script_sig = b""
        tx_in.script_witness = Witness()
    outputs = [PsbtOut() for _ in tx.vout]
    # from_tx and not Psbt(...): the outpoint and sequence of each input
    # are the input's own now, and taking the transaction apart into them
    # is what this classmethod is
    return Psbt.from_tx(tx, inputs, outputs, check_validity=False)


def assert_input_is_the_spend_with_maximal_signatures(psbt: Psbt, signed: Tx) -> int:
    """Each estimate is the real spend, every signature at 72 bytes.

    Returns how many bytes of signature the estimate added, which is
    negative where the transaction predates the low-s rule: a high-s
    signature is 73 bytes and no estimate assuming 72 is an upper bound
    for it.
    """
    added = 0
    for psbt_in, tx_in, signed_in in zip(
        psbt.inputs, psbt.tx.vin, signed.vin, strict=True
    ):
        script_sig_size, witness_sizes = estimated_input_sizes(psbt_in, tx_in)

        in_script_sig = sum(
            SIG_SIZE - len(push)
            for push in pushes(signed_in.script_sig) or []
            if is_sig(push)
        )
        assert script_sig_size == len(signed_in.script_sig) + in_script_sig

        stack = signed_in.script_witness.stack
        assert witness_sizes == [
            SIG_SIZE if is_sig(element) else len(element) for element in stack
        ]
        added += in_script_sig + sum(witness_sizes) - sum(len(e) for e in stack)
    return added


def test_the_bip174_example_is_bounded_by_its_signed_transaction() -> None:
    """The Updater's psbt against the transaction BIP174 publishes."""
    signed = extract_tx(Psbt.b64decode(BIP174_FINALIZED_PSBT))
    psbt = unsigned(Psbt.b64decode(BIP174_SIGNED_PSBT))

    assert psbt.estimated_weight >= signed.weight
    assert psbt.estimated_vsize >= signed.vsize
    # four signatures, three of them a byte short of the assumption: two
    # in the script_sig of the p2sh input, at four weight units each, and
    # two in the witness of the p2sh-p2wsh one, at one
    assert assert_input_is_the_spend_with_maximal_signatures(psbt, signed) == 3
    assert psbt.estimated_weight - signed.weight == 6


def test_an_incoherent_psbt_is_not_estimated() -> None:
    """A weight is a number, and a number is what a fee is computed from.

    Every other public method of `Psbt` that reads this psbt's data
    validates it first; this one did not, so a psbt BIP174 calls invalid
    -- here a v0 carrying the v2-only PSBT_GLOBAL_TX_MODIFIABLE -- came
    back with an estimate rather than with the refusal `assert_valid`
    was there to give.
    """
    psbt = unsigned(Psbt.b64decode(BIP174_SIGNED_PSBT))
    assert psbt.weight_estimate() > 0

    psbt.tx_modifiable = 1
    err_msg = "PSBT_GLOBAL_TX_MODIFIABLE is not allowed in a v0 psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.weight_estimate()
    with pytest.raises(BTClibValueError, match=err_msg):
        _ = psbt.estimated_weight
    with pytest.raises(BTClibValueError, match=err_msg):
        _ = psbt.estimated_vsize


def test_a_finalized_input_is_not_estimated() -> None:
    """What the Finalizer produced is what the transaction will carry."""
    psbt = Psbt.b64decode(BIP174_FINALIZED_PSBT)
    signed = extract_tx(deepcopy(psbt))

    assert psbt.estimated_weight == signed.weight
    assert psbt.estimated_vsize == signed.vsize


def test_a_taproot_key_path_is_its_signature() -> None:
    """BIP371's key path psbt against the signature the next one holds."""
    signature = bip371_psbt(1).inputs[0].taproot_key_spend_signature
    assert len(signature) == 64

    signed = bip371_psbt(1).tx
    signed.vin[0].script_witness = Witness([signature])

    psbt = bip371_psbt(0)
    assert psbt.tx.id == signed.id
    assert psbt.estimated_weight == signed.weight
    assert psbt.estimated_vsize == signed.vsize


def test_a_taproot_sig_hash_type_costs_the_byte_it_is() -> None:
    """SIGHASH_DEFAULT is the absence of the byte, and the only one."""
    psbt = bip371_psbt(0)
    default = psbt.estimated_weight

    psbt.inputs[0].sig_hash_type = 0  # SIGHASH_DEFAULT, spelled out
    assert psbt.estimated_weight == default

    psbt.inputs[0].sig_hash_type = 1  # SIGHASH_ALL, a byte of witness
    assert psbt.estimated_weight == default + 1


def test_the_first_transaction_is_bounded_by_its_p2pk_spend() -> None:
    """Block 170: one p2pk input, whose script_sig is one signature."""
    signed = Tx.parse(BLOCK_170_TX)
    psbt = Psbt.from_tx(deepcopy(signed))
    psbt.inputs[0].witness_utxo = TxOut(5000000000, BLOCK_170_UTXO)

    assert psbt.estimated_weight >= signed.weight
    assert assert_input_is_the_spend_with_maximal_signatures(psbt, signed) == 1


def spend_kind(tx_in: TxIn, psbt_in: PsbtIn) -> str:
    """Name what `psbt_input_from_spend` made of the input.

    Only so that a corpus can be asserted to hold what it is here for: a
    block is a frozen file, but which types are in it is not something
    to take on trust from a comment.
    """
    if tx_in.script_witness.stack:
        kind = "p2wpkh" if not psbt_in.witness_script else "p2wsh"
        return f"p2sh-{kind}" if tx_in.script_sig else kind
    if psbt_in.redeem_script:
        return "p2sh-p2ms"
    return f"p2pkh-{len((pushes(tx_in.script_sig) or [])[1])}"


def test_the_bip174_spend_is_read_back_off_the_wire() -> None:
    """The same inversion, on the p2sh-p2wsh neither block holds.

    BIP174's transaction is where a witness carrying a multisig is, so
    it is read here the way the blocks below are read -- off the network
    serialization, with nothing of the psbt it was signed from -- rather
    than only from the psbt the earlier tests decode.
    """
    signed = extract_tx(Psbt.b64decode(BIP174_FINALIZED_PSBT))
    psbt = psbt_from_spend(signed)
    assert psbt is not None
    assert list(starmap(spend_kind, zip(signed.vin, psbt.inputs, strict=True))) == [
        "p2sh-p2ms",
        "p2sh-p2wsh",
    ]
    # the three signatures a byte short of the assumption, as above
    assert assert_input_is_the_spend_with_maximal_signatures(psbt, signed) == 3


@pytest.mark.parametrize(
    "block_name, first, kinds",
    [
        # the first 600 transactions of the first segwit block, which is
        # where its seven segwit spends are -- p2wpkh and p2sh-p2wpkh,
        # beside the p2pkh and p2sh-multisig of everything else in it.
        # p2wsh and p2sh-p2wsh are the two neither block holds, and the
        # test above is where those are: BIP174's second input is a
        # p2sh-p2wsh 2-of-2, and the multisig arithmetic does not care
        # which of the three scripts carries the multisig it solves
        (
            "block_481824_complete.bin",
            600,
            {"p2pkh-33", "p2pkh-65", "p2sh-p2ms", "p2sh-p2wpkh", "p2wpkh"},
        ),
        # and a pre-BIP66 block whole, which is where the signatures are
        # 73 bytes: a third of them encode an r with the high bit set and
        # no leading zero, and no estimate assuming low s bounds those
        ("block_200000.bin", None, {"p2pkh-33", "p2pkh-65"}),
    ],
)
def test_a_block_of_real_spends(
    block_name: str, first: int | None, kinds: set[str]
) -> None:
    """Check the estimate of every readable spend in a real block."""
    block = Block.parse(load_bin("block", "_data", block_name))
    checked = 0
    seen: set[str] = set()
    for tx in block.transactions[:first]:
        if tx.is_coinbase:
            continue
        psbt = psbt_from_spend(tx)
        if psbt is None:
            continue
        added = assert_input_is_the_spend_with_maximal_signatures(psbt, tx)
        if added >= 0:
            assert psbt.estimated_weight >= tx.weight
        seen.update(starmap(spend_kind, zip(tx.vin, psbt.inputs, strict=True)))
        checked += 1
    # a corpus that stopped being read would otherwise pass the loop
    # vacuously, and both files are frozen
    assert checked > 300
    assert seen == kinds


def test_an_input_of_an_unreadable_type_has_no_estimate() -> None:
    """The rule that makes the rest of it honest, and it names the input."""
    psbt = Psbt.b64decode(BIP174_SIGNED_PSBT)

    psbt.inputs[1].witness_script = b""
    with pytest.raises(BTClibValueError, match="input 1: no witness script"):
        _ = psbt.estimated_weight

    psbt.inputs[1].redeem_script = b""
    with pytest.raises(BTClibValueError, match="input 1: no redeem script"):
        _ = psbt.estimated_vsize

    psbt.inputs[0].non_witness_utxo = None
    with pytest.raises(BTClibValueError, match="input 0: no utxo"):
        _ = psbt.estimated_weight


def test_a_script_nobody_can_solve_has_no_estimate() -> None:
    """A nulldata output, and an output of no type at all."""
    psbt = Psbt.b64decode(BIP174_SIGNED_PSBT)
    tx_in = psbt.tx.vin[0]

    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = TxOut(1000, ScriptPubKey.nulldata("gm"))
    with pytest.raises(BTClibValueError, match="type 'nulldata'"):
        estimated_input_sizes(psbt.inputs[0], tx_in)

    psbt.inputs[0].witness_utxo = TxOut(1000, "0a0b0c", check_validity=False)
    with pytest.raises(BTClibValueError, match="type 'unknown'"):
        estimated_input_sizes(psbt.inputs[0], tx_in)


def test_a_taproot_script_path_has_no_estimate() -> None:
    """Which leaf will be spent is not something the psbt says."""
    psbt = bip371_psbt(3)
    assert psbt.inputs[0].taproot_leaf_scripts

    with pytest.raises(BTClibValueError, match="taproot script path"):
        _ = psbt.estimated_vsize


def test_a_bare_multisig_is_solved_where_it_is_found() -> None:
    """p2ms as the script_pub_key, and not only as a redeem script."""
    redeem_script = Psbt.b64decode(BIP174_SIGNED_PSBT).inputs[0].redeem_script
    assert is_p2ms(redeem_script)

    psbt = Psbt.b64decode(BIP174_SIGNED_PSBT)
    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = TxOut(1000, redeem_script)

    wrapped, _ = estimated_input_sizes(
        Psbt.b64decode(BIP174_SIGNED_PSBT).inputs[0], psbt.tx.vin[0]
    )
    bare, _ = estimated_input_sizes(psbt.inputs[0], psbt.tx.vin[0])
    # the same signatures, without the push of the redeem script
    assert wrapped - bare == len(serialize([redeem_script]))


@pytest.mark.parametrize(
    "test_vector",
    [
        pytest.param(vector, id=vector_id(index, vector["description"]))
        for index, vector in enumerate(
            load("psbt", "_data", "bip174_test_vectors.json")["valid psbts"], 1
        )
    ],
)
def test_every_bip174_vector_answers(test_vector: dict[str, str]) -> None:
    """Every valid psbt estimates, or says which input it cannot.

    The vectors are not all estimable -- one carries an input with no
    utxo at all -- and what is checked is that each is one or the other,
    with nothing raising anything but a BTClibValueError naming an
    input.
    """
    psbt = Psbt.b64decode(test_vector["encoded psbt"])
    vsize: int | None = None
    refusal = ""
    try:
        vsize = psbt.estimated_vsize
    except BTClibValueError as e:
        refusal = str(e)

    if vsize is None:
        assert refusal.startswith("input ")
    else:
        # the unsigned transaction plus what the signatures will take
        assert vsize >= psbt.tx.vsize


def test_a_sizer_answers_for_the_scripts_this_file_cannot_read() -> None:
    """What a caller who does not have to guess says, and where it is asked.

    A p2wsh of no standard type -- the shape a custody script has, a
    branch chosen by CHECKSEQUENCEVERIFY -- and the whole of what it will
    push, the witness script included: one rule, so that neither side
    appends the other's element.
    """
    witness_script = serialize(["OP_IF", "OP_1", "OP_ELSE", "OP_2", "OP_ENDIF"])
    psbt = Psbt.b64decode(BIP174_SIGNED_PSBT)
    tx_in = psbt.tx.vin[0]
    psbt.inputs[0].non_witness_utxo = None
    psbt.inputs[0].witness_utxo = TxOut(1000, ScriptPubKey.p2wsh(witness_script))
    psbt.inputs[0].witness_script = witness_script
    psbt.inputs[0].redeem_script = b""

    # unasked, the refusal is the one that was there before
    with pytest.raises(BTClibValueError, match="type 'unknown'"):
        estimated_input_sizes(psbt.inputs[0], tx_in)

    stack = [SIG_SIZE, SIG_SIZE, len(witness_script)]
    script_sig_size, witness_sizes = estimated_input_sizes(
        psbt.inputs[0], tx_in, sizer=lambda _in, _tx: list(stack)
    )
    assert witness_sizes == stack
    assert script_sig_size == 0

    # a sizer that does not answer for this input is the refusal again
    with pytest.raises(BTClibValueError, match="type 'unknown'"):
        estimated_input_sizes(psbt.inputs[0], tx_in, sizer=lambda _in, _tx: None)


def test_a_sizer_answers_for_a_taproot_script_path() -> None:
    """Which leaf will be spent is the caller's to say, and then all of it.

    The solution, the leaf script and the control block are one answer
    because one choice decides the three, and the psbt carries every leaf
    it could have been.
    """
    psbt = bip371_psbt(3)
    psbt_in = psbt.inputs[0]
    assert psbt_in.taproot_leaf_scripts

    with pytest.raises(BTClibValueError, match="taproot script path"):
        _ = psbt.estimated_vsize

    ((leaf_script, leaf_version),) = list(psbt_in.taproot_leaf_scripts.values())[:1]
    # the control block of a tree of one leaf: the version byte with the
    # parity, and the internal key
    control_block_size = 33
    stack = [SCHNORR_SIG_SIZE, len(leaf_script), control_block_size]
    assert leaf_version is not None

    def sizer(_in: PsbtIn, _tx: TxIn) -> list[int]:
        return list(stack)

    _, witness_sizes = estimated_input_sizes(psbt_in, psbt.tx.vin[0], sizer=sizer)
    assert witness_sizes == stack

    # and the same answer reaches the weight, which is what a fee is
    # computed from: the placeholder witness is the one the sizer named
    asked = psbt.vsize_estimate(sizer)
    assert asked > psbt.vsize_estimate(lambda _in, _tx: [SCHNORR_SIG_SIZE])


def test_a_sizer_is_never_asked_where_this_file_knows() -> None:
    """A key path spend and a multisig: neither of them is asked about.

    What the sizer was asked about is recorded, and the same recorder
    then meets the input that has to be asked about: the two halves of
    the rule -- asked exactly where this file has no answer, and
    nowhere else -- are one list either way. A sizer that raised would
    state the first half by never running, which is a body no run
    executes and an assertion no test makes.
    """
    asked: list[PsbtIn] = []

    def record(psbt_in: PsbtIn, _tx: TxIn) -> list[int]:
        asked.append(psbt_in)
        return [SCHNORR_SIG_SIZE]

    psbt = Psbt.b64decode(BIP174_SIGNED_PSBT)
    assert psbt.vsize_estimate(record) == psbt.estimated_vsize

    key_path = bip371_psbt(0)
    assert key_path.vsize_estimate(record) == key_path.estimated_vsize
    assert not asked

    script_path = bip371_psbt(3)
    _ = script_path.vsize_estimate(record)
    assert asked == [script_path.inputs[0]]


def test_the_key_of_a_p2pkh_is_looked_up_past_the_ones_that_miss() -> None:
    """An input's hd_key_paths is not one key, so the lookup is a walk.

    An Updater fills that map with every key a Signer may need, and a
    wallet watching more than one account puts more than one there. What
    decides the size is the key that hash160s to the payload of the
    script: an entry ahead of it is stepped over, and a map that answers
    for none of it leaves the estimate at the compressed size, which is
    the assumption the module docstring states.

    Every other p2pkh input here carries exactly the key its script
    commits to, so the miss was never taken.
    """
    uncompressed = bytes_from_point(mult(3), compressed=False)
    miss = bytes_from_point(mult(4))
    script_pub_key = ScriptPubKey.p2pkh(uncompressed).script
    tx_in = TxIn(OutPoint(b"\x01" * 32, 0))

    def sizes(*pub_keys: bytes) -> int:
        # one origin per key, and they have to differ: an hd_key_paths
        # naming the same derivation twice is what assert_valid refuses
        psbt_in = PsbtIn(
            witness_utxo=TxOut(1000, script_pub_key, check_validity=False),
            hd_key_paths={
                pub_key: BIP32KeyOrigin("deadbeef", f"m/{index}")
                for index, pub_key in enumerate(pub_keys)
            },
            check_validity=False,
        )
        return estimated_input_sizes(psbt_in, tx_in)[0]

    # the miss is walked past, and the entry behind it answers
    assert sizes(miss, uncompressed) == sizes(uncompressed)
    # and a map that answers for none of it falls back to compressed
    assert sizes(uncompressed) - sizes(miss) == len(uncompressed) - len(miss)
