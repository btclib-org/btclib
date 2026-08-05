# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.sig_hash` module.

test vector at
https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
"""

import pytest

from btclib import var_bytes
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash256
from btclib.script import Witness, sig_hash
from btclib.tx import OutPoint, Tx, TxIn, TxOut


def test_native_p2wpkh() -> None:
    """Reproduce BIP143's native p2wpkh example."""
    tx_bytes = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
    tx = Tx.parse(tx_bytes)

    utxo_0 = TxOut(
        625000000,
        "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
    )
    utxo_1 = TxOut(600000000, "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")

    hash_ = sig_hash.from_tx([utxo_0, utxo_1], tx, 1, sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    )


def test_wrapped_p2wpkh() -> None:
    """Reproduce BIP143's p2sh-p2wpkh example, script_sig on the wire."""
    tx_bytes = "0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000"
    tx = Tx.parse(tx_bytes)
    # the script_sig as it goes on the wire: the 0x16 push of the 22-byte
    # redeem script, not the bare redeem script (issue #136)
    tx.vin[0].script_sig = bytes.fromhex(
        "16001479091972186c449eb1ded22b78e40d009bdf0089"
    )

    utxo = TxOut(1000000000, "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387")

    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
    )


def test_native_p2wsh() -> None:
    """Reproduce BIP143's native p2wsh example, OP_CODESEPARATOR too."""
    tx_bytes = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
    tx = Tx.parse(tx_bytes)
    tx.vin[1].script_witness = Witness(
        [
            "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
        ]
    )

    utxo_0 = TxOut(
        156250000,
        "21036d5c20fa14fb2f635474c1dc4ef5909d4568e5569b79fc94d3448486e14685f8ac",
    )
    utxo_1 = TxOut(
        4900000000,
        "00205d1b56b63d714eebe542309525f484b7e9d6f686b3781b6f61ef925d66d6f6a0",
    )

    hash_ = sig_hash.from_tx([utxo_0, utxo_1], tx, 1, sig_hash.SINGLE)
    assert hash_ == bytes.fromhex(
        "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
    )

    # the second signature of the same input, checked after the
    # OP_CODESEPARATOR has executed: BIP143 prints its script code, and
    # it is the witness script from just past that byte -- separators
    # kept, only the truncation applied
    script_ = bytes.fromhex(
        "210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
    )
    assert tx.vin[1].script_witness.stack[-1].endswith(script_)
    hash_ = sig_hash.segwit_v0(script_, tx, 1, sig_hash.SINGLE, utxo_1.value)
    assert hash_ == bytes.fromhex(
        "fef7bd749cce710c5c052bd796df1af0d935e59cea63736268bcbe2d2134fc47"
    )
    # and asked of from_tx, which counts the occurrence for the caller
    assert hash_ == sig_hash.from_tx(
        [utxo_0, utxo_1], tx, 1, sig_hash.SINGLE, codesep_index=1
    )


def test_native_p2wsh_2() -> None:
    """Reproduce BIP143's second p2wsh example, one branch per input."""
    tx_bytes = "0100000002e9b542c5176808107ff1df906f46bb1f2583b16112b95ee5380665ba7fcfc0010000000000ffffffff80e68831516392fcd100d186b3c2c7b95c80b53c77e77c35ba03a66b429a2a1b0000000000ffffffff0280969800000000001976a914de4b231626ef508c9a74a8517e6783c0546d6b2888ac80969800000000001976a9146648a8cd4531e1ec47f35916de8e259237294d1e88ac00000000"
    tx = Tx.parse(tx_bytes)
    tx.vin[0].script_witness = Witness(
        [
            "0063ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
        ]
    )
    tx.vin[1].script_witness = Witness(
        [
            "5163ab68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
        ]
    )

    previous_txout_1 = TxOut(
        16777215, "0020ba468eea561b26301e4cf69fa34bde4ad60c81e70f059f045ca9a79931004a4d"
    )
    previous_txout_2 = TxOut(
        16777215, "0020d9bbfbe56af7c4b7f960a70d7ea107156913d9e5a26b0a71429df5e097ca6537"
    )
    hash_ = sig_hash.from_tx(
        [previous_txout_1, previous_txout_2],
        tx,
        0,
        sig_hash.ANYONECANPAY | sig_hash.SINGLE,
    )
    assert hash_ == bytes.fromhex(
        "e9071e75e25b8a1e298a72f0d2e9f4f95a0f5cdf86a533cda597eb402ed13b3a"
    )

    # input 1 takes the branch input 0 does not -- OP_1 against OP_0 --
    # so the same OP_CODESEPARATOR occurrence executes here and not
    # there, which is why the index is the caller's to give
    script_ = bytes.fromhex(
        "68210392972e2eb617b2388771abe27235fd5ac44af8e61693261550447a4c3e39da98ac"
    )
    assert tx.vin[1].script_witness.stack[-1].endswith(script_)
    hash_ = sig_hash.segwit_v0(
        script_,
        tx,
        1,
        sig_hash.ANYONECANPAY | sig_hash.SINGLE,
        previous_txout_2.value,
    )
    assert hash_ == bytes.fromhex(
        "cd72f1f1a433ee9df816857fad88d8ebd97e09a75cd481583eb841c330275e54"
    )
    assert hash_ == sig_hash.from_tx(
        [previous_txout_1, previous_txout_2],
        tx,
        1,
        sig_hash.ANYONECANPAY | sig_hash.SINGLE,
        codesep_index=1,
    )


def test_wrapped_p2wsh() -> None:
    """Reproduce BIP143's p2sh-p2wsh example over all six hash types."""
    tx_bytes = "010000000136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000000ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac00000000"
    tx = Tx.parse(tx_bytes)
    stack = [
        "56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae"
    ]
    tx.vin[0].script_witness = Witness(stack)
    # again the wire form: the 0x22 push of the p2wsh redeem script
    tx.vin[0].script_sig = bytes.fromhex(
        "220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54"
    )

    utxo = TxOut(987654321, "a9149993a429037b5d912407a71c252019287b8d27a587")

    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.NONE)
    assert hash_ == bytes.fromhex(
        "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.SINGLE)
    assert hash_ == bytes.fromhex(
        "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ANYONECANPAY | sig_hash.ALL)
    assert hash_ == bytes.fromhex(
        "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ANYONECANPAY | sig_hash.NONE)
    assert hash_ == bytes.fromhex(
        "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a"
    )
    hash_ = sig_hash.from_tx([utxo], tx, 0, sig_hash.ANYONECANPAY | sig_hash.SINGLE)
    assert hash_ == bytes.fromhex(
        "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b"
    )


# issue 252: SIGHASH_SINGLE for an input past the last output


# BIP143's own out-of-range example, the one `test_native_p2wsh` signs:
# two inputs and a single output, so input 1 has no output of its own
_BIP143_TX = "0100000002fe3dc9208094f3ffd12645477b3dc56f60ec4fa8e6f5d67c565d1c6b9216b36e0000000000ffffffff0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f80000000000ffffffff0100f2052a010000001976a914a30741f8145e5acadf23f751864167f32e0963f788ac00000000"
_WITNESS_SCRIPT = "21026dccc749adc2a9d0d89497ac511f760f45c47dc5ed9cf352a58ac706453880aeadab210255a9626aebf5e29c0e6538428ba0d1dcf6ca98ffdf086aa8ced5e0d0215ea465ac"
_AMOUNT = 4900000000


def _bip143_preimage(
    tx: Tx, vin_i: int, script_code: bytes, amount: int, hash_outputs: bytes
) -> bytes:
    """BIP143's field list, written out, for a SIGHASH_SINGLE input.

    The rule under test is one field of it — "hashOutputs is a uint256
    of 0x0000......0000" when the input index is beyond the last output
    — so the field is a parameter and the other ten are spelled here
    rather than asked of the code being checked. hashSequence is zero
    because SINGLE says so, and hashPrevouts is the only one hashed.
    """
    prev_outs = b"".join(vin.prev_out.serialize() for vin in tx.vin)
    return b"".join(
        [
            tx.version.to_bytes(4, "little"),
            hash256(prev_outs),
            b"\x00" * 32,
            tx.vin[vin_i].prev_out.serialize(),
            var_bytes.serialize(script_code),
            amount.to_bytes(8, "little", signed=True),  # a CAmount
            tx.vin[vin_i].sequence.to_bytes(4, "little"),
            hash_outputs,
            tx.lock_time.to_bytes(4, "little"),
            sig_hash.SINGLE.to_bytes(4, "little"),
        ]
    )


def test_the_hand_built_preimage_is_the_one_bip143_publishes() -> None:
    """The next test's authority, checked against a published number.

    `_bip143_preimage` is what says the rule below is right, so it is
    itself checked here — against BIP143's own preimage for its
    out-of-range example, printed in the BIP beside the sigHash that
    `test_native_p2wsh` already pins.
    """
    tx = Tx.parse(_BIP143_TX)
    script_code = bytes.fromhex(_WITNESS_SCRIPT)
    preimage = _bip143_preimage(tx, 1, script_code, _AMOUNT, b"\x00" * 32)
    assert preimage.hex() == (
        "01000000ef546acf4a020de3898d1b8956176bb507e6211b5ed3619cd08b6ea7e2a09d41"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0815cf020f013ed6cf91d29f4202e8a58726b1ac6c79da47c23d1bee0a6925f800000000"
        "47" + _WITNESS_SCRIPT + "0011102401000000ffffffff"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000003000000"
    )
    assert hash256(preimage).hex() == (
        "82dde6e4f1e94d02c2b7ad03d2115d691f48d064e9d52f58194a6637e4194391"
    )


def test_sighash_single_past_the_last_output() -> None:
    """Verify hashOutputs is zero for every index past the last output.

    BIP143: "if the sighash type is SINGLE and the input index is
    smaller than the number of outputs, hashOutputs is the double
    SHA256 of the output amount with scriptPubKey of the same index as
    the input; Otherwise, hashOutputs is a uint256 of 0x0000......0000".

    *Every* index past it, which is the part no vector states. BIP143's
    own example signs input 1 of a transaction with one output, so it
    pins the case where the index equals the output count and says
    nothing about the ones beyond — and an implementation reading the
    bound as `vin_i != len(tx.vout)` passes every vector there is
    (issue #252). Here a third input carries the same spend two indices
    past the last output.
    """
    tx = Tx.parse(_BIP143_TX)
    script_code = bytes.fromhex(_WITNESS_SCRIPT)

    # the index the BIP publishes, and the two beyond it
    tx.vin.append(TxIn(OutPoint(b"\x11" * 32, 0), b"", 0xFFFFFFFF))
    tx.vin.append(TxIn(OutPoint(b"\x22" * 32, 1), b"", 0xFFFFFFFF))
    assert len(tx.vout) == 1
    for vin_i in (1, 2, 3):
        preimage = _bip143_preimage(tx, vin_i, script_code, _AMOUNT, b"\x00" * 32)
        assert sig_hash.segwit_v0(
            script_code, tx, vin_i, sig_hash.SINGLE, _AMOUNT
        ) == hash256(preimage)

    # and the index that does have an output of its own is the other
    # branch: it commits to that output and to no other
    hash_outputs = hash256(tx.vout[0].serialize())
    preimage = _bip143_preimage(tx, 0, script_code, _AMOUNT, hash_outputs)
    assert sig_hash.segwit_v0(script_code, tx, 0, sig_hash.SINGLE, _AMOUNT) == hash256(
        preimage
    )


def test_the_bip143_amount_is_a_signed_camount() -> None:
    """BIP143's amount is Core's CAmount, so the eight bytes are signed.

    The amount reaches the preimage from a spent output's value, which
    is a signed int64 (issue #388), so the two must agree on which
    integers the field stands for: -1 is what eight `ff` octets mean,
    and writing them is what Core's `ss << amount` does. Asserted as
    the bytes rather than as a number, the preimage being what is
    signed -- and hand-written here, as the file's other preimage is.
    """
    tx = Tx.parse(_BIP143_TX)
    script_code = bytes.fromhex(_WITNESS_SCRIPT)
    hash_outputs = hash256(tx.vout[0].serialize())

    preimage = _bip143_preimage(tx, 0, script_code, _AMOUNT, hash_outputs)
    assert sig_hash.segwit_v0(script_code, tx, 0, sig_hash.SINGLE, _AMOUNT) == hash256(
        preimage
    )

    # the octets a signed and an unsigned reading disagree about: what
    # goes into the preimage is `ffffffffffffffff` either way, so the
    # hash is unchanged and only the integer naming those octets moves
    assert (-1).to_bytes(8, "little", signed=True) == b"\xff" * 8
    negative = _bip143_preimage(tx, 0, script_code, -1, hash_outputs)
    assert b"\xff" * 8 in negative
    assert sig_hash.segwit_v0(script_code, tx, 0, sig_hash.SINGLE, -1) == hash256(
        negative
    )


def test_the_hash_type_is_a_signed_int32() -> None:
    """Core's nHashType is an int32_t, so -1 has a preimage of its own.

    `SignatureHash` takes an `int32_t` and BIP143's preimage ends with the
    four bytes of one, `ffffffff` for -1, where an unsigned reading has no
    such hash type at all and answers with an `OverflowError` from
    underneath the library (issue #405). The bits of that word choose the
    fields as they always do: `-1 & 0x80` is ANYONECANPAY, so hashPrevouts
    and hashSequence are zero, and `-1 & 0x1F` is 31, neither NONE nor
    SINGLE, so hashOutputs commits to every output.

    The field list is written out here, as the file's other preimages are,
    rather than asked of the code under test.
    """
    tx = Tx.parse(_BIP143_TX)
    script_code = bytes.fromhex(_WITNESS_SCRIPT)
    outputs = b"".join(vout.serialize() for vout in tx.vout)
    preimage = b"".join(
        [
            tx.version.to_bytes(4, "little"),
            b"\x00" * 32,  # hashPrevouts, ANYONECANPAY
            b"\x00" * 32,  # hashSequence, ANYONECANPAY
            tx.vin[0].prev_out.serialize(),
            var_bytes.serialize(script_code),
            _AMOUNT.to_bytes(8, "little", signed=True),  # a CAmount
            tx.vin[0].sequence.to_bytes(4, "little"),
            hash256(outputs),
            tx.lock_time.to_bytes(4, "little"),
            b"\xff\xff\xff\xff",
        ]
    )
    assert sig_hash.segwit_v0(script_code, tx, 0, -1, _AMOUNT) == hash256(preimage)

    # the unsigned spelling of the same 32-bit word: the same four octets
    # go on the wire and the same bits choose the fields, so it is the same
    # preimage rather than a second hash type
    assert sig_hash.segwit_v0(script_code, tx, 0, 0xFFFFFFFF, _AMOUNT) == hash256(
        preimage
    )


@pytest.mark.parametrize("hash_type", [-(2**31) - 1, 2**32, 2**64])
def test_hash_type_too_wide_for_its_four_bytes(hash_type: int) -> None:
    """Refuse a hash type the field cannot carry.

    A `BTClibValueError` naming the field, where `int.to_bytes` answers
    with an `OverflowError` from outside the library's exception contract
    (issue #405). The same domain `legacy` has, both preimages writing the
    same `nHashType`.
    """
    tx = Tx.parse(_BIP143_TX)
    script_code = bytes.fromhex(_WITNESS_SCRIPT)
    with pytest.raises(BTClibValueError, match="sig_hash type too wide"):
        sig_hash.segwit_v0(script_code, tx, 0, hash_type, _AMOUNT)
