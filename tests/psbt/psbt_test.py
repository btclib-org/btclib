#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.psbt.psbt` module."""

import base64
from io import BytesIO
from typing import Any

import pytest

from btclib.bip32 import BIP32KeyOrigin
from btclib.curves import sec_point
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.psbt import Psbt, combine_psbts, extract_tx, finalize_psbt, join_psbts
from btclib.psbt.psbt import _sort_or_shuffle_together
from btclib.psbt.psbt_utils import PSBT_SEPARATOR
from btclib.script import ScriptPubKey, Witness, serialize, sig_hash
from btclib.script.engine import verify_transaction
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import load, vector_id
from tests.conftest import JsonGolden

# first tests are part of the official BIP174 test vectors


def psbt_vectors(fname: str, kind: str) -> list[Any]:
    """The `kind` cases of a BIP test vector file, named by description.

    The description is the id because a bare "case 7 failed" is not a
    report: as a test id it is there for free, with no print-and-raise
    wrapper around the decode and no interpolation into the message of
    every assert -- and for the cases that pass as well.
    """
    return [
        pytest.param(test_vector, id=vector_id(index, test_vector["description"]))
        for index, test_vector in enumerate(load("psbt", "_data", fname)[kind], 1)
    ]


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "valid psbts")
)
def test_valid_psbt_bip174(test_vector: dict[str, str]) -> None:
    """Test https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki."""
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_bip174(test_vector: dict[str, str]) -> None:
    """Each case must be refused, with the message this file records.

    The message is btclib's, not the BIP's, so the assert is what pins a
    rejection to its reason -- and one of the twenty is pinned to the
    wrong one: the `invalid value data` case answers "Missing inputs"
    because its unsigned tx has none, while btclib's map parser accepts
    the malformed value itself. Lifting the input check of issue 170
    turns this case red, which is where the missing size check gets
    written.
    """
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip174_test_vectors.json", "signer check failures")
)
def test_signer_check_failure_bip174(test_vector: dict[str, str]) -> None:
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    with pytest.raises(BTClibValueError) as excinfo:
        psbt_decoded.assert_signable()
    assert test_vector["error message"] in str(excinfo.value)
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip371_test_vectors.json", "valid psbts")
)
def test_valid_psbt_bip371(test_vector: dict[str, str]) -> None:
    """Test https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki."""
    psbt_decoded = Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["encoded psbt"] == Psbt.b64encode(psbt_decoded)


@pytest.mark.parametrize(
    "test_vector", psbt_vectors("bip371_test_vectors.json", "invalid psbts")
)
def test_invalid_psbt_bip371(test_vector: dict[str, str]) -> None:
    with pytest.raises(BTClibValueError) as excinfo:
        Psbt.b64decode(test_vector["encoded psbt"])
    assert test_vector["error message"] in str(excinfo.value)


def test_taproot_signature_carries_its_sig_hash_type() -> None:
    """A taproot signature is 64 bytes, or 65 with its hash type (issue #122).

    BIP341 appends the sig_hash type when it is not the default one, and
    BIP371 says "64 or 65 bytes" of both PSBT_IN_TAP_KEY_SIG and
    PSBT_IN_TAP_SCRIPT_SIG. Requiring 64 here, while btclib's own script
    engine reads the 65-byte form, would leave a signature Bitcoin Core
    accepts no psbt to travel in.

    The vectors are BIP371's own valid ones, whose signatures are 64
    bytes; what is exercised is the byte appended to them. Their invalid
    counterparts are 63 and 66 bytes, so they stay invalid, and
    test_invalid_psbt_bip371 is what says so.
    """
    valid = load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"]
    psbts = [Psbt.b64decode(test_vector["encoded psbt"]) for test_vector in valid]

    psbt = next(p for p in psbts if p.inputs[0].taproot_key_spend_signature)
    signature = psbt.inputs[0].taproot_key_spend_signature
    assert len(signature) == 64

    # ALL, appended: the 65-byte form
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x01"
    psbt.assert_valid()
    assert Psbt.b64decode(psbt.b64encode()) == psbt

    # 0x00 is what the 64-byte form already means, so appending it is a
    # second spelling of one signature: BIP341 refuses it, and so does
    # the engine's get_hashtype
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x00"
    err_msg = "invalid taproot key path signature: explicit SIGHASH_DEFAULT"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # not one of the seven values SIG_HASH_TYPES holds
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x04"
    err_msg = "invalid taproot key path signature sig_hash type: 0x4"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # and the length that is neither of the two
    psbt.inputs[0].taproot_key_spend_signature = signature + b"\x01\x01"
    err_msg = "invalid taproot key path signature length: 66 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # the script path field is a map, and gets the same treatment
    psbt = next(p for p in psbts if p.inputs[0].taproot_script_spend_signatures)
    signatures = psbt.inputs[0].taproot_script_spend_signatures
    key, signature = next(iter(signatures.items()))
    assert len(signature) == 64

    # ANYONECANPAY | ALL this time
    signatures[key] = signature + b"\x81"
    psbt.assert_valid()
    assert Psbt.b64decode(psbt.b64encode()) == psbt

    signatures[key] = signature + b"\x00"
    err_msg = "invalid taproot script path signature: explicit SIGHASH_DEFAULT"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    # 0x80 is ANYONECANPAY with DEFAULT, which BIP341 does not define
    signatures[key] = signature + b"\x80"
    err_msg = "invalid taproot script path signature sig_hash type: 0x80"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()

    signatures[key] = signature[:63]
    err_msg = "invalid taproot script path signature length: 63 bytes"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()


def test_creation() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    output_1 = TxOut(
        149990000, ScriptPubKey("0014d85c2b71d0060b09c9886aeb815e50991dda124d")
    )
    output_2 = TxOut(
        100000000, ScriptPubKey("001400aea9a2e5f0f876a588df5546e8742d1d87008f")
    )
    input_1 = TxIn(
        OutPoint("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858", 0),
        b"",
        0xFFFFFFFF,
    )
    input_2 = TxIn(
        OutPoint("1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83", 1),
        b"",
        0xFFFFFFFF,
    )
    transaction = Tx(2, 0, [input_1, input_2], [output_1, output_2])
    psbt_from_tx_ = Psbt.from_tx(transaction)
    assert psbt_from_tx_ == psbt


# all the updater stuff are missing


def test_psbt_combination() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="
    psbt2 = Psbt.b64decode(psbt2_str)
    combined_psbt = combine_psbts([psbt1, psbt2])
    assert combined_psbt == psbt

    # get the wrong tx_id
    psbt1.tx.lock_time = psbt1.tx.lock_time ^ 12345678
    err_msg = "mismatched psbt.tx.id: "
    with pytest.raises(BTClibValueError, match=err_msg):
        combine_psbts([psbt1, psbt2])


def test_finalize() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    to_be_finalized_psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    to_be_finalized_psbt = Psbt.b64decode(to_be_finalized_psbt_string)
    finalized_psbt = finalize_psbt(to_be_finalized_psbt)
    assert finalized_psbt == psbt

    to_be_finalized_psbt.inputs[0].partial_sigs = {}
    err_msg = "missing signatures"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(to_be_finalized_psbt)


def test_extract_tx() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    tx = extract_tx(psbt)
    tx_string = "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000"
    tx_bin = tx.serialize(include_witness=True)
    assert tx_bin.hex() == tx_string


def test_lexicographic_ordering() -> None:
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt1_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt2 = Psbt.b64decode(psbt2_str)
    combined_psbt = combine_psbts([psbt1, psbt2])
    assert combined_psbt == psbt
    combined_psbt = combine_psbts([psbt2, psbt1])
    assert combined_psbt == psbt


# not part of the official BIP174 test vector


def test_merge() -> None:
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8K8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwrwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)
    psbt1_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.b64decode(psbt1_str)
    psbt2_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAK8AECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACvABAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAArwAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt2 = Psbt.b64decode(psbt2_str)

    psbt1.inputs[0].sig_hash_type = 1
    psbt.inputs[0].sig_hash_type = 1
    combined_psbt = combine_psbts([psbt2, psbt1])
    assert combined_psbt == psbt


def test_missing_script_pub_key() -> None:
    psbt_str = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8KDwECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCg8BAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwoPAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt = Psbt.b64decode(psbt_str)

    with pytest.raises(BTClibValueError) as excinfo:
        psbt.assert_signable()
    assert str(excinfo.value) == "missing script_pub_key"


def test_psbt() -> None:
    prev_out = OutPoint(
        "9dcfdb5836ecfe146bdaa896605ba21222f83cd014dd47adde14fab2aba7de9b", 1
    )
    script_sig = b""
    sequence = 0xFFFFFFFF
    tx_in = TxIn(prev_out, script_sig, sequence)

    tx_out1 = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    tx_out2 = TxOut(
        6381891, "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
    )
    version = 1
    lock_time = 0
    tx = Tx(version, lock_time, [tx_in], [tx_out1, tx_out2])
    psbt = Psbt.from_tx(tx)
    assert psbt == Psbt.parse(psbt.serialize())
    assert psbt == Psbt.from_dict(psbt.to_dict())


def test_parse_reads_a_stream() -> None:
    """A psbt is one record in a stream, not the whole of a buffer.

    It ends at the separator of its last map, so a parse reading the
    stream can leave what follows to the caller, and can start where the
    caller has got to; a parse slicing bytes can do neither, which is
    what taking BinaryData rather than Octets answers (issue 179).
    """
    tx_in = TxIn(OutPoint(bytes(range(32)), 1), b"", 0xFFFFFFFF)
    tx_out = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    psbt = Psbt.from_tx(Tx(1, 0, [tx_in], [tx_out]))
    psbt_bin = psbt.serialize()

    tail = b"whatever the caller reads next"
    stream = BytesIO(psbt_bin + tail)
    assert Psbt.parse(stream) == psbt
    assert stream.read() == tail

    # and the psbt need not be at the start of the buffer either: what
    # says a map is missing is the position, not the size
    head = b"whatever the caller has already read"
    stream = BytesIO(head + psbt_bin)
    stream.seek(len(head))
    assert Psbt.parse(stream) == psbt

    # BinaryData is a superset of Octets: bytes and hex-string still parse
    assert Psbt.parse(psbt_bin) == psbt
    assert Psbt.parse(psbt_bin.hex()) == psbt


def test_parse_refuses_what_follows_a_psbt_in_octets() -> None:
    """Octets are a psbt whole, and a tail is malleability.

    Accepting one means two buffers deserialize to the same object, and
    that object serializes back to only the shorter of them -- the same
    thing an unchecked read length would buy, which is what #138 was.
    Bitcoin Core refuses it in DecodeRawPSBT, the entry point that takes
    a buffer, and not in the Unserialize that reads a stream.
    """
    tx_in = TxIn(OutPoint(bytes(range(32)), 1), b"", 0xFFFFFFFF)
    tx_out = TxOut(2500000, "a914f987c321394968be164053d352fc49763b2be55c87")
    psbt_bin = Psbt.from_tx(Tx(1, 0, [tx_in], [tx_out])).serialize()

    err_msg = "malformed psbt: 3 bytes after the psbt"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse(psbt_bin + b"abc")
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.parse((psbt_bin + b"abc").hex())
    # base64 is octets too, being decoded to them
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.b64decode(base64.b64encode(psbt_bin + b"abc").decode("ascii"))


def test_explicit_version() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.version = 10
    assert_valid = False
    assert (
        Psbt.b64decode(
            psbt.b64encode(check_validity=assert_valid), check_validity=assert_valid
        )
        == psbt
    )
    with pytest.raises(BTClibValueError, match="invalid non-zero version: "):
        psbt.b64encode(check_validity=True)
    with pytest.raises(BTClibValueError, match="invalid non-zero version: "):
        Psbt.b64decode(psbt.b64encode(check_validity=assert_valid), check_validity=True)


def test_global_unknown() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.unknown[b"unknown key"] = b"unknown value"
    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_output_unknown() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.outputs[0].unknown[b"unknown key"] = b"unknown value"
    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_output_scripts_serialization() -> None:
    input_1 = TxIn(
        OutPoint("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858", 0),
        b"",
        0xFFFFFFFF,
    )
    output_1 = TxOut(
        149990000, bytes.fromhex("a914256b3a9ae8145e5094329537dd4d7a25dbc9452087")
    )
    output_2 = TxOut(
        100000000, bytes.fromhex("001400aea9a2e5f0f876a588df5546e8742d1d87008f")
    )
    tx = Tx(2, 0, [input_1], [output_1, output_2])

    psbt = Psbt.from_tx(tx)

    # p2sh-p2wsh
    psbt.outputs[0].redeem_script = bytes.fromhex(
        "003BD89EE628E6EB745F99DF1E4AEF64A0DAA814850DAA509F30C0F472E0563C7A"
    )
    psbt.outputs[0].witness_script = bytes.fromhex(
        "522103dcea327ff7b2b4449413d9dc24cef0cc9e7864bad9d6291f3f1a04b639422c312103a2c5199b333adfaed4fea7ab65485b9e23a6cb317ddae7e8c1f2bd673414bdd352ae"
    )

    assert Psbt.b64decode(psbt.b64encode()) == psbt


def test_additional_combination() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt_1 = Psbt.b64decode(psbt_str)
    psbt_2 = Psbt.b64decode(psbt_str)

    # split the hd_key_paths dict in half
    hd_key_paths = psbt_1.inputs[1].hd_key_paths
    assert len(hd_key_paths) > 1
    i = len(hd_key_paths) // 2
    half_index = list(hd_key_paths.items())

    # first half
    psbt_1.inputs[1].hd_key_paths = dict(half_index[:i])
    # second half
    psbt_2.inputs[1].hd_key_paths = dict(half_index[i:])

    combined_psbt = combine_psbts([psbt_1, psbt_2])
    assert combined_psbt == psbt


def test_valid_sign() -> None:
    psbt_str = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt.assert_signable()


def test_valid_sign_2() -> None:
    psbt_str = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    transaction_input = TxIn(
        OutPoint("75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858", 0),
        b"",
        0xFFFFFFFF,
    )
    assert psbt.inputs[0].witness_utxo is not None
    # pylance cannot grok the following line, even considering the above line
    transaction = Tx(1, 2, [transaction_input], [psbt.inputs[0].witness_utxo])
    # a new OutPoint, OutPoint being frozen; TxIn.prev_out is still settable
    psbt.tx.vin[0].prev_out = OutPoint(transaction.id, psbt.tx.vin[0].prev_out.vout)
    psbt.inputs[0].non_witness_utxo = transaction
    psbt.assert_signable()


def test_sig_type1() -> None:
    # psbt with a single partial sig and one single input
    psbt_check_str = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgIDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX49IMEUCIQDh6ho/n3kEkusYgQ8OSeZQszl/kfpKOAwGSeMUSUMAngIgLDbfAC4tGyEdoCVrRGsnVB4zDEb9k4a1mhYbSQLoVMsBIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="
    psbt_check = Psbt.b64decode(psbt_check_str)
    assert psbt_check.b64encode() == psbt_check_str

    # template psbt with no sigs and one single input
    psbt_str = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    pk1 = bytes.fromhex(
        "03 572f9af6aebd7a6764264e17abdc4fc80cf359c11f81cbbe4ecf7a2c234a5f8f"
    )
    sig1 = bytes.fromhex(
        "3045022100e1ea1a3f9f790492eb18810f0e49e650b3397f91fa4a380c0649e3144943009e02202c36df002e2d1b211da0256b446b27541e330c46fd9386b59a161b4902e854cb01"
    )
    psbt.inputs[0].partial_sigs[pk1] = sig1
    assert psbt == psbt_check
    assert psbt.inputs[0].partial_sigs[pk1] == sig1


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    # let's sort it
    psbt_str = Psbt.b64decode(psbt_str).b64encode()
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    # Psbt dataclass
    assert isinstance(psbt, Psbt)

    # Psbt dataclass to dict
    psbt_dict = psbt.to_dict()
    assert isinstance(psbt_dict, dict)
    assert psbt_dict["tx"]

    # against the json committed beside this module, not written to it
    json_golden("psbt.json", psbt_dict)

    # Psbt dataclass from dict
    psbt2 = Psbt.from_dict(psbt_dict)
    assert isinstance(psbt2, Psbt)

    assert psbt == psbt2


def test_encode_serialize() -> None:
    # from creator example
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    psbt = Psbt.b64decode(psbt_str)
    assert psbt.b64encode() == psbt_str

    psbt_serialized = bytes.fromhex(
        "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"
    )
    assert psbt == Psbt.parse(psbt_serialized)
    assert psbt_serialized == psbt.serialize()


def test_exceptions() -> None:
    # from creator example
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs[0].redeem_script = "bad script"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs[0].witness_script = "bad script"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs[0].unknown = {"bad key": b""}  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs[0].unknown = {b"deadbeef": "bad value"}  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs[0].sig_hash_type = 101
    with pytest.raises(BTClibValueError, match="invalid sig_hash type: "):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs[0].final_script_sig = "bad script"  # type: ignore[assignment]
    with pytest.raises(TypeError):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    _, Q = dsa.gen_keys()
    pub_key = sec_point.bytes_from_point(Q)
    r = s = int.from_bytes(bytes.fromhex("FF" * 32), byteorder="big", signed=False)
    sig_bytes = dsa.Sig(r, s, check_validity=False).serialize(check_validity=False)
    psbt.inputs[0].partial_sigs = {pub_key: sig_bytes}
    with pytest.raises(BTClibValueError, match="invalid partial signature: "):
        psbt.serialize()

    pub_key = bytes.fromhex("02" + 31 * "00" + "07")
    psbt.inputs[0].partial_sigs = {pub_key: sig_bytes}
    with pytest.raises(BTClibValueError, match="invalid partial signature pub_key: "):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    err_msg = "invalid version: "
    psbt.version = -1
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
    psbt.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
    psbt.version = 1
    with pytest.raises(BTClibValueError, match="invalid non-zero version: "):
        psbt.serialize()

    # the 0xff is the fifth byte of the header, not a field of its own, so
    # losing it is the header being wrong and nothing more specific
    psbt = Psbt.b64decode(psbt_str)
    psbt_bin = psbt.serialize()
    psbt_bin = psbt_bin[:4] + PSBT_SEPARATOR + psbt_bin[5:]
    with pytest.raises(BTClibValueError, match="malformed psbt: missing magic bytes"):
        Psbt.parse(psbt_bin)

    psbt = Psbt.b64decode(psbt_str)
    psbt.inputs.pop()
    err_msg = "mismatched number of psb.tx.vin and psb.inputs: "
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.tx.vin[0].script_witness = Witness([b""])
    err_msg = "non empty script_sig or witness"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()

    psbt = Psbt.b64decode(psbt_str)
    psbt.outputs.pop()
    err_msg = "mismatched number of psb.tx.vout and psbt.outputs: "
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()

    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)
    # swap the two tx_id, each keeping its own vout: new OutPoints, OutPoint
    # being frozen
    prev_out_0, prev_out_1 = psbt.tx.vin[0].prev_out, psbt.tx.vin[1].prev_out
    psbt.tx.vin[0].prev_out = OutPoint(prev_out_1.tx_id, prev_out_0.vout)
    psbt.tx.vin[1].prev_out = OutPoint(prev_out_0.tx_id, prev_out_1.vout)
    err_msg = "mismatched non-witness utxo / outpoint tx_id"
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.assert_valid()


def test_valid_ripemd160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = ripemd160(preimage)
    psbt.inputs[0].ripemd160_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_ripemd160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].ripemd160_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid RIPEMD160 preimage"):
        psbt.assert_valid()


def test_valid_sha256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = sha256(preimage)
    psbt.inputs[0].sha256_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_sha256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].sha256_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid SHA256 preimage"):
        psbt.assert_valid()


def test_valid_hash160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = hash160(preimage)
    psbt.inputs[0].hash160_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_hash160_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].hash160_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid HASH160 preimage"):
        psbt.assert_valid()


def test_valid_hash256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    h = hash256(preimage)
    psbt.inputs[0].hash256_preimages.update({h: preimage})

    psbt.assert_valid()

    assert Psbt.parse(psbt.serialize()) == psbt


def test_invalid_hash256_preimage() -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    preimage = b"\x01"
    psbt.inputs[0].hash256_preimages.update({preimage: preimage})

    with pytest.raises(BTClibValueError, match="invalid HASH256 preimage"):
        psbt.assert_valid()


def test_join_psbts() -> None:
    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt1 = Psbt.b64decode(psbt1_str)

    psbt2_str = "cHNidP8BAIkCAAAAAQKRPRGG7prm5Q6O5UJleyh9L9mmTPInNsVHnHzOS+ouAAAAAAAAAAAAAkBCDwAAAAAAIgAg1CyIdLnm/VxeOpIrt1Cvd2pVfTIgBuhGjqY7NVWGNgNDZAMAAAAAACIAIIUkJZx27tj1ukl5cN1lACHcJpd+XYVHg3XdxlGGJaRGAAAAAAABASslqRIAAAAAACIAIIUkJZx27tj1ukl5cN1lACHcJpd+XYVHg3XdxlGGJaRGIgICAO+hDq7He+h19gglhqAwUuruSCtWpIXFyEkj53crNh1IMEUCIQDiB1FrWN+TYztVhZTo7T7OJzQXTDz5dOhMG9+2ydm8+AIgb6pEEFSXYa9bAOExy4VQ3R3hpbi94l4doBBqLHQIh1ABIgIDxpfu3Y+krSVPw26m5LwhdoYVyRf7xWBL+P5WUbdO2etHMEQCIC/gN9WvBgebfiLJoNGXL6VPtblmo09Yr9bkjmCdMVIfAiBKJu4UTYVPkun4Whq8YKlddlRp95nzzInN4MnPx0N7ZQEBBf2oAVIhAgDvoQ6ux3vodfYIJYagMFLq7kgrVqSFxchJI+d3KzYdIQKtPKqcpvfFHCIaEGlHiX2kBTvZ+sZa8dtXLz6eErPsWyEDxpfu3Y+krSVPw26m5LwhdoYVyRf7xWBL+P5WUbdO2etTrmRSIQJAg8IBrMPT1XzBOuatwoVRObsgDKywIO/hTXX5BLqJ2yECWDeYBx2nVYYUPeICE2IgZ32CtqldcbZWrhmncmX7fxIhAs/eanomSWEuQFlCjry6HTmZcZ03c12wzMe6+jFMZFjYU68CkACyZ1MhA2HwlTuHQ7vQzuBibvN/r36m4MaIP6p1CEypK06o02pyIQNlG153o/5ni/xXlHgDAsD8sjOmvfh8E3s8XoQr8kBj7SEDahsw8dKvYjcoyrLfr+kWiXBRmG8cr0EBhDoslO3JgF0hA34ELbQa8gKi0ju2YUck4PSOLtfJ+QWAREM9Zmn4zAcjIQOnrP8c7MWRPaVi8ew06516BidH/65MoqblLYUp4+3KwSEDw2+64TPFicHXuZ1HYJWxEQ5v6iKmuTdgDvwIndMCfI9WrmgiBgIA76EOrsd76HX2CCWGoDBS6u5IK1akhcXISSPndys2HRj8i5WHKgAAgAAAAIAAAACAAQAAAAEAAAAiBgKtPKqcpvfFHCIaEGlHiX2kBTvZ+sZa8dtXLz6eErPsWxgN8rafKgAAgAAAAIAAAACAAQAAAAEAAAAiBgNh8JU7h0O70M7gYm7zf69+puDGiD+qdQhMqStOqNNqchg/h1X2LAAAgAAAAIAAAACAAQAAAAEAAAAiBgNlG153o/5ni/xXlHgDAsD8sjOmvfh8E3s8XoQr8kBj7RgmqLvwLAAAgAAAAIAAAACAAQAAAAEAAAAiBgNqGzDx0q9iNyjKst+v6RaJcFGYbxyvQQGEOiyU7cmAXRgQqVSnLAAAgAAAAIAAAACAAQAAAAEAAAAiBgN+BC20GvICotI7tmFHJOD0ji7XyfkFgERDPWZp+MwHIxgZXhf6LAAAgAAAAIAAAACAAQAAAAEAAAAiBgOnrP8c7MWRPaVi8ew06516BidH/65MoqblLYUp4+3KwRhm/AUgLAAAgAAAAIAAAACAAQAAAAEAAAAiBgPDb7rhM8WJwde5nUdglbERDm/qIqa5N2AO/Aid0wJ8jxg2/ys6LAAAgAAAAIAAAACAAQAAAAEAAAAiBgPGl+7dj6StJU/DbqbkvCF2hhXJF/vFYEv4/lZRt07Z6xiTeMdTKgAAgAAAAIAAAACAAQAAAAEAAAAAAAA="
    psbt2 = Psbt.b64decode(psbt2_str)
    psbt2.tx.lock_time = psbt1.tx.lock_time
    joint_psbt = join_psbts(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        merge_out=False,
        shuffle_inp=False,
        shuffle_out=False,
    )

    joint_psbt.assert_valid()
    assert all(i in joint_psbt.inputs for i in psbt1.inputs + psbt2.inputs)
    assert all(i in joint_psbt.outputs for i in psbt1.outputs + psbt2.outputs)

    # non-shuffled join is deterministic
    assert join_psbts(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        merge_out=False,
        shuffle_inp=False,
        shuffle_out=False,
    ) == join_psbts(
        [psbt1, psbt2],
        enforce_same_tx_version=True,
        enforce_same_tx_lock_time=True,
        merge_out=False,
        shuffle_inp=False,
        shuffle_out=False,
    )
    # Check that joining with shuffle=True does really shuffle inputs and
    # outputs. 10 attempts should be enough to get at least a shuffled
    # join that is different from the unshuffled one
    assert any(
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=False,
            shuffle_inp=True,
            shuffle_out=True,
        )
        != joint_psbt
        for _ in range(10)
    )

    # failure: different locktimes
    psbt2.tx.lock_time = psbt1.tx.lock_time ^ 12345678
    with pytest.raises(BTClibValueError, match="Lock times are not the same"):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=False,
            shuffle_inp=False,
            shuffle_out=False,
        )

    # failure: common inputs
    psbt2 = Psbt.b64decode(psbt2_str)
    psbt2.inputs.append(psbt2.inputs[0])
    err_msg = "mismatched number of psb.tx.vin and psb.inputs: "
    with pytest.raises(BTClibValueError, match=err_msg):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=False,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    fingerprint = b"beef"
    pub_key = bytes.fromhex(
        "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"
    )
    psbt1.hd_key_paths[pub_key] = BIP32KeyOrigin(fingerprint, "m/42/0/0/1")
    psbt2.hd_key_paths[pub_key] = BIP32KeyOrigin(fingerprint, "m/42/0/0/2")
    with pytest.raises(
        BTClibValueError, match="hd_key_paths: same pub_key, different key_origin"
    ):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=False,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    fingerprint = b"beef"
    pubkey1 = bytes.fromhex(
        "023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73"
    )
    pubkey2 = bytes.fromhex(
        "03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc"
    )
    psbt1.hd_key_paths[pubkey1] = BIP32KeyOrigin(fingerprint, "m/42/0/0/1")
    psbt2.hd_key_paths[pubkey2] = BIP32KeyOrigin(fingerprint, "m/42/0/0/1")
    with pytest.raises(
        BTClibValueError, match="hd_key_paths: same key_origin, different pub_key"
    ):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=False,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    psbt1.unknown[b"foo"] = b"321"
    psbt2.unknown[b"foo"] = b"123"
    with pytest.raises(BTClibValueError, match="unknown: same key, different value"):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=False,
            shuffle_inp=False,
            shuffle_out=False,
        )

    psbt2 = Psbt.b64decode(psbt2_str)
    with pytest.raises(BTClibValueError, match="output merge not implemented yet"):
        join_psbts(
            [psbt1, psbt2],
            enforce_same_tx_version=True,
            enforce_same_tx_lock_time=True,
            merge_out=True,
            shuffle_inp=False,
            shuffle_out=False,
        )


def test_shuffle_sort_inp_out() -> None:
    psbt1_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt1 = Psbt.b64decode(psbt1_str)
    # let's shuffle inputs and outputs
    psbt1.sort_inputs()
    psbt1.sort_outputs()
    psbt1.assert_valid()


def test_shuffle_sort() -> None:
    list_a = [2, 1, 4, 3]
    list_b = ["b", "a", "d", "c"]

    # testing sort
    assert (
        _sort_or_shuffle_together(list_a, list_b, lambda t: t)
        == (
            [1, 2, 3, 4],
            ["a", "b", "c", "d"],
        )
        and list_a == [2, 1, 4, 3]
        and list_b == ["b", "a", "d", "c"]
    )

    # testing shuffle
    # 10 attempts should be enough to reduce to zero the probability
    # of having (all) shuffled ones identical to the original one
    assert any(
        _sort_or_shuffle_together(list_a, list_b) != (list_a, list_b)
        and list_a == [2, 1, 4, 3]
        and list_b == ["b", "a", "d", "c"]
        for _ in range(10)
    )

    list_a.append(list_a[0])
    with pytest.raises(BTClibValueError, match="sequences must have same length"):
        _sort_or_shuffle_together(list_a, list_b)


def test_a_psbt_may_have_no_inputs() -> None:
    """BIP174 lists two such psbts as valid, and btclib must take both.

    A PSBT's global unsigned transaction is incomplete by construction --
    that is the whole point of the format -- so the two rules that make an
    empty vin or vout invalid in a *transaction* do not apply to it,
    anywhere on its path: deserialize_tx on the way in, Psbt.assert_valid,
    and Tx.serialize on the way back out (issue 170).
    """
    # "PSBT with global unsigned tx that has 0 inputs and 0 outputs"
    empty = "cHNidP8BAAoAAAAAAAAAAAAAAA=="
    psbt = Psbt.b64decode(empty)
    assert not psbt.tx.vin
    assert not psbt.tx.vout
    assert not psbt.inputs
    assert not psbt.outputs
    psbt.assert_valid()
    assert psbt.b64encode() == empty
    assert Psbt.from_dict(psbt.to_dict()) == psbt

    # the transaction on its own is still not a valid transaction: the two
    # rules are dropped for the template, not for Tx
    with pytest.raises(BTClibValueError, match="Missing inputs"):
        psbt.tx.assert_valid()

    # valid, and not signable: every check in assert_signable is per input,
    # so without an explicit test an empty vin passes the loop vacuously
    # and a caller signs nothing while being told nothing. The answer
    # belongs here, not in assert_valid, which would refuse a psbt BIP174
    # calls valid
    with pytest.raises(BTClibValueError, match="nothing to sign: no inputs"):
        psbt.assert_signable()


def test_the_global_unsigned_tx_is_mandatory() -> None:
    """A psbt with no PSBT_GLOBAL_UNSIGNED_TX at all is refused (BIP174).

    Distinct from a psbt whose transaction has no inputs, which BIP174
    allows: Psbt.parse tracks whether the key was seen, so the two get
    different answers.
    """
    # "PSBT where inputs and outputs are provided but without an unsigned tx"
    no_tx = (
        "cHNidP8AAQBpAgAAAAGe/8Ee1KsvBiepWx6Kcs97VBcYtNMbrN+iUwLtGyRoNQAAAAAA/////"
        "wJhLQEAAAAAABl2qRQ0Sg9IyhUOwrkDgXZgubaLE6ZwJoisAAAAAAAAAAAJagUpZ2FCcm9tAA"
        "AAAAABABYAFA0lQfhqxdgm7O5vlIhc2yEbGF+wAAA="
    )
    err_msg = "malformed psbt: missing global unsigned tx"
    with pytest.raises(BTClibValueError, match=err_msg):
        Psbt.b64decode(no_tx)


def test_a_value_that_is_not_the_stated_size_says_so() -> None:
    """The size mismatch is what is reported, and the check is reachable.

    deserialize_tx compares the re-serialized transaction against the
    value it came from. Were Tx.parse to validate on the way in, a value
    the parse rejects would never reach the comparison, and this vector
    would be reported as "Missing inputs" -- true of it, and not what is
    wrong with it: 51 bytes whose transaction is 10.
    """
    bad_size = "cHNidP8BADN0Af8HAAEAAAABAP8BAApzMXQo/wAAAAAB/wEDAQAAAQAAAAAAAAAAdgEAAABBAAkAAAAAAA=="
    with pytest.raises(BTClibValueError, match="wrong tx serialization format"):
        Psbt.b64decode(bad_size)


# issue 249: the finalizer against btclib's own script engine

_PRV_KEY = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
_PUB_KEY = bytes.fromhex(
    "02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d"
)


def _p2pkh_script_code(pub_key_hash: bytes) -> bytes:
    return serialize(
        ["OP_DUP", "OP_HASH160", pub_key_hash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )


def _single_key_psbt(kind: str) -> tuple[Psbt, list[TxOut]]:
    """Build a one-input psbt of the given kind, signed and not finalized.

    The Updater's job, done here because btclib has no Signer: the psbt
    carries the utxo, the scripts the input needs, and one partial
    signature filed under the public key that made it.
    """
    p2pk = serialize([_PUB_KEY, "OP_CHECKSIG"])
    witness_script = p2pk if "p2wsh" in kind else b""
    script_pub_key = {
        "p2pkh": ScriptPubKey.p2pkh(_PUB_KEY),
        "p2wpkh": ScriptPubKey.p2wpkh(_PUB_KEY),
        "p2wsh": ScriptPubKey.p2wsh(p2pk),
        "p2sh-p2wpkh": ScriptPubKey.p2sh(ScriptPubKey.p2wpkh(_PUB_KEY).script),
        "p2sh-p2wsh": ScriptPubKey.p2sh(ScriptPubKey.p2wsh(p2pk).script),
    }[kind]
    redeem_script = (
        ScriptPubKey.p2wpkh(_PUB_KEY).script
        if kind == "p2sh-p2wpkh"
        else ScriptPubKey.p2wsh(p2pk).script
        if kind == "p2sh-p2wsh"
        else b""
    )

    prev_out = TxOut(100_000, script_pub_key)
    # the previous transaction, not merely the output it holds: a legacy
    # input is spent against the whole of it, and its id is the outpoint
    prev_tx = Tx(
        2, 0, [TxIn(OutPoint("00" * 31 + "01", 0), b"", 0xFFFFFFFF)], [prev_out]
    )
    tx_in = TxIn(OutPoint(prev_tx.id, 0), b"", 0xFFFFFFFF)
    tx = Tx(2, 0, [tx_in], [TxOut(90_000, ScriptPubKey.p2wpkh(_PUB_KEY))])

    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].redeem_script = redeem_script
    psbt.inputs[0].witness_script = witness_script
    if kind == "p2pkh":
        psbt.inputs[0].non_witness_utxo = prev_tx
        msg_hash = sig_hash.legacy(script_pub_key.script, tx, 0, 1)
    else:
        psbt.inputs[0].witness_utxo = prev_out
        # BIP143's script code: the witness script for p2wsh, the p2pkh
        # script for the same hash160 for p2wpkh
        script_code = witness_script or _p2pkh_script_code(hash160(_PUB_KEY))
        msg_hash = sig_hash.segwit_v0(script_code, tx, 0, 1, prev_out.value)
    sig = dsa.sign_(msg_hash, _PRV_KEY).serialize() + b"\x01"
    psbt.inputs[0].partial_sigs = {_PUB_KEY: sig}
    return psbt, [prev_out]


@pytest.mark.parametrize(
    "kind", ["p2pkh", "p2wpkh", "p2wsh", "p2sh-p2wpkh", "p2sh-p2wsh"]
)
def test_what_the_finalizer_builds_the_engine_accepts(kind: str) -> None:
    """Finalize each single-key shape and run the result (issue #249).

    The five kinds a wallet actually holds, and the assertion is the
    script engine's rather than a string comparison: what the Finalizer
    writes is what a node executes, so the engine is the authority on
    whether it is right.

    Only the two multisig shapes reach here through BIP174's own
    vectors, which is why the single-key ones were broken -- the
    signature went into the script_sig of an input BIP141 requires an
    empty one of, and the public key a p2pkh or p2wpkh script hashes
    reached no stack at all.
    """
    psbt, prevouts = _single_key_psbt(kind)
    finalized = finalize_psbt(psbt)
    verify_transaction(prevouts, extract_tx(finalized, check_validity=False))


@pytest.mark.parametrize("kind", ["p2pkh", "p2wpkh", "p2sh-p2wpkh"])
def test_a_single_key_input_is_spent_with_its_public_key(kind: str) -> None:
    """The key beside the signature, and the empty script_sig (issue #249).

    Where each of the two goes is the whole of the difference between
    the three kinds: a native segwit input is spent with an empty
    script_sig and a witness, a wrapped one pushes its redeem script and
    nothing else, and a legacy p2pkh carries both stack items in the
    script_sig.
    """
    psbt, _ = _single_key_psbt(kind)
    sig = psbt.inputs[0].partial_sigs[_PUB_KEY]
    redeem_script = psbt.inputs[0].redeem_script
    psbt_in = finalize_psbt(psbt).inputs[0]

    if kind == "p2pkh":
        assert psbt_in.final_script_sig == serialize([sig, _PUB_KEY])
        assert not psbt_in.final_script_witness
    else:
        assert psbt_in.final_script_sig == serialize(
            [redeem_script] if redeem_script else []
        )
        assert psbt_in.final_script_witness.stack == (sig, _PUB_KEY)


def test_a_native_p2wsh_input_gets_no_script_sig() -> None:
    """No redeem script is no push, not a push of nothing (issue #249).

    serialize([b""]) is the one byte OP_0, which is a non-empty
    script_sig -- the very thing BIP141 forbids a native segwit input,
    and which the engine names.
    """
    psbt, _ = _single_key_psbt("p2wsh")
    assert finalize_psbt(psbt).inputs[0].final_script_sig == b""


def test_a_single_key_input_takes_one_signature() -> None:
    """A second signature is not a second half (issue #249).

    A p2wpkh output commits to one public key, so two partial signatures
    are two claims about which key that is; picking one is a guess, and
    the wrong guess builds a witness that will not run.
    """
    psbt, _ = _single_key_psbt("p2wpkh")
    other_key = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    psbt.inputs[0].partial_sigs[other_key] = psbt.inputs[0].partial_sigs[_PUB_KEY]
    err_msg = "2 signatures for a single-key input"
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(psbt)


def test_an_input_that_does_not_say_what_it_spends() -> None:
    """No utxo is no dispatch, and the finalizer builds what it always did.

    A missing utxo is a psbt an Updater has not finished, not evidence
    about the spend, so it is not refused here: the signatures go into
    the script_sig with the redeem script after them, which is the
    answer for every kind the psbt has not identified. The same holds
    one level down, for a p2sh input carrying no redeem script
    (issue #249).
    """
    psbt, _ = _single_key_psbt("p2wpkh")
    sig = psbt.inputs[0].partial_sigs[_PUB_KEY]
    psbt.inputs[0].witness_utxo = None

    psbt_in = finalize_psbt(psbt).inputs[0]
    assert psbt_in.final_script_sig == serialize([sig])
    assert not psbt_in.final_script_witness
