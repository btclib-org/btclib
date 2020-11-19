#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for `btclib.psbt` module"

import json
from os import path

import pytest

from btclib import der, dsa, secpoint
from btclib.exceptions import BTClibValueError
from btclib.psbt import (
    PSBT_DELIMITER,
    PSBT_SEPARATOR,
    Psbt,
    combine_psbts,
    extract_tx,
    finalize_psbt,
    psbt_from_tx,
)
from btclib.psbt_in import PsbtIn
from btclib.psbt_out import PsbtOut
from btclib.tx import Tx
from btclib.tx_in import OutPoint, TxIn
from btclib.tx_out import TxOut

# first tests are part of the official BIP174 test vectors


def test_vectors_bip174() -> None:
    "Test https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki"

    data_folder = path.join(path.dirname(__file__), "test_data")
    filename = path.join(data_folder, "bip174_test_vectors.json")
    with open(filename, "r") as file_:
        # json.dump(test_vectors, f, indent=4)
        test_vectors = json.load(file_)

    for i, test_vector in enumerate(test_vectors["invalid psbts"]):
        with pytest.raises(BTClibValueError) as excinfo:
            Psbt.decode(test_vector["encoded psbt"])
        assert test_vector["error message"] in str(
            excinfo.value
        ), f"invalid case {i+1}: {test_vector['description']}\n{excinfo.value}"

    for i, test_vector in enumerate(test_vectors["valid psbts"]):
        try:
            psbt_decoded = Psbt.decode(test_vector["encoded psbt"])
        except Exception as e:  # pragma: no cover # pylint: disable=broad-except
            print(f"valid case {i+1}: {test_vector['description']}")  # pragma: no cover
            raise e  # pragma: no cover
        assert test_vector["encoded psbt"] == Psbt.encode(psbt_decoded)

    for i, test_vector in enumerate(test_vectors["signer check failures"]):
        psbt_decoded = Psbt.decode(test_vector["encoded psbt"])
        with pytest.raises(BTClibValueError) as excinfo:
            psbt_decoded.assert_signable()
        assert test_vector["error message"] in str(
            excinfo.value
        ), f"signer check failure {i+1}: {test_vector['description']}\n{excinfo.value}"
        assert test_vector["encoded psbt"] == Psbt.encode(psbt_decoded)


def test_creation() -> None:
    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    assert Psbt.decode(psbt_string).encode() == psbt_string

    output_1 = TxOut(
        149990000, bytes.fromhex("0014d85c2b71d0060b09c9886aeb815e50991dda124d")
    )
    output_2 = TxOut(
        100000000, bytes.fromhex("001400aea9a2e5f0f876a588df5546e8742d1d87008f")
    )
    input_1 = TxIn(
        OutPoint(
            bytes.fromhex(
                "75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858"
            ),
            0,
        ),
        b"",
        0xFFFFFFFF,
        [],
    )
    input_2 = TxIn(
        OutPoint(
            bytes.fromhex(
                "1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83"
            ),
            1,
        ),
        b"",
        0xFFFFFFFF,
        [],
    )
    transaction = Tx(2, 0, [input_1, input_2], [output_1, output_2])
    psbt = psbt_from_tx(transaction)
    assert psbt.encode() == psbt_string


# all the updater stuff are missing


def test_psbt_combination() -> None:
    combined_psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    assert Psbt.decode(combined_psbt_string).encode() == combined_psbt_string

    psbt1 = Psbt.decode(
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEBAwQBAAAAAQQiACCMI1MXN0O1ld+0oHtyuo5C43l9p06H/n2ddJfjsgKJAwEFR1IhAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcIQI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc1KuIgYCOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnMQ2QxqTwAAAIAAAACAAwAAgCIGAwidwQx6xttU+RMpr2FzM9s4jOrQwjH3IzedG5kDCwLcENkMak8AAACAAAAAgAIAAIAAIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    )
    psbt2 = Psbt.decode(
        "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU210gwRQIhAPYQOLMI3B2oZaNIUnRvAVdyk0IIxtJEVDk82ZvfIhd3AiAFbmdaZ1ptCgK4WxTl4pB02KJam1dgvqKBb2YZEKAG6gEBAwQBAAAAAQRHUiEClYO/Oa4KYJdHrRma3dY0+mEIVZ1sXNObTCGD8auW4H8hAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXUq4iBgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfxDZDGpPAAAAgAAAAIAAAACAIgYC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtcQ2QxqTwAAAIAAAACAAQAAgAABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohyICAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zRzBEAiBl9FulmYtZon/+GnvtAWrx8fkNVLOqj3RQql9WolEDvQIgf3JHA60e25ZoCyhLVtT/y4j3+3Weq74IqjDym4UTg9IBAQMEAQAAAAEEIgAgjCNTFzdDtZXftKB7crqOQuN5fadOh/59nXSX47ICiQMBBUdSIQMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3CECOt2QTz1tz1nduQaw3uI1Kbf/ue1Q5ehhUZJoYCIfDnNSriIGAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zENkMak8AAACAAAAAgAMAAIAiBgMIncEMesbbVPkTKa9hczPbOIzq0MIx9yM3nRuZAwsC3BDZDGpPAAAAgAAAAIACAACAACICA6mkw39ZltOqJdusa1cK8GUDlEkpQkYLNUdT7Z7spYdxENkMak8AAACAAAAAgAQAAIAAIgICf2OZdX0u/1WhNq0CxoSxg4tlVuXxtrNCgqlLa1AFEJYQ2QxqTwAAAIAAAACABQAAgAA="
    )
    combined_psbt = combine_psbts([psbt1, psbt2])
    assert combined_psbt.encode() == combined_psbt_string

    # get the wrong txid
    psbt1.tx.locktime = psbt1.tx.locktime ^ 12345678
    err_msg = "mismatched psbt.tx.txid: "
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match=err_msg):
        combine_psbts([psbt1, psbt2])


def test_finalize() -> None:
    finalized_psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    assert Psbt.decode(finalized_psbt_string).encode() == finalized_psbt_string

    to_be_finalized_psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    to_be_finalized_psbt = Psbt.decode(to_be_finalized_psbt_string)
    finalized_psbt = finalize_psbt(to_be_finalized_psbt)
    assert finalized_psbt.encode() == finalized_psbt_string

    to_be_finalized_psbt.inputs[0].partial_signatures = {}
    err_msg = "missing signatures"
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match=err_msg):
        finalize_psbt(to_be_finalized_psbt)


def test_extraction() -> None:

    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.decode(psbt_string)
    assert psbt.encode() == psbt_string
    tx = extract_tx(psbt)

    tx_string = "0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000"

    assert tx.serialize().hex() == tx_string


def test_lexicographic_ordering() -> None:
    combined_psbt_string = "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8KDwECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PCg8BAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwoPAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    psbt1 = Psbt.decode(
        "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA="
    )
    psbt2 = Psbt.decode(
        "cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcIEA8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCBAPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgQDwECAwQFBgcICQoLDA0ODwA="
    )
    combined_psbt = combine_psbts([psbt1, psbt2])
    assert combined_psbt.encode() == combined_psbt_string
    assert combined_psbt == Psbt.decode(combined_psbt_string)


# not part of the official BIP174 test vector


def test_psbt_serialization() -> None:
    # this is a finalized Psbt
    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAABB9oARzBEAiB0AYrUGACXuHMyPAAVcgs2hMyBI4kQSOfbzZtVrWecmQIgc9Npt0Dj61Pc76M4I8gHBRTKVafdlUTxV8FnkTJhEYwBSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAUdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSrgABASAAwusLAAAAABepFLf1+vQOPUClpFmx2zU18rcvqSHohwEHIyIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQjaBABHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwFHMEQCIGX0W6WZi1mif/4ae+0BavHx+Q1Us6qPdFCqX1aiUQO9AiB/ckcDrR7blmgLKEtW1P/LiPf7dZ6rvgiqMPKbhROD0gFHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4AIgIDqaTDf1mW06ol26xrVwrwZQOUSSlCRgs1R1Ptnuylh3EQ2QxqTwAAAIAAAACABAAAgAAiAgJ/Y5l1fS7/VaE2rQLGhLGDi2VW5fG2s0KCqUtrUAUQlhDZDGpPAAAAgAAAAIAFAACAAA=="
    psbt = Psbt.decode(psbt_string)
    assert psbt.encode() == psbt_string


def test_explicit_version() -> None:
    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.decode(psbt_string)
    psbt.version = 10
    assert_valid = False
    assert Psbt.decode(psbt.encode(assert_valid), assert_valid) == psbt
    with pytest.raises(BTClibValueError):
        psbt.encode()
    with pytest.raises(BTClibValueError):
        Psbt.decode(psbt.encode(assert_valid))


def test_global_unknown() -> None:
    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.decode(psbt_string)
    psbt.unknown[b"unknown key"] = b"unknown value"
    assert Psbt.decode(psbt.encode()) == psbt


def test_output_unknown() -> None:
    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.decode(psbt_string)
    psbt.outputs[0].unknown[b"unknown key"] = b"unknown value"
    assert Psbt.decode(psbt.encode()) == psbt


def test_output_scripts_serialization() -> None:
    input_1 = TxIn(
        OutPoint(
            bytes.fromhex(
                "75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858"
            ),
            0,
        ),
        b"",
        0xFFFFFFFF,
        [],
    )
    output_1 = TxOut(
        149990000, bytes.fromhex("a914256b3a9ae8145e5094329537dd4d7a25dbc9452087")
    )
    output_2 = TxOut(
        100000000, bytes.fromhex("001400aea9a2e5f0f876a588df5546e8742d1d87008f")
    )
    transaction = Tx(2, 0, [input_1], [output_1, output_2])

    psbt = psbt_from_tx(transaction)

    # p2sh-p2wsh
    psbt.outputs[0].redeem_script = bytes.fromhex(
        "003BD89EE628E6EB745F99DF1E4AEF64A0DAA814850DAA509F30C0F472E0563C7A"
    )
    psbt.outputs[0].witness_script = bytes.fromhex(
        "522103dcea327ff7b2b4449413d9dc24cef0cc9e7864bad9d6291f3f1a04b639422c312103a2c5199b333adfaed4fea7ab65485b9e23a6cb317ddae7e8c1f2bd673414bdd352ae"
    )

    assert Psbt.decode(psbt.encode()) == psbt


def test_additional_combination() -> None:
    psbt_string = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"

    psbt_1 = Psbt.decode(psbt_string)
    psbt_2 = Psbt.decode(psbt_string)

    # split the bip32_derivs dict in half
    d = psbt_1.inputs[1].bip32_derivs
    assert len(d) > 1
    i = len(d) // 2
    ll = list(d.items())

    # first half
    psbt_1.inputs[1].bip32_derivs = dict(ll[:i])
    # second half
    psbt_2.inputs[1].bip32_derivs = dict(ll[i:])

    psbt = combine_psbts([psbt_1, psbt_2])
    assert psbt.encode() == psbt_string


def test_valid_sign() -> None:
    psbt_string = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.decode(psbt_string)
    psbt.assert_signable()


def test_valid_sign_2() -> None:
    psbt_string = "cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA="
    psbt = Psbt.decode(psbt_string)
    transaction_input = TxIn(
        prevout=OutPoint(
            bytes.fromhex(
                "75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858"
            ),
            0,
        ),
        scriptSig=b"",
        sequence=0xFFFFFFFF,
        txinwitness=[],
    )
    assert psbt.inputs[0].witness_utxo is not None
    transaction = Tx(0, 2, vin=[transaction_input], vout=[psbt.inputs[0].witness_utxo])
    psbt.tx.vin[0].prevout.txid = transaction.txid
    psbt.inputs[0].non_witness_utxo = transaction
    psbt.assert_signable()


def test_sig_type1() -> None:
    # psbt with a sigle partial sig and one single input
    psbt_check_string = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgIDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX49IMEUCIQDh6ho/n3kEkusYgQ8OSeZQszl/kfpKOAwGSeMUSUMAngIgLDbfAC4tGyEdoCVrRGsnVB4zDEb9k4a1mhYbSQLoVMsBIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="
    # template psbt with no sigs and one single input
    psbt_template = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="

    psbt = Psbt.decode(psbt_template)
    pk1 = bytes.fromhex(
        "03 572f9af6aebd7a6764264e17abdc4fc80cf359c11f81cbbe4ecf7a2c234a5f8f"
    )
    sig1 = bytes.fromhex(
        "3045022100e1ea1a3f9f790492eb18810f0e49e650b3397f91fa4a380c0649e3144943009e02202c36df002e2d1b211da0256b446b27541e330c46fd9386b59a161b4902e854cb01"
    )

    psbt.inputs[0].partial_signatures[pk1] = sig1
    assert psbt.encode() == psbt_check_string
    assert psbt.inputs[0].partial_signatures[pk1] == sig1


# TODO: add test case with non_witness_utxo and witness_utxo


def test_dataclasses_json_dict() -> None:
    psbt_encoded = "cHNidP8BAIkCAAAAARnxViCzMlE50R7BLfUK9Em7JRSithDHx6/HqzxOPb/lAAAAAAD9////AiChBwAAAAAAIgAg6OYWyJlTxF3xOZM+ZJnQYcC6um0klfv3rZqVkbDWaKVBiAMAAAAAACIAIFXAXQ7M7bSsf6IR0Zt+mWvjNRtOX1dbUyA7QN7x3rJVAAAAAAABASuFKwsAAAAAACIAIGxMhA6S1FFxsrccUutx1Wu6+ijbCMDqwETnode6/M9vIgIDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX49IMEUCIQDh6ho/n3kEkusYgQ8OSeZQszl/kfpKOAwGSeMUSUMAngIgLDbfAC4tGyEdoCVrRGsnVB4zDEb9k4a1mhYbSQLoVMsBIgYCOOOQQx1Uydk9h38Rd98Gj/dMemSmLtsUC3tlt004+5QUpFwW+ywAAIAAAACAAAAAAAAAAAAiBgJ6RK62ZrlAXMGL4dJOG61AdvTYSrSYvJu7XE37wIolbBQ+kOBlLAAAgAAAAIAAAAAAAAAAACIGAyoYpiApIUlH9R9l71y9PdAJBGyxofwpoeoZGTcP8OkCFLd96kwsAACAAAAAgAAAAAAAAAAAIgYDVy+a9q69emdkJk4Xq9xPyAzzWcEfgcu+Ts96LCNKX48UOIHNZywAAIAAAACAAAAAAAAAAAAiBgP8xVUHZvsvdflS4U8rKZT1vopnW1W8RSXAqOTGeY3RFxRS5uGZLAAAgAAAAIAAAAAAAAAAAAAAAA=="
    psbt_encoded = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"

    # dataclass
    psbt_data = Psbt.decode(psbt_encoded)
    assert isinstance(psbt_data, Psbt)

    psbt_out_data = psbt_data.outputs[0]
    assert isinstance(psbt_out_data, PsbtOut)

    psbt_in_data = psbt_data.inputs[0]
    assert isinstance(psbt_in_data, PsbtIn)

    datadir = path.join(path.dirname(__file__), "generated_files")

    # PsbtOut to dict and file
    psbt_out_dict = psbt_out_data.to_dict()
    assert isinstance(psbt_out_dict, dict)
    filename = path.join(datadir, "psbt_out.json")
    with open(filename, "w") as file_:
        json.dump(psbt_out_dict, file_, indent=4)

    # PsbtOut from dict and file
    assert psbt_out_data == PsbtOut.from_dict(psbt_out_dict)
    with open(filename, "r") as file_:
        psbt_out_dict2 = json.load(file_)
    assert isinstance(psbt_out_dict2, dict)
    assert psbt_out_dict == psbt_out_dict2

    # PsbtIn to dict and file
    psbt_in_dict = psbt_in_data.to_dict()
    assert isinstance(psbt_in_dict, dict)
    filename = path.join(datadir, "psbt_in.json")
    with open(filename, "w") as file_:
        json.dump(psbt_in_dict, file_, indent=4)

    # PsbtIn from dict and file
    assert psbt_in_data == PsbtIn.from_dict(psbt_in_dict)
    with open(filename, "r") as file_:
        psbt_in_dict2 = json.load(file_)
    assert isinstance(psbt_in_dict2, dict)
    assert psbt_in_dict == psbt_in_dict2

    # Psbt to dict and file
    psbt_dict = psbt_data.to_dict()
    assert isinstance(psbt_dict, dict)
    filename = path.join(datadir, "psbt.json")
    with open(filename, "w") as file_:
        json.dump(psbt_dict, file_, indent=4)

    # Psbt from dict and file
    assert psbt_data == Psbt.from_dict(psbt_dict)
    with open(filename, "r") as file_:
        psbt_dict2 = json.load(file_)
    assert isinstance(psbt_dict2, dict)
    assert psbt_dict == psbt_dict2

    # PsbtOut to str
    psbt_out_json_str = psbt_out_data.to_json()
    assert isinstance(psbt_out_json_str, str)
    assert psbt_out_data == PsbtOut.from_json(psbt_out_json_str)

    # PsbtIn to str
    psbt_in_json_str = psbt_in_data.to_json()
    assert isinstance(psbt_in_json_str, str)
    assert psbt_in_data == PsbtIn.from_json(psbt_in_json_str)

    # Psbt to str
    psbt_json_str = psbt_data.to_json()
    assert isinstance(psbt_json_str, str)
    assert psbt_data == Psbt.from_json(psbt_json_str)


def test_final_script_witness() -> None:

    datadir = path.join(path.dirname(__file__), "test_data")
    filename = path.join(datadir, "psbt_final_script_witness.json")
    with open(filename, "r") as file_:
        psbt_dict2 = json.load(file_)
    assert isinstance(psbt_dict2, dict)
    Psbt.from_dict(psbt_dict2)


def test_serialize() -> None:
    # from creator example
    psbt_encoded = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="
    psbt_serialized = bytes.fromhex(
        "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000"
    )
    psbt = Psbt.decode(psbt_encoded)
    assert psbt == Psbt.deserialize(psbt_serialized)
    assert psbt_serialized == psbt.serialize()
    assert psbt_encoded == psbt.encode()


def test_exceptions() -> None:
    # from creator example
    psbt_encoded = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAAAAAA="

    psbt = Psbt.decode(psbt_encoded)
    psbt.outputs[0].redeem_script = "bad script"  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid redeem script"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.inputs[0].witness_script = "bad script"  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid witness script"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.outputs[0].unknown = {"bad key": b""}  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid key in unknown"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.outputs[0].unknown = {b"deadbeef": "bad value"}  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid value in unknown"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.inputs[0].sighash = 101
    with pytest.raises(BTClibValueError, match="invalid sighash: "):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.inputs[0].final_script_sig = "bad script"  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid final script_sig"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.inputs[0].final_script_witness = "bad script"  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid final script witness"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.inputs[0].final_script_witness = [b"", ""]  # type: ignore
    with pytest.raises(BTClibValueError, match="invalid final script witness"):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    _, Q = dsa.gen_keys()
    pubkey = secpoint.bytes_from_point(Q)
    r = s = int.from_bytes(bytes.fromhex("FF" * 32), "big")
    sig_bytes = der._serialize_scalar(r)
    sig_bytes += der._serialize_scalar(s)
    sig_bytes = b"\x30" + len(sig_bytes).to_bytes(1, byteorder="big") + sig_bytes
    psbt.inputs[0].partial_signatures = {pubkey: sig_bytes}
    with pytest.raises(BTClibValueError, match="invalid partial signature: "):
        psbt.serialize()

    pubkey = bytes.fromhex("02" + 31 * "00" + "07")
    psbt.inputs[0].partial_signatures = {pubkey: sig_bytes}
    with pytest.raises(BTClibValueError, match="invalid partial signature pubkey: "):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    err_msg = "invalid version: "
    psbt.version = -1
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
    psbt.version = 0xFFFFFFFF + 1
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
    psbt.version = 1
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match="invalid non-zero version: "):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt_bin = psbt.serialize()
    psbt_bin = psbt_bin.replace(PSBT_SEPARATOR, PSBT_DELIMITER)
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match="malformed psbt: missing separator"):
        Psbt.deserialize(psbt_bin)

    psbt = Psbt.decode(psbt_encoded)
    psbt.inputs.pop()
    err_msg = "mismatched number of tx.vin and psbt_in"
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.tx.vin[0].txinwitness = [b""]
    err_msg = "non empty txinwitness"
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()

    psbt = Psbt.decode(psbt_encoded)
    psbt.outputs.pop()
    err_msg = "mismatched number of tx.vout and psbt_out"
    # TODO: add to test vectors
    with pytest.raises(BTClibValueError, match=err_msg):
        psbt.serialize()
