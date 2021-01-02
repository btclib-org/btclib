#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.psbt_out` module"

import json
from os import path
from typing import Dict

from btclib.alias import Octets
from btclib.psbt.psbt import Psbt
from btclib.psbt.psbt_out import (
    PsbtOut,
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    encode_dict_bytes_bytes,
    serialize_dict_bytes_bytes,
)


def test_unknown() -> None:
    # the json representation
    encoded_data: Dict[Octets, Octets] = {
        "baad": "deadbeef",
        "abadbabe": "cafebabe",
    }
    data: Dict[bytes, bytes] = decode_dict_bytes_bytes(encoded_data)
    assert_valid_unknown(data)
    assert encoded_data == encode_dict_bytes_bytes(data)

    _ = serialize_dict_bytes_bytes(b"", data)
    # TODO: check deserialization


def test_psbt_out() -> None:
    psbt_out = PsbtOut()
    # FIXME
    # assert psbt_out == PsbtOut.parse(psbt_out.serialize())
    assert psbt_out == PsbtOut.from_dict(psbt_out.to_dict())


def test_dataclasses_json_dict() -> None:

    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    # PsbtOut dataclass
    psbt_out = psbt.outputs[0]
    assert isinstance(psbt_out, PsbtOut)

    # PsbtOut dataclass to dict
    psbt_out_dict = psbt_out.to_dict()
    assert isinstance(psbt_out_dict, dict)
    assert psbt_out_dict["redeem_script"] == ""
    assert psbt_out_dict["witness_script"] == ""
    assert psbt_out_dict["bip32_derivs"]
    assert psbt_out_dict["unknown"] == {}

    # PsbtOut dataclass dict to file
    datadir = path.join(path.dirname(__file__), "_generated_files")
    filename = path.join(datadir, "psbt_out.json")
    with open(filename, "w") as file_:
        json.dump(psbt_out_dict, file_, indent=4)

    # PsbtOut dataclass dict from file
    with open(filename, "r") as file_:
        psbt_out_dict2 = json.load(file_)
    assert isinstance(psbt_out_dict2, dict)
    assert psbt_out_dict2["redeem_script"] == ""
    assert psbt_out_dict2["witness_script"] == ""
    assert psbt_out_dict2["bip32_derivs"]
    assert psbt_out_dict2["unknown"] == {}

    assert psbt_out_dict == psbt_out_dict2

    # PsbtOut dataclass from dict
    psbt_out2 = PsbtOut.from_dict(psbt_out_dict)
    assert isinstance(psbt_out2, PsbtOut)

    assert psbt_out == psbt_out2
