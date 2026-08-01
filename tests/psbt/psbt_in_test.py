#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.psbt.psbt_in` module."""

from dataclasses import FrozenInstanceError, fields

import pytest

from btclib.psbt import Psbt, PsbtIn
from btclib.psbt.psbt_in import (
    _DROPPED_ONCE_FINALIZED,
    _KEY_DATA_FIELDS,
    _SERIALIZED_FIELDS,
    _WHOLE_VALUE_FIELDS,
)
from tests.conftest import JsonGolden


def test_psbt_out() -> None:
    psbt_in = PsbtIn()
    # the dict round trip and not the bytes one: PsbtIn.serialize returns
    # bytes and PsbtIn.parse takes a decoded key-value map, so the two are
    # not inverses and there is no bytes-to-object parse to call here
    # (issue #181)
    assert psbt_in == PsbtIn.from_dict(psbt_in.to_dict())


def test_compatibility() -> None:
    psbt_in = PsbtIn()
    assert not psbt_in.sig_hash


def test_default_arguments_are_not_shared() -> None:
    # guards against the final_script_witness default being built once,
    # at definition time, and shared by every PsbtIn built without it
    # (issue #139)
    psbt_in = PsbtIn()
    assert psbt_in.final_script_witness is not PsbtIn().final_script_witness

    # a Witness is immutable all the way down, so a shared one could not
    # be corrupted; it is still built per call
    with pytest.raises(FrozenInstanceError):
        psbt_in.final_script_witness.stack = ()  # type: ignore[misc]
    assert not PsbtIn().final_script_witness.stack


def test_key_type_tables_name_every_field() -> None:
    # serialize and parse read the field out of a table by name, so a field
    # renamed on the dataclass and not in the table would serialize as
    # absent -- a psbt quietly missing a signature, and no error anywhere.
    # This is the check that costs, the names being strings
    field_names = {field.name for field in fields(PsbtIn)}

    assert {name for _, name, _ in _SERIALIZED_FIELDS} == field_names
    assert _DROPPED_ONCE_FINALIZED < field_names

    parsed = {name for name, _, _ in _WHOLE_VALUE_FIELDS.values()}
    parsed |= {name for name, _ in _KEY_DATA_FIELDS.values()}
    # unknown is what no key type claims, so it is in neither table
    assert parsed | {"unknown"} == field_names

    # one key type per entry, in both directions
    assert len(_WHOLE_VALUE_FIELDS.keys() & _KEY_DATA_FIELDS.keys()) == 0
    assert (
        len(_SERIALIZED_FIELDS) == len(_WHOLE_VALUE_FIELDS) + len(_KEY_DATA_FIELDS) + 1
    )


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    psbt_str = "cHNidP8BAJoCAAAAAljoeiG1ba8MI76OcHBFbDNvfLqlyHV5JPVFiHuyq911AAAAAAD/////g40EJ9DsZQpoqka7CwmK6kQiwHGyyng1Kgd5WdB86h0BAAAAAP////8CcKrwCAAAAAAWABTYXCtx0AYLCcmIauuBXlCZHdoSTQDh9QUAAAAAFgAUAK6pouXw+HaliN9VRuh0LR2HAI8AAAAAAAEAuwIAAAABqtc5MQGL0l+ErkALaISL4J23BurCrBgpi6vucatlb4sAAAAASEcwRAIgWPb8fGoz4bMVSNSByCbAFb0wE1qtQs1neQ2rZtKtJDsCIEoc7SYExnNbY5PltBaR3XiwDwxZQvufdRhW+qk4FX26Af7///8CgPD6AgAAAAAXqRQPuUY0IWlrgsgzryQceMF9295JNIfQ8gonAQAAABepFCnKdPigj4GZlCgYXJe12FLkBj9hh2UAAAAiAgKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgf0cwRAIgdAGK1BgAl7hzMjwAFXILNoTMgSOJEEjn282bVa1nnJkCIHPTabdA4+tT3O+jOCPIBwUUylWn3ZVE8VfBZ5EyYRGMASICAtq2H/SaFNtqfQKwzR+7ePxLGDErW05U2uTbovv+9TbXSDBFAiEA9hA4swjcHahlo0hSdG8BV3KTQgjG0kRUOTzZm98iF3cCIAVuZ1pnWm0KArhbFOXikHTYolqbV2C+ooFvZhkQoAbqAQEDBAEAAAABBEdSIQKVg785rgpgl0etGZrd1jT6YQhVnWxc05tMIYPxq5bgfyEC2rYf9JoU22p9ArDNH7t4/EsYMStbTlTa5Nui+/71NtdSriIGApWDvzmuCmCXR60Zmt3WNPphCFWdbFzTm0whg/GrluB/ENkMak8AAACAAAAAgAAAAIAiBgLath/0mhTban0CsM0fu3j8SxgxK1tOVNrk26L7/vU21xDZDGpPAAAAgAAAAIABAACAAAEBIADC6wsAAAAAF6kUt/X69A49QKWkWbHbNTXyty+pIeiHIgIDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtxHMEQCIGLrelVhB6fHP0WsSrWh3d9vcHX7EnWWmn84Pv/3hLyyAiAMBdu3Rw2/LwhVfdNWxzJcHtMJE+mWzThAlF2xIijaXwEiAgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8Oc0cwRAIgZfRbpZmLWaJ//hp77QFq8fH5DVSzqo90UKpfVqJRA70CIH9yRwOtHtuWaAsoS1bU/8uI9/t1nqu+CKow8puFE4PSAQEDBAEAAAABBCIAIIwjUxc3Q7WV37Sge3K6jkLjeX2nTof+fZ10l+OyAokDAQVHUiEDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwhAjrdkE89bc9Z3bkGsN7iNSm3/7ntUOXoYVGSaGAiHw5zUq4iBgI63ZBPPW3PWd25BrDe4jUpt/+57VDl6GFRkmhgIh8OcxDZDGpPAAAAgAAAAIADAACAIgYDCJ3BDHrG21T5EymvYXMz2ziM6tDCMfcjN50bmQMLAtwQ2QxqTwAAAIAAAACAAgAAgAAiAgOppMN/WZbTqiXbrGtXCvBlA5RJKUJGCzVHU+2e7KWHcRDZDGpPAAAAgAAAAIAEAACAACICAn9jmXV9Lv9VoTatAsaEsYOLZVbl8bazQoKpS2tQBRCWENkMak8AAACAAAAAgAUAAIAA"
    psbt = Psbt.b64decode(psbt_str)

    # PsbtIn dataclass
    psbt_in = psbt.inputs[0]
    assert isinstance(psbt_in, PsbtIn)

    # PsbtIn dataclass to dict
    psbt_in_dict = psbt_in.to_dict()
    assert isinstance(psbt_in_dict, dict)
    assert psbt_in_dict["redeem_script"]

    # against the json committed beside this module, not written to it
    json_golden("psbt_in.json", psbt_in_dict)

    # PsbtIn dataclass from dict
    psbt_in2 = PsbtIn.from_dict(psbt_in_dict)
    assert isinstance(psbt_in2, PsbtIn)

    assert psbt_in == psbt_in2
