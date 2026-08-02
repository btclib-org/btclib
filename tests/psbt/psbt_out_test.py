#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.psbt.psbt_out` module."""

from __future__ import annotations

from io import BytesIO

from btclib.alias import Octets
from btclib.psbt import (
    Psbt,
    PsbtOut,
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    deserialize_map,
    encode_dict_bytes_bytes,
    serialize_dict_bytes_bytes,
)
from btclib.psbt.psbt_utils import PSBT_SEPARATOR
from tests.conftest import JsonGolden


def test_unknown() -> None:
    # the json representation
    encoded_data: dict[Octets, Octets] = {
        "baad": "deadbeef",
        "abadbabe": "cafebabe",
    }
    data = decode_dict_bytes_bytes(encoded_data)
    assert_valid_unknown(data)
    assert encoded_data == encode_dict_bytes_bytes(data)

    # the serialize read back, so that the two are a round trip rather
    # than a call whose result is dropped. The separator is appended
    # because serialize_dict_bytes_bytes writes the records of a map and
    # not the byte that ends it: an unknown is one field of a map among
    # others, so the terminator belongs to whichever of PsbtIn, PsbtOut or
    # Psbt.serialize is assembling the whole of that map
    serialized = serialize_dict_bytes_bytes(b"", data)
    assert deserialize_map(serialized + PSBT_SEPARATOR) == data


def test_psbt_out() -> None:
    psbt_out = PsbtOut()
    # an output carries its own terminator, as an input does: see
    # tests/psbt/psbt_in_test.py for why the two maps are read that way
    assert psbt_out.serialize() == PSBT_SEPARATOR
    assert psbt_out == PsbtOut.parse(psbt_out.serialize())
    assert psbt_out == PsbtOut.from_dict(psbt_out.to_dict())


def test_parse_reads_one_output_from_the_stream() -> None:
    psbt_out = PsbtOut(redeem_script=b"\x51")
    stream = BytesIO(psbt_out.serialize() + PsbtOut().serialize() + b"nothing else")
    assert PsbtOut.parse(stream) == psbt_out
    assert PsbtOut.parse(stream) == PsbtOut()
    assert stream.read() == b"nothing else"


def test_a_leaf_that_cannot_execute_is_storable() -> None:
    """A tap_tree leaf is bytes, and a PSBT is not a validity oracle.

    The tree used to be validated by parsing every leaf, so a leaf
    carrying a push over 520 bytes or one running past the end made the
    whole PsbtOut invalid. Neither is a fact about what can be *stored*:
    Core's PSBT does not look at a leaf script either, and issue #123 is
    where refusing bytes for what an interpreter would say about them was
    settled. What cannot execute is unspendable, and a signer wanting to
    know says so by running it.
    """
    truncated = bytes.fromhex("4c05aabb")  # a push of five bytes, two given
    oversized = bytes.fromhex("4d0902") + b"\x00" * 521  # 521 bytes pushed
    for leaf in (truncated, oversized):
        psbt_out = PsbtOut(taproot_tree=[(0, 192, leaf)])
        assert psbt_out == PsbtOut.from_dict(psbt_out.to_dict())


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
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

    # against the json committed beside this module, not written to it
    json_golden("psbt_out.json", psbt_out_dict)

    # PsbtOut dataclass from dict
    psbt_out2 = PsbtOut.from_dict(psbt_out_dict)
    assert isinstance(psbt_out2, PsbtOut)

    assert psbt_out == psbt_out2
