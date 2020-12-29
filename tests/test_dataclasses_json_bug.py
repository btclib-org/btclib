#!/usr/bin/env python3

# Copyright (C) 2020-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Test dataclasses_json bug."

from dataclasses import dataclass, field

import pytest
from dataclasses_json import DataClassJsonMixin


def test_dataclasses_json_bug() -> None:
    @dataclass
    class Person(DataClassJsonMixin):
        name: str
        nick_name: str = field(default="", init=False, repr=True, compare=True)

    jack = Person(name="Jack")  # Person(name='Jack', nick_name='')
    jack.nick_name = "the Ripper"  # Person(name='Jack', nick_name='the Ripper')

    jack_dict = jack.to_dict()  # {'name': 'Jack', 'nick_name': 'the Ripper'}
    assert jack.nick_name == jack_dict["nick_name"], "nick_name is retained"

    jack_from_dict = Person.from_dict(jack_dict)  # Person(name='Jack', nick_name='')
    with pytest.raises(AssertionError):
        assert jack == jack_from_dict
    # if the test faild, the bug has been fixed
    # TxIn.witness can have init=False
