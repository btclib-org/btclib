#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.script.taproot` module."

import json
from os import path

import pytest

from btclib import b32
from btclib.ecc.curve import mult
from btclib.exceptions import BTClibValueError
from btclib.script.script import serialize
from btclib.script.script_pub_key import is_p2tr, type_and_payload
from btclib.script.taproot import (
    check_output_pubkey,
    input_script_sig,
    output_prvkey,
    output_pubkey,
)
from btclib.script.witness import Witness
from btclib.tx.tx_out import TxOut


def test_valid_script_path() -> None:
    fname = "tapscript_test_vector.json"
    filename = path.join(path.dirname(__file__), "_data", fname)
    with open(filename, "r", encoding="ascii") as file_:
        data = json.load(file_)

    for x in data:

        prevouts = [TxOut.parse(prevout) for prevout in x["prevouts"]]
        index = x["index"]

        if not is_p2tr(prevouts[index].script_pub_key.script):
            continue

        script_sig = x["success"]["scriptSig"]
        assert not script_sig

        witness = Witness(x["success"]["witness"])
        if len(witness.stack) >= 2 and witness.stack[-1][0] == 0x50:
            witness.stack = witness.stack[:-1]

        # check script paths
        if len(witness.stack) < 2:
            continue

        Q = type_and_payload(prevouts[index].script_pub_key.script)[1]

        script = witness.stack[-2]
        control = witness.stack[-1]

        assert check_output_pubkey(Q, script, control)


def test_taproot_key_tweaking() -> None:
    prvkey = 123456
    pubkey = mult(prvkey)

    script_trees = [
        None,
        [(0xC0, ["OP_1"])],
        [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]],
    ]

    for script_tree in script_trees:
        tweaked_prvkey = output_prvkey(prvkey, script_tree)
        tweaked_pubkey = output_pubkey(pubkey, script_tree)[0]

        assert tweaked_pubkey == mult(tweaked_prvkey)[0].to_bytes(32, "big")


def test_invalid_control_block() -> None:

    err_msg = "Control block too long"
    with pytest.raises(BTClibValueError, match=err_msg):
        check_output_pubkey(b"\x00" * 32, b"\x00", b"\x00" * 4130)

    err_msg = "Invalid control block length"
    with pytest.raises(BTClibValueError, match=err_msg):
        check_output_pubkey(b"\x00" * 32, b"\x00", b"\x00" * 100)


def test_unspendable_script() -> None:
    err_msg = "Missing data"
    with pytest.raises(BTClibValueError, match=err_msg):
        output_pubkey()


def test_control_block() -> None:

    script_tree = [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]]
    pubkey = output_pubkey(None, script_tree)[0]
    script, control = input_script_sig(None, script_tree, 0)
    assert check_output_pubkey(pubkey, serialize(script), control)

    prvkey = 123456
    internal_pubkey = mult(prvkey)
    script_tree = [[(0xC0, ["OP_2"])], [(0xC0, ["OP_3"])]]
    pubkey = output_pubkey(internal_pubkey, script_tree)[0]
    script, control = input_script_sig(internal_pubkey, script_tree, 0)
    assert check_output_pubkey(pubkey, serialize(script), control)


def test_bip_test_vector():

    test_vector = [
        {
            "pubkey": "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
            "script_tree": [],
            "tweaked_pubkey": "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
            "address": "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5",
        },
        {
            "pubkey": "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
            "script_tree": [
                [
                    0xC0,
                    [
                        "d85a959b0290bf19bb89ed43c916be835475d013da4b362117393e25a48229b8",
                        "OP_CHECKSIG",
                    ],
                ]
            ],
            "tweaked_pubkey": "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
            "address": "bc1pz37fc4cn9ah8anwm4xqqhvxygjf9rjf2resrw8h8w4tmvcs0863sa2e586",
        },
        {
            "pubkey": "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820",
            "script_tree": [
                [
                    0xC0,
                    [
                        "b617298552a72ade070667e86ca63b8f5789a9fe8731ef91202a91c9f3459007",
                        "OP_CHECKSIG",
                    ],
                ]
            ],
            "tweaked_pubkey": "e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
            "address": "bc1punvppl2stp38f7kwv2u2spltjuvuaayuqsthe34hd2dyy5w4g58qqfuag5",
        },
        {
            "pubkey": "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592",
            "script_tree": [
                [
                    [
                        0xC0,
                        [
                            "387671353e273264c495656e27e39ba899ea8fee3bb69fb2a680e22093447d48",
                            "OP_CHECKSIG",
                        ],
                    ]
                ],
                [[0x98, ["424950333431"]]],
            ],
            "tweaked_pubkey": "0f63ca2c7639b9bb4be0465cc0aa3ee78a0761ba5f5f7d6ff8eab340f09da561",
            "address": "bc1ppa3u5trk8xumkjlqgewvp237u79qwcd6ta0h6mlca2e5puya54ssw9zq0y",
        },
        {
            "pubkey": "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8",
            "script_tree": [
                [
                    [
                        0xC0,
                        [
                            "44b178d64c32c4a05cc4f4d1407268f764c940d20ce97abfd44db5c3592b72fd",
                            "OP_CHECKSIG",
                        ],
                    ]
                ],
                [[0x52, ["546170726f6f74"]]],
            ],
            "tweaked_pubkey": "053690babeabbb7850c32eead0acf8df990ced79f7a31e358fabf2658b4bc587",
            "address": "bc1pq5mfpw474wahs5xr9m4dpt8cm7vsemte7733udv040extz6tckrs29g04c",
        },
        {
            "pubkey": "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f",
            "script_tree": [
                [
                    [
                        0xC0,
                        [
                            "72ea6adcf1d371dea8fba1035a09f3d24ed5a059799bae114084130ee5898e69",
                            "OP_CHECKSIG",
                        ],
                    ]
                ],
                [
                    [
                        [
                            0xC0,
                            [
                                "2352d137f2f3ab38d1eaa976758873377fa5ebb817372c71e2c542313d4abda8",
                                "OP_CHECKSIG",
                            ],
                        ]
                    ],
                    [
                        [
                            0xC0,
                            [
                                "7337c0dd4253cb86f2c43a2351aadd82cccb12a172cd120452b9bb8324f2186a",
                                "OP_CHECKSIG",
                            ],
                        ]
                    ],
                ],
            ],
            "tweaked_pubkey": "91b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
            "address": "bc1pjxmy65eywgafs5tsunw95ruycpqcqnev6ynxp7jaasylcgtcxczs6n332e",
        },
        {
            "pubkey": "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d",
            "script_tree": [
                [
                    [
                        0xC0,
                        [
                            "71981521ad9fc9036687364118fb6ccd2035b96a423c59c5430e98310a11abe2",
                            "OP_CHECKSIG",
                        ],
                    ]
                ],
                [
                    [
                        [
                            0xC0,
                            [
                                "d5094d2dbe9b76e2c245a2b89b6006888952e2faa6a149ae318d69e520617748",
                                "OP_CHECKSIG",
                            ],
                        ]
                    ],
                    [
                        [
                            0xC0,
                            [
                                "c440b462ad48c7a77f94cd4532d8f2119dcebbd7c9764557e62726419b08ad4c",
                                "OP_CHECKSIG",
                            ],
                        ]
                    ],
                ],
            ],
            "tweaked_pubkey": "75169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
            "address": "bc1pw5tf7sqp4f50zka7629jrr036znzew70zxyvvej3zrpf8jg8hqcssyuewe",
        },
    ]

    for test in test_vector:
        tweaked_pubkey = output_pubkey("02" + test["pubkey"], test["script_tree"])[0]
        assert tweaked_pubkey.hex() == test["tweaked_pubkey"]

        address = b32.p2tr("02" + test["pubkey"], test["script_tree"])
        assert address == test["address"]
