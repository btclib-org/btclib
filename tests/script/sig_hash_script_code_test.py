#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the script code a sig_hash commits to (issue #176).

The script code is a *slice of the script's own bytes*, and every test
here pins some consequence of that: a re-serialization of part of a
parse is a different thing whenever the two differ — and they differ
for any push not written minimally, which consensus allows and
`Script.assert_valid` already says it allows.
"""

from __future__ import annotations

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey, sig_hash
from btclib.tx import OutPoint, Tx, TxIn, TxOut

# OP_PUSHDATA1 of one byte where a one-byte push would do, then
# OP_CODESEPARATOR OP_CHECKSIG. Core signs 4c0105ac for it in a legacy
# input -- the separator elided by the serializer, the push as written --
# and 4c0105abac in a segwit v0 one
NON_MINIMAL = bytes.fromhex("4c0105abac")
MINIMAL = bytes.fromhex("0105abac")


def one_input_tx() -> Tx:
    return Tx(
        vin=[TxIn(OutPoint(), b"", 0xFFFFFFFF, check_validity=False)],
        vout=[TxOut(0, ScriptPubKey(b""), check_validity=False)],
        check_validity=False,
    )


def test_a_push_is_signed_as_it_was_written() -> None:
    """Two script codes that differ in bytes hash differently.

    They differ in one byte and mean the same push, so a script code
    recovered by parsing and re-serializing collapses them onto the
    second — one preimage for two scripts, and the wrong one whenever
    the script on the chain is the first.
    """
    tx = one_input_tx()
    assert sig_hash.legacy(NON_MINIMAL, tx, 0, sig_hash.ALL) != sig_hash.legacy(
        MINIMAL, tx, 0, sig_hash.ALL
    )
    assert sig_hash.segwit_v0(
        NON_MINIMAL, tx, 0, sig_hash.ALL, 1
    ) != sig_hash.segwit_v0(MINIMAL, tx, 0, sig_hash.ALL, 1)


def test_legacy_elides_the_separators_and_segwit_v0_keeps_them() -> None:
    """Which is the whole of the difference between the two script codes.

    Core elides them in `CTransactionSignatureSerializer::Serialize
    ScriptCode` and nowhere else, so the elision is the legacy
    serializer's and BIP-143 does without it.
    """
    tx = one_input_tx()
    elided = bytes.fromhex("4c0105ac")
    assert sig_hash.legacy(NON_MINIMAL, tx, 0, sig_hash.ALL) == sig_hash.legacy(
        elided, tx, 0, sig_hash.ALL
    )
    assert sig_hash.segwit_v0(
        NON_MINIMAL, tx, 0, sig_hash.ALL, 1
    ) != sig_hash.segwit_v0(elided, tx, 0, sig_hash.ALL, 1)


def test_a_separator_inside_a_push_is_data() -> None:
    """0xab is only an op code where an op code is read, so it stays.

    The walk that elides separators reads op codes; a byte scan would
    take this one out of the middle of a public key.
    """
    tx = one_input_tx()
    pushed = bytes.fromhex("02ab00ac")  # a two-byte push of ab00, OP_CHECKSIG
    scanned = bytes.fromhex("0200ac")  # what dropping every 0xab would give
    assert sig_hash.legacy(pushed, tx, 0, sig_hash.ALL) != sig_hash.legacy(
        scanned, tx, 0, sig_hash.ALL
    )


def test_a_truncated_tail_is_kept_verbatim() -> None:
    """No op code can be read from it, and Core writes it out as it is.

    A script code reaches the serializer already cut and already
    FindAndDeleted, so its last push can be half a push; Core's
    SerializeScriptCode loop ends on the GetOp that fails and copies
    what is left.
    """
    tx = one_input_tx()
    # OP_CODESEPARATOR, then a push of five bytes with three of them
    truncated = bytes.fromhex("ab05010203")
    assert sig_hash.legacy(truncated, tx, 0, sig_hash.ALL) == sig_hash.legacy(
        bytes.fromhex("05010203"), tx, 0, sig_hash.ALL
    )


def test_from_tx_takes_the_separator_occurrence() -> None:
    """And 0, the default, is the script whole."""
    script = bytes.fromhex("ab51ab52")  # separators before OP_1 and OP_2
    prevout = TxOut(0, ScriptPubKey(script), check_validity=False)
    tx = one_input_tx()

    for index, script_code in enumerate([script, script[1:], script[3:]]):
        assert sig_hash.from_tx(
            [prevout], tx, 0, sig_hash.ALL, codesep_index=index
        ) == sig_hash.legacy(script_code, tx, 0, sig_hash.ALL)

    with pytest.raises(BTClibValueError, match="OP_CODESEPARATOR index 3"):
        sig_hash.from_tx([prevout], tx, 0, sig_hash.ALL, codesep_index=3)
    with pytest.raises(BTClibValueError, match="negative OP_CODESEPARATOR index"):
        sig_hash.from_tx([prevout], tx, 0, sig_hash.ALL, codesep_index=-1)


def test_a_p2wsh_input_with_no_witness_script() -> None:
    """There is no script to take a script code from, and it says so.

    `stack[-1]` on an empty stack was an IndexError, malformed input
    leaving through something other than BTClibValueError; the engine
    took the same guard in #182, Core calling it
    WITNESS_PROGRAM_WITNESS_EMPTY.
    """
    p2wsh = TxOut(0, ScriptPubKey(bytes.fromhex("0020" + "00" * 32)))
    with pytest.raises(BTClibValueError, match="empty p2wsh witness stack"):
        sig_hash.from_tx([p2wsh], one_input_tx(), 0, sig_hash.ALL)


def test_no_separator_index_where_there_is_no_script_to_cut() -> None:
    """A p2wpkh script code is built, not read, and taproot commits instead.

    BIP-341 hashes the *position* of the last executed separator rather
    than truncating anything, and this builds the extension with
    0xffffffff, none executed — which is the one case Core's signer
    supports too, `sign.cpp` saying so in as many words.
    """
    tx = one_input_tx()
    p2wpkh = TxOut(0, ScriptPubKey(bytes.fromhex("0014" + "00" * 20)))
    p2tr = TxOut(0, ScriptPubKey(bytes.fromhex("5120" + "00" * 32)))

    with pytest.raises(BTClibValueError, match="index for a p2wpkh input"):
        sig_hash.from_tx([p2wpkh], tx, 0, sig_hash.ALL, codesep_index=1)
    with pytest.raises(BTClibValueError, match="index for a taproot input"):
        sig_hash.from_tx([p2tr], tx, 0, sig_hash.ALL, codesep_index=1)
