#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.ecc.musig2` module.

The vectors are BIP327's own, all eight files of
https://github.com/bitcoin/bips/tree/master/bip-0327/vectors, vendored
under `tests/ecc/_data/`; `tests/_data/README.md` pins the revision.
Every case of every file is exercised, the error cases included, and an
error case is checked against the exception the file names -- which
party misbehaved and how, or the message of a plain value error.
"""

from typing import Any

import pytest

from btclib.curves import bytes_from_point, mult
from btclib.ecc import musig2, ssa
from btclib.exceptions import BTClibValueError, InvalidContributionError
from tests import load, vector_id

# the two exception types BIP327 tells apart: a caller's own bad
# argument, and a peer's bad contribution
_ERRORS = (BTClibValueError, InvalidContributionError)


def _hex_all(values: list[str]) -> list[bytes]:
    return [bytes.fromhex(value) for value in values]


def _pub_nonce_of(sec_nonce: bytes) -> bytes:
    """Recompute a public nonce from a secret one, k_1*G and k_2*G."""
    return b"".join(
        bytes_from_point(mult(int.from_bytes(sec_nonce[i : i + 32], "big")))
        for i in (0, 32)
    )


def assert_error(error: dict[str, Any], exc: Exception) -> None:
    """Check the raised exception against what the vector expects."""
    if error["type"] == "invalid_contribution":
        assert isinstance(exc, InvalidContributionError)
        assert exc.signer == error["signer"]
        assert exc.contrib == error["contrib"]
    else:
        assert error["type"] == "value"
        assert isinstance(exc, BTClibValueError)
        # the message, byte for byte: the four BIP327 strings btclib
        # copies verbatim are the reason it can be compared at all
        assert str(exc) == error["message"]


def test_key_sort_vectors() -> None:
    test_data = load("ecc", "_data", "key_sort_vectors.json")
    pub_keys = _hex_all(test_data["pubkeys"])
    unsorted = list(pub_keys)

    assert musig2.key_sort(pub_keys) == _hex_all(test_data["sorted_pubkeys"])
    # btclib sorts into a new list where the reference sorts in place
    assert pub_keys == unsorted


_KEY_AGG = load("ecc", "_data", "key_agg_vectors.json")


def key_agg_valid_vectors() -> list[Any]:
    pub_keys = _hex_all(_KEY_AGG["pubkeys"])
    return [
        pytest.param(
            [pub_keys[i] for i in case["key_indices"]],
            bytes.fromhex(case["expected"]),
            id=vector_id(index, case["key_indices"]),
        )
        for index, case in enumerate(_KEY_AGG["valid_test_cases"])
    ]


@pytest.mark.parametrize(("pub_keys", "expected"), key_agg_valid_vectors())
def test_key_agg_vectors(pub_keys: list[bytes], expected: bytes) -> None:
    assert musig2.key_agg(pub_keys).x_only_pub_key == expected


def key_agg_error_vectors() -> list[Any]:
    pub_keys = _hex_all(_KEY_AGG["pubkeys"])
    tweaks = _hex_all(_KEY_AGG["tweaks"])
    return [
        pytest.param(
            [pub_keys[i] for i in case["key_indices"]],
            [tweaks[i] for i in case["tweak_indices"]],
            case["is_xonly"],
            case["error"],
            id=vector_id(index, case["comment"]),
        )
        for index, case in enumerate(_KEY_AGG["error_test_cases"])
    ]


@pytest.mark.parametrize(
    ("pub_keys", "tweaks", "is_xonly", "error"), key_agg_error_vectors()
)
def test_key_agg_error_vectors(
    pub_keys: list[bytes], tweaks: list[bytes], is_xonly: list[bool], error: Any
) -> None:
    with pytest.raises(_ERRORS) as excinfo:
        musig2.key_agg_and_tweak(pub_keys, tweaks, is_xonly)
    assert_error(error, excinfo.value)


def nonce_gen_vectors() -> list[Any]:
    test_data = load("ecc", "_data", "nonce_gen_vectors.json")
    return [
        pytest.param(case, id=vector_id(index, case["msg"]))
        for index, case in enumerate(test_data["test_cases"])
    ]


@pytest.mark.parametrize("case", nonce_gen_vectors())
def test_nonce_gen_vectors(case: dict[str, Any]) -> None:
    sec_nonce, pub_nonce = musig2.nonce_gen_(
        case["rand_"],
        case["sk"],
        case["pk"],
        case["aggpk"],
        case["msg"],
        case["extra_in"],
    )
    assert bytes(sec_nonce) == bytes.fromhex(case["expected_secnonce"])
    assert pub_nonce == bytes.fromhex(case["expected_pubnonce"])


_NONCE_AGG = load("ecc", "_data", "nonce_agg_vectors.json")


def nonce_agg_valid_vectors() -> list[Any]:
    pub_nonces = _hex_all(_NONCE_AGG["pnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pnonce_indices"]],
            bytes.fromhex(case["expected"]),
            id=vector_id(index, case.get("comment")),
        )
        for index, case in enumerate(_NONCE_AGG["valid_test_cases"])
    ]


@pytest.mark.parametrize(("pub_nonces", "expected"), nonce_agg_valid_vectors())
def test_nonce_agg_vectors(pub_nonces: list[bytes], expected: bytes) -> None:
    assert musig2.nonce_agg(pub_nonces) == expected


def nonce_agg_error_vectors() -> list[Any]:
    pub_nonces = _hex_all(_NONCE_AGG["pnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pnonce_indices"]],
            case["error"],
            id=vector_id(index, case["comment"]),
        )
        for index, case in enumerate(_NONCE_AGG["error_test_cases"])
    ]


@pytest.mark.parametrize(("pub_nonces", "error"), nonce_agg_error_vectors())
def test_nonce_agg_error_vectors(pub_nonces: list[bytes], error: Any) -> None:
    with pytest.raises(_ERRORS) as excinfo:
        musig2.nonce_agg(pub_nonces)
    assert_error(error, excinfo.value)


_SIGN_VERIFY = load("ecc", "_data", "sign_verify_vectors.json")
_SV_SK = _SIGN_VERIFY["sk"]
_SV_PUB_KEYS = _hex_all(_SIGN_VERIFY["pubkeys"])
_SV_SEC_NONCES = _hex_all(_SIGN_VERIFY["secnonces"])
_SV_PUB_NONCES = _hex_all(_SIGN_VERIFY["pnonces"])
_SV_AGG_NONCES = _hex_all(_SIGN_VERIFY["aggnonces"])
_SV_MSGS = _hex_all(_SIGN_VERIFY["msgs"])


def test_sign_verify_vectors_consistency() -> None:
    """The file's own cross-references, as the reference checks them."""
    assert _SV_PUB_KEYS[0] == musig2.individual_pub_key(_SV_SK)
    # the public nonce at index 0 is the one of the secnonce at index 0
    assert _SV_PUB_NONCES[0] == _pub_nonce_of(_SV_SEC_NONCES[0])
    # the aggregate of the first three public nonces is at index 0, and
    # the aggregate of the first and the fourth -- the infinity point in
    # both halves -- at index 1
    assert _SV_AGG_NONCES[0] == musig2.nonce_agg(_SV_PUB_NONCES[:3])
    assert _SV_AGG_NONCES[1] == musig2.nonce_agg([_SV_PUB_NONCES[0], _SV_PUB_NONCES[3]])


def sign_verify_valid_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case.get("comment")))
        for index, case in enumerate(_SIGN_VERIFY["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", sign_verify_valid_vectors())
def test_sign_verify_valid_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_SV_PUB_NONCES[i] for i in case["nonce_indices"]]
    agg_nonce = _SV_AGG_NONCES[case["aggnonce_index"]]
    assert musig2.nonce_agg(pub_nonces) == agg_nonce
    msg = _SV_MSGS[case["msg_index"]]
    expected = bytes.fromhex(case["expected"])

    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, [], [], msg)
    # a copy: signing consumes the secnonce, and the vectors reuse it
    sec_nonce = bytearray(_SV_SEC_NONCES[0])
    assert musig2.sign(sec_nonce, _SV_SK, session_ctx) == expected
    assert musig2.partial_sig_verify(
        expected, pub_nonces, pub_keys, [], [], msg, case["signer_index"]
    )


def sign_error_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIGN_VERIFY["sign_error_test_cases"])
    ]


@pytest.mark.parametrize("case", sign_error_vectors())
def test_sign_error_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    agg_nonce = _SV_AGG_NONCES[case["aggnonce_index"]]
    msg = _SV_MSGS[case["msg_index"]]
    sec_nonce = bytearray(_SV_SEC_NONCES[case["secnonce_index"]])

    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, [], [], msg)
    with pytest.raises(_ERRORS) as excinfo:
        musig2.sign(sec_nonce, _SV_SK, session_ctx)
    assert_error(case["error"], excinfo.value)


def verify_fail_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIGN_VERIFY["verify_fail_test_cases"])
    ]


@pytest.mark.parametrize("case", verify_fail_vectors())
def test_verify_fail_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_SV_PUB_NONCES[i] for i in case["nonce_indices"]]
    msg = _SV_MSGS[case["msg_index"]]
    assert not musig2.partial_sig_verify(
        case["sig"], pub_nonces, pub_keys, [], [], msg, case["signer_index"]
    )


def verify_error_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIGN_VERIFY["verify_error_test_cases"])
    ]


@pytest.mark.parametrize("case", verify_error_vectors())
def test_verify_error_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_SV_PUB_NONCES[i] for i in case["nonce_indices"]]
    msg = _SV_MSGS[case["msg_index"]]
    with pytest.raises(_ERRORS) as excinfo:
        musig2.partial_sig_verify(
            case["sig"], pub_nonces, pub_keys, [], [], msg, case["signer_index"]
        )
    assert_error(case["error"], excinfo.value)


_TWEAK = load("ecc", "_data", "tweak_vectors.json")
_TW_SK = _TWEAK["sk"]
_TW_PUB_KEYS = _hex_all(_TWEAK["pubkeys"])
_TW_SEC_NONCE = bytes.fromhex(_TWEAK["secnonce"])
_TW_PUB_NONCES = _hex_all(_TWEAK["pnonces"])
_TW_AGG_NONCE = bytes.fromhex(_TWEAK["aggnonce"])
_TW_TWEAKS = _hex_all(_TWEAK["tweaks"])
_TW_MSG = bytes.fromhex(_TWEAK["msg"])


def test_tweak_vectors_consistency() -> None:
    """The file's own cross-references, as the reference checks them."""
    assert _TW_PUB_KEYS[0] == musig2.individual_pub_key(_TW_SK)
    assert _TW_PUB_NONCES[0] == _pub_nonce_of(_TW_SEC_NONCE)
    assert _TW_AGG_NONCE == musig2.nonce_agg(_TW_PUB_NONCES[:3])


def tweak_valid_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_TWEAK["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", tweak_valid_vectors())
def test_tweak_valid_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_TW_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_TW_PUB_NONCES[i] for i in case["nonce_indices"]]
    tweaks = [_TW_TWEAKS[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    expected = bytes.fromhex(case["expected"])

    session_ctx = musig2.SessionContext(
        _TW_AGG_NONCE, pub_keys, tweaks, is_xonly, _TW_MSG
    )
    sec_nonce = bytearray(_TW_SEC_NONCE)
    assert musig2.sign(sec_nonce, _TW_SK, session_ctx) == expected
    assert musig2.partial_sig_verify(
        expected,
        pub_nonces,
        pub_keys,
        tweaks,
        is_xonly,
        _TW_MSG,
        case["signer_index"],
    )


def tweak_error_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_TWEAK["error_test_cases"])
    ]


@pytest.mark.parametrize("case", tweak_error_vectors())
def test_tweak_error_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_TW_PUB_KEYS[i] for i in case["key_indices"]]
    tweaks = [_TW_TWEAKS[i] for i in case["tweak_indices"]]
    session_ctx = musig2.SessionContext(
        _TW_AGG_NONCE, pub_keys, tweaks, case["is_xonly"], _TW_MSG
    )
    with pytest.raises(_ERRORS) as excinfo:
        musig2.sign(bytearray(_TW_SEC_NONCE), _TW_SK, session_ctx)
    assert_error(case["error"], excinfo.value)


_DET_SIGN = load("ecc", "_data", "det_sign_vectors.json")
_DS_SK = _DET_SIGN["sk"]
_DS_PUB_KEYS = _hex_all(_DET_SIGN["pubkeys"])
_DS_MSGS = _hex_all(_DET_SIGN["msgs"])


def test_det_sign_vectors_consistency() -> None:
    assert _DS_PUB_KEYS[0] == musig2.individual_pub_key(_DS_SK)


def det_sign_valid_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case.get("comment")))
        for index, case in enumerate(_DET_SIGN["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", det_sign_valid_vectors())
def test_det_sign_valid_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_DS_PUB_KEYS[i] for i in case["key_indices"]]
    agg_other_nonce = case["aggothernonce"]
    tweaks = case["tweaks"]
    is_xonly = case["is_xonly"]
    msg = _DS_MSGS[case["msg_index"]]
    expected = _hex_all(case["expected"])

    pub_nonce, psig = musig2.deterministic_sign(
        _DS_SK, agg_other_nonce, pub_keys, tweaks, is_xonly, msg, case["rand"]
    )
    assert pub_nonce == expected[0]
    assert psig == expected[1]

    agg_nonce = musig2.nonce_agg([agg_other_nonce, pub_nonce])
    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, tweaks, is_xonly, msg)
    assert musig2.partial_sig_verify_(
        psig, pub_nonce, pub_keys[case["signer_index"]], session_ctx
    )


def det_sign_error_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_DET_SIGN["error_test_cases"])
    ]


@pytest.mark.parametrize("case", det_sign_error_vectors())
def test_det_sign_error_vectors(case: dict[str, Any]) -> None:
    pub_keys = [_DS_PUB_KEYS[i] for i in case["key_indices"]]
    with pytest.raises(_ERRORS) as excinfo:
        musig2.deterministic_sign(
            _DS_SK,
            case["aggothernonce"],
            pub_keys,
            case["tweaks"],
            case["is_xonly"],
            _DS_MSGS[case["msg_index"]],
            case["rand"],
        )
    assert_error(case["error"], excinfo.value)


_SIG_AGG = load("ecc", "_data", "sig_agg_vectors.json")
_SA_PUB_KEYS = _hex_all(_SIG_AGG["pubkeys"])
_SA_PUB_NONCES = _hex_all(_SIG_AGG["pnonces"])
_SA_TWEAKS = _hex_all(_SIG_AGG["tweaks"])
_SA_PSIGS = _hex_all(_SIG_AGG["psigs"])
_SA_MSG = bytes.fromhex(_SIG_AGG["msg"])


def sig_agg_valid_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["key_indices"]))
        for index, case in enumerate(_SIG_AGG["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", sig_agg_valid_vectors())
def test_sig_agg_valid_vectors(case: dict[str, Any]) -> None:
    pub_nonces = [_SA_PUB_NONCES[i] for i in case["nonce_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    assert agg_nonce == musig2.nonce_agg(pub_nonces)

    pub_keys = [_SA_PUB_KEYS[i] for i in case["key_indices"]]
    tweaks = [_SA_TWEAKS[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    psigs = [_SA_PSIGS[i] for i in case["psig_indices"]]

    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, tweaks, is_xonly, _SA_MSG)
    sig = musig2.partial_sig_agg(psigs, session_ctx)
    assert sig.serialize() == bytes.fromhex(case["expected"])
    # the aggregate is an ordinary BIP340 signature, and btclib's own
    # verifier is what says so
    agg_pk = musig2.key_agg_and_tweak(pub_keys, tweaks, is_xonly).x_only_pub_key
    assert ssa.verify_(_SA_MSG, agg_pk, sig)


def sig_agg_error_vectors() -> list[Any]:
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIG_AGG["error_test_cases"])
    ]


@pytest.mark.parametrize("case", sig_agg_error_vectors())
def test_sig_agg_error_vectors(case: dict[str, Any]) -> None:
    pub_nonces = [_SA_PUB_NONCES[i] for i in case["nonce_indices"]]
    pub_keys = [_SA_PUB_KEYS[i] for i in case["key_indices"]]
    tweaks = [_SA_TWEAKS[i] for i in case["tweak_indices"]]
    psigs = [_SA_PSIGS[i] for i in case["psig_indices"]]

    session_ctx = musig2.SessionContext(
        musig2.nonce_agg(pub_nonces), pub_keys, tweaks, case["is_xonly"], _SA_MSG
    )
    with pytest.raises(_ERRORS) as excinfo:
        musig2.partial_sig_agg(psigs, session_ctx)
    assert_error(case["error"], excinfo.value)


# btclib's own tests, past the vectors: the whole interactive protocol,
# once through, over a message that is not 32 bytes -- which is the
# precondition issue #190 names, BIP327 signing a message of any size and
# the bindings taking none but a 32-byte one (issue #169)
_SK_1 = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
_SK_2 = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
_MSG = b"a message the two signers agree on, and not of 32 bytes"


@pytest.mark.parametrize(
    ("tweaks", "is_xonly"),
    [
        pytest.param([], [], id="no-tweak"),
        pytest.param([bytes(31) + b"\x07"], [True], id="x-only-tweak"),
        pytest.param(
            [bytes(31) + b"\x07", bytes(31) + b"\x08"],
            [False, True],
            id="plain-then-x-only",
        ),
    ],
)
def test_session(tweaks: list[bytes], is_xonly: list[bool]) -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    pub_keys = musig2.key_sort([pk_2, pk_1])
    agg_pk = musig2.key_agg_and_tweak(pub_keys, tweaks, is_xonly).x_only_pub_key

    # round 1: signer 1 draws its nonce, signer 2 derives one instead
    sec_nonce_1, pub_nonce_1 = musig2.nonce_gen(
        _SK_1, pk_1, agg_pk, _MSG, (1).to_bytes(4, "big")
    )
    agg_other_nonce = musig2.nonce_agg([pub_nonce_1])
    pub_nonce_2, psig_2 = musig2.deterministic_sign(
        _SK_2, agg_other_nonce, pub_keys, tweaks, is_xonly, _MSG, bytes(32)
    )

    # round 2: signer 1 signs, and each holds the other to its partial.
    # Nonces, keys and partial signatures are indexed alike, which is
    # what key_sort settled: aggregation is order-independent, telling
    # signer i from signer j is not
    nonce_of = {pk_1: pub_nonce_1, pk_2: pub_nonce_2}
    pub_nonces = [nonce_of[pk] for pk in pub_keys]
    agg_nonce = musig2.nonce_agg(pub_nonces)
    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, tweaks, is_xonly, _MSG)
    psig_1 = musig2.sign(sec_nonce_1, _SK_1, session_ctx)
    psig_of = {pk_1: psig_1, pk_2: psig_2}
    psigs = [psig_of[pk] for pk in pub_keys]
    for i, psig in enumerate(psigs):
        assert musig2.partial_sig_verify(
            psig, pub_nonces, pub_keys, tweaks, is_xonly, _MSG, i
        )

    # a partial signature is about one signer, one message and one nonce
    assert not musig2.partial_sig_verify(
        psigs[0], pub_nonces, pub_keys, tweaks, is_xonly, _MSG, 1
    )
    assert not musig2.partial_sig_verify(
        psigs[0], pub_nonces, pub_keys, tweaks, is_xonly, _MSG + b"!", 0
    )

    sig = musig2.partial_sig_agg(psigs, session_ctx)
    assert ssa.verify_(_MSG, agg_pk, sig)
    ssa.assert_as_valid_(_MSG, agg_pk, sig)


def test_sec_nonce_signs_once() -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    session_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce]), [pk_1], [], [], _MSG
    )
    musig2.sign(sec_nonce, _SK_1, session_ctx)
    # the bytearray has been zeroed, which is the whole defence
    assert bytes(sec_nonce[:64]) == bytes(64)
    with pytest.raises(BTClibValueError, match="first secnonce value is out of range"):
        musig2.sign(sec_nonce, _SK_1, session_ctx)


def test_sec_nonce_second_half_out_of_range() -> None:
    # the vectors zero a whole secnonce, which the first half already
    # answers; the second half is checked here
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    sec_nonce[32:64] = bytes(32)
    session_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce]), [pk_1], [], [], _MSG
    )
    with pytest.raises(BTClibValueError, match="second secnonce value is out of range"):
        musig2.sign(sec_nonce, _SK_1, session_ctx)


def test_sec_nonce_of_another_key() -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    session_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce]), [pk_1, pk_2], [], [], _MSG
    )
    with pytest.raises(BTClibValueError, match="does not match nonce_gen argument"):
        musig2.sign(sec_nonce, _SK_2, session_ctx)


def test_session_context_normalizes() -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    del sec_nonce
    agg_nonce = musig2.nonce_agg([pub_nonce])
    from_octets = musig2.SessionContext(
        agg_nonce.hex(), [pk_1.hex()], [], [], _MSG.hex()
    )
    assert from_octets == musig2.SessionContext(agg_nonce, [pk_1], [], [], _MSG)


def test_tweaks_and_is_xonly_pair_up() -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    with pytest.raises(BTClibValueError, match="must have the same length"):
        musig2.key_agg_and_tweak([pk_1], [bytes(32)], [])
    with pytest.raises(BTClibValueError, match="must have the same length"):
        musig2.SessionContext(bytes(66), [pk_1], [bytes(32)], [], _MSG)


def test_tweak_size() -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    key_agg_ctx = musig2.key_agg([pk_1])
    with pytest.raises(BTClibValueError, match="must be a 32-byte array"):
        musig2.apply_tweak(key_agg_ctx, bytes(31), False)


def test_a_nonce_per_key() -> None:
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    del sec_nonce
    with pytest.raises(BTClibValueError, match="must have the same length"):
        musig2.partial_sig_verify(bytes(32), [pub_nonce], [pk_1, pk_2], [], [], _MSG, 0)


def test_invalid_contribution_names_the_party() -> None:
    exc = InvalidContributionError(2, "pubkey")
    assert exc.signer == 2
    assert exc.contrib == "pubkey"
    assert str(exc) == "invalid pubkey from signer 2"
    # the aggregator has no key, so it has no index either
    assert str(InvalidContributionError(None, "aggnonce")) == (
        "invalid aggnonce from the aggregator"
    )
