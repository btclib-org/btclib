# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.musig2` module.

The vectors are BIP327's own, all eight files of
https://github.com/bitcoin/bips/tree/master/bip-0327/vectors, vendored
under `tests/ecc/_data/`; `tests/_data/README.md` pins the revision.
Every case of every file is exercised, the error cases included, and an
error case is checked against the exception the file names -- which
party misbehaved and how, or the message of a plain value error.

btclib-org/btclib#1048 adds a second authority beside those vectors:
`btclib_secp256k1.musig`, the wrapper btclib-org/btclib-secp256k1#282
built around libsecp256k1's own MuSig2 module. Every "matches bindings"
or "verified by bindings" test below calls it and compares -- the tree's
stated position since btclib-org/btclib#993 is that the bindings are the
reference implementation, and agreeing with them is the property worth
checking, not the vectors' own numbers a second time.

Two operations have no such oracle, and that absence is recorded here
rather than left for a reader to notice on their own, per #993's rule
that a missing third-party vector is said so in the inventory instead of
being counted twice: `nonce_gen_` derives a nonce libsecp256k1's own
`musig_nonce_gen` derives differently, so nothing below crosses the
derivation, only the arithmetic relating a pubnonce to a secnonce that
`tests.ecc.musig2_test.test_sign_verify_vectors_consistency` and
`test_tweak_vectors_consistency` already check with btclib's own `mult`;
`nonce_gen_vectors.json` stays the sole authority on the derivation.
`deterministic_sign` has no libsecp256k1 counterpart at all --
`musig_nonce_gen_counter` is a different construction, for a
non-repeating counter rather than for collapsing the two rounds -- so
`det_sign_vectors.json` is and stays its only authority.

The gate every oracle test below has to pass through: `musig_nonce_gen`
and `musig_nonce_process` take a fixed `msg32`, with no length
parameter, so BIP327's own empty-message and 38-byte-message vectors
(`sign_verify_vectors.json`'s messages at index 1 and 2) cannot reach the
C call at all. Those cases are not filtered out of the parameter list --
they are skipped by `pytest.mark.skip`, with the reason stated, so the
skip is visible in a test report rather than an absence nobody notices.
"""

import secrets
from typing import Any

import pytest

from btclib._libsecp256k1 import INSTALLED
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.ecc import musig2, ssa
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    InvalidContributionError,
)
from tests import load, needs_bindings, vector_id

if INSTALLED:
    from btclib_secp256k1 import musig as libsecp256k1_musig
else:  # pragma: no cover
    # never called from a skipped test, mirroring the fallback
    # `btclib._libsecp256k1` gives every name it wraps
    libsecp256k1_musig = None  # type: ignore[assignment]

# the two exception types BIP327 tells apart: a caller's own bad
# argument, and a peer's bad contribution
_ERRORS = (BTClibValueError, InvalidContributionError)


def _hex_all(values: list[str]) -> list[bytes]:
    """Convert a list of hex strings to bytes, one for one."""
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
    """Reproduce BIP327's key_sort_vectors.json, sorting into a new list."""
    test_data = load("ecc", "_data", "key_sort_vectors.json")
    pub_keys = _hex_all(test_data["pubkeys"])
    unsorted = list(pub_keys)

    assert musig2.key_sort(pub_keys) == _hex_all(test_data["sorted_pubkeys"])
    # btclib sorts into a new list where the reference sorts in place
    assert pub_keys == unsorted


_KEY_AGG = load("ecc", "_data", "key_agg_vectors.json")


def key_agg_valid_vectors() -> list[Any]:
    """One param per valid case of key_agg_vectors.json."""
    pub_keys = _hex_all(_KEY_AGG["pubkeys"])
    return [
        pytest.param(
            [pub_keys[i] for i in case["key_indices"]],
            bytes.fromhex(case["expected"]),
            id=vector_id(index, case["key_indices"]),
        )
        for index, case in enumerate(_KEY_AGG["valid_test_cases"])
    ]


@pytest.mark.parametrize("pub_keys, expected", key_agg_valid_vectors())
def test_key_agg_vectors(pub_keys: list[bytes], expected: bytes) -> None:
    """Reproduce the valid cases of BIP327's key_agg_vectors.json."""
    assert musig2.key_agg(pub_keys).x_only_pub_key == expected


def key_agg_error_vectors() -> list[Any]:
    """One param per error case of key_agg_vectors.json."""
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


@pytest.mark.parametrize("pub_keys, tweaks, is_xonly, error", key_agg_error_vectors())
def test_key_agg_error_vectors(
    pub_keys: list[bytes], tweaks: list[bytes], is_xonly: list[bool], error: Any
) -> None:
    """Reproduce the error cases of BIP327's key_agg_vectors.json."""
    with pytest.raises(_ERRORS) as excinfo:
        musig2.key_agg_and_tweak(pub_keys, tweaks, is_xonly)
    assert_error(error, excinfo.value)


def nonce_gen_vectors() -> list[Any]:
    """One param per case of nonce_gen_vectors.json."""
    test_data = load("ecc", "_data", "nonce_gen_vectors.json")
    return [
        pytest.param(case, id=vector_id(index, case["msg"]))
        for index, case in enumerate(test_data["test_cases"])
    ]


@pytest.mark.parametrize("case", nonce_gen_vectors())
def test_nonce_gen_vectors(case: dict[str, Any]) -> None:
    """Reproduce BIP327's nonce_gen_vectors.json."""
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
    """One param per valid case of nonce_agg_vectors.json."""
    pub_nonces = _hex_all(_NONCE_AGG["pnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pnonce_indices"]],
            bytes.fromhex(case["expected"]),
            id=vector_id(index, case.get("comment")),
        )
        for index, case in enumerate(_NONCE_AGG["valid_test_cases"])
    ]


@pytest.mark.parametrize("pub_nonces, expected", nonce_agg_valid_vectors())
def test_nonce_agg_vectors(pub_nonces: list[bytes], expected: bytes) -> None:
    """Reproduce the valid cases of BIP327's nonce_agg_vectors.json."""
    assert musig2.nonce_agg(pub_nonces) == expected


def nonce_agg_error_vectors() -> list[Any]:
    """One param per error case of nonce_agg_vectors.json."""
    pub_nonces = _hex_all(_NONCE_AGG["pnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pnonce_indices"]],
            case["error"],
            id=vector_id(index, case["comment"]),
        )
        for index, case in enumerate(_NONCE_AGG["error_test_cases"])
    ]


@pytest.mark.parametrize("pub_nonces, error", nonce_agg_error_vectors())
def test_nonce_agg_error_vectors(pub_nonces: list[bytes], error: Any) -> None:
    """Reproduce the error cases of BIP327's nonce_agg_vectors.json."""
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
    """One param per valid case of sign_verify_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case.get("comment")))
        for index, case in enumerate(_SIGN_VERIFY["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", sign_verify_valid_vectors())
def test_sign_verify_valid_vectors(case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP327's sign_verify_vectors.json."""
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
    """One param per sign error case of sign_verify_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIGN_VERIFY["sign_error_test_cases"])
    ]


@pytest.mark.parametrize("case", sign_error_vectors())
def test_sign_error_vectors(case: dict[str, Any]) -> None:
    """Reproduce the sign error cases of BIP327's sign_verify_vectors.json."""
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    agg_nonce = _SV_AGG_NONCES[case["aggnonce_index"]]
    msg = _SV_MSGS[case["msg_index"]]
    sec_nonce = bytearray(_SV_SEC_NONCES[case["secnonce_index"]])

    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, [], [], msg)
    with pytest.raises(_ERRORS) as excinfo:
        musig2.sign(sec_nonce, _SV_SK, session_ctx)
    assert_error(case["error"], excinfo.value)


def verify_fail_vectors() -> list[Any]:
    """One param per verify fail case of sign_verify_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIGN_VERIFY["verify_fail_test_cases"])
    ]


@pytest.mark.parametrize("case", verify_fail_vectors())
def test_verify_fail_vectors(case: dict[str, Any]) -> None:
    """Reproduce the verify fail cases of sign_verify_vectors.json."""
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_SV_PUB_NONCES[i] for i in case["nonce_indices"]]
    msg = _SV_MSGS[case["msg_index"]]
    assert not musig2.partial_sig_verify(
        case["sig"], pub_nonces, pub_keys, [], [], msg, case["signer_index"]
    )


def verify_error_vectors() -> list[Any]:
    """One param per verify error case of sign_verify_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIGN_VERIFY["verify_error_test_cases"])
    ]


@pytest.mark.parametrize("case", verify_error_vectors())
def test_verify_error_vectors(case: dict[str, Any]) -> None:
    """Reproduce the verify error cases of sign_verify_vectors.json."""
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
    assert musig2.nonce_agg(_TW_PUB_NONCES[:3]) == _TW_AGG_NONCE


def tweak_valid_vectors() -> list[Any]:
    """One param per valid case of tweak_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_TWEAK["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", tweak_valid_vectors())
def test_tweak_valid_vectors(case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP327's tweak_vectors.json."""
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
    """One param per error case of tweak_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_TWEAK["error_test_cases"])
    ]


@pytest.mark.parametrize("case", tweak_error_vectors())
def test_tweak_error_vectors(case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP327's tweak_vectors.json."""
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
    """Check the file's one cross-reference, pubkeys[0] against sk."""
    assert _DS_PUB_KEYS[0] == musig2.individual_pub_key(_DS_SK)


def det_sign_valid_vectors() -> list[Any]:
    """One param per valid case of det_sign_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case.get("comment")))
        for index, case in enumerate(_DET_SIGN["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", det_sign_valid_vectors())
def test_det_sign_valid_vectors(case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP327's det_sign_vectors.json."""
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
    """One param per error case of det_sign_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_DET_SIGN["error_test_cases"])
    ]


@pytest.mark.parametrize("case", det_sign_error_vectors())
def test_det_sign_error_vectors(case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP327's det_sign_vectors.json."""
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
    """One param per valid case of sig_agg_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["key_indices"]))
        for index, case in enumerate(_SIG_AGG["valid_test_cases"])
    ]


@pytest.mark.parametrize("case", sig_agg_valid_vectors())
def test_sig_agg_valid_vectors(case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP327's sig_agg_vectors.json."""
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
    """One param per error case of sig_agg_vectors.json."""
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(_SIG_AGG["error_test_cases"])
    ]


@pytest.mark.parametrize("case", sig_agg_error_vectors())
def test_sig_agg_error_vectors(case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP327's sig_agg_vectors.json."""
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


# The bindings oracle, issue #1048: every test below cross-validates
# btclib's answer against `libsecp256k1_musig`, reusing the vectors and
# the helpers already loaded above rather than a second copy of either.


@needs_bindings
@pytest.mark.parametrize("pub_keys, expected", key_agg_valid_vectors())
def test_key_agg_matches_bindings(pub_keys: list[bytes], expected: bytes) -> None:
    """key_agg answers the same Q as musig_pubkey_agg, byte for byte."""
    cache = libsecp256k1_musig.KeyAggCache(pub_keys)
    assert cache.agg_pubkey == expected
    assert musig2.key_agg(pub_keys).x_only_pub_key == cache.agg_pubkey


def tweak_pub_keys_and_tweaks_vectors() -> list[Any]:
    """One (pub_keys, tweaks, is_xonly) per tweak_vectors.json valid case."""
    return [
        pytest.param(
            [_TW_PUB_KEYS[i] for i in case["key_indices"]],
            [_TW_TWEAKS[i] for i in case["tweak_indices"]],
            case["is_xonly"],
            id=vector_id(index, case["comment"]),
        )
        for index, case in enumerate(_TWEAK["valid_test_cases"])
    ]


@needs_bindings
@pytest.mark.parametrize(
    "pub_keys, tweaks, is_xonly", tweak_pub_keys_and_tweaks_vectors()
)
def test_apply_tweak_matches_bindings(
    pub_keys: list[bytes], tweaks: list[bytes], is_xonly: list[bool]
) -> None:
    """apply_tweak answers the same Q as the matching *_tweak_add call.

    Applied one tweak at a time, over the same sequence key_agg_and_tweak
    would run, so this is that entry point's oracle as well as
    apply_tweak's own: there is no separate C call to aggregate and tweak
    in one step, `musig.KeyAggCache` accumulating both the same way
    `KeyAggContext` does.
    """
    ctx = musig2.key_agg(pub_keys)
    cache = libsecp256k1_musig.KeyAggCache(pub_keys)
    assert ctx.x_only_pub_key == cache.agg_pubkey
    for tweak, xonly in zip(tweaks, is_xonly, strict=True):
        ctx = musig2.apply_tweak(ctx, tweak, xonly)
        tweak_add = cache.pubkey_xonly_tweak_add if xonly else cache.pubkey_ec_tweak_add
        assert tweak_add(tweak) == bytes_from_point(ctx.Q, secp256k1)


@needs_bindings
@pytest.mark.parametrize("pub_nonces, expected", nonce_agg_valid_vectors())
def test_nonce_agg_matches_bindings(pub_nonces: list[bytes], expected: bytes) -> None:
    """nonce_agg answers the same 66-byte aggnonce as musig_nonce_agg."""
    assert libsecp256k1_musig.nonce_agg(pub_nonces) == expected
    assert musig2.nonce_agg(pub_nonces) == expected


def _msg32_gated(cases: list[dict[str, Any]], msgs: list[bytes]) -> list[Any]:
    """One param per case, `pytest.mark.skip` where its message is not 32 bytes.

    `musig_nonce_process` takes a fixed-size `msg32`: a case whose message
    is not exactly 32 bytes cannot reach the C call this module's tests
    make, and is skipped by this predicate rather than left out of the
    parameter list -- the module docstring's "gate" paragraph says why.
    """
    params = []
    for index, case in enumerate(cases):
        msg = msgs[case["msg_index"]]
        marks = (
            pytest.mark.skip(
                reason=(
                    "musig_nonce_process takes a fixed 32-byte msg32; this "
                    f"vector's message is {len(msg)} bytes"
                )
            )
            if len(msg) != 32
            else ()
        )
        params.append(
            pytest.param(case, marks=marks, id=vector_id(index, case.get("comment")))
        )
    return params


@needs_bindings
@pytest.mark.parametrize(
    "case", _msg32_gated(_SIGN_VERIFY["valid_test_cases"], _SV_MSGS)
)
def test_sign_verified_by_bindings(case: dict[str, Any]) -> None:
    """musig_partial_sig_verify accepts the partial signature sign produces.

    What is crossed into the bindings is `sign`'s own return value, not
    the vector's pinned `expected` -- that equality is already
    `test_sign_verify_valid_vectors`'s, and checking it again here would
    let this test pass on the vector's word instead of on `sign`'s.
    """
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_SV_PUB_NONCES[i] for i in case["nonce_indices"]]
    agg_nonce = _SV_AGG_NONCES[case["aggnonce_index"]]
    msg = _SV_MSGS[case["msg_index"]]
    signer = case["signer_index"]

    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, [], [], msg)
    # a copy: signing consumes the secnonce, and every valid case in this
    # file signs with the vector file's one secnonce, index 0, exactly as
    # test_sign_verify_valid_vectors does
    sig = musig2.sign(bytearray(_SV_SEC_NONCES[0]), _SV_SK, session_ctx)

    cache = libsecp256k1_musig.KeyAggCache(pub_keys)
    session = libsecp256k1_musig.Session(agg_nonce, msg, cache)
    assert session.partial_sig_verify(sig, pub_nonces[signer], pub_keys[signer], cache)


@needs_bindings
@pytest.mark.parametrize(
    "case", _msg32_gated(_SIGN_VERIFY["verify_fail_test_cases"], _SV_MSGS)
)
def test_partial_sig_verify_matches_bindings(case: dict[str, Any]) -> None:
    """partial_sig_verify and musig_partial_sig_verify answer the same verdict.

    Every case here is one BIP327 says fails: what the bindings are
    checked against is not a hardcoded False but their own verdict, so
    agreement is what the test asks rather than the vector's own number a
    second time.
    """
    pub_keys = [_SV_PUB_KEYS[i] for i in case["key_indices"]]
    pub_nonces = [_SV_PUB_NONCES[i] for i in case["nonce_indices"]]
    msg = _SV_MSGS[case["msg_index"]]
    signer = case["signer_index"]
    psig = bytes.fromhex(case["sig"])

    btclib_verdict = musig2.partial_sig_verify(
        psig, pub_nonces, pub_keys, [], [], msg, signer
    )
    cache = libsecp256k1_musig.KeyAggCache(pub_keys)
    agg_nonce = libsecp256k1_musig.nonce_agg(pub_nonces)
    session = libsecp256k1_musig.Session(agg_nonce, msg, cache)
    try:
        bindings_verdict = session.partial_sig_verify(
            psig, pub_nonces[signer], pub_keys[signer], cache
        )
    except ValueError:
        # "Signature exceeds group size": s >= n does not parse, so
        # musig_partial_sig_verify is never reached -- the bindings' own
        # `musig.py` module docstring's "a parse failure ... tells this
        # package nothing" applies, and a refusal to parse is the same
        # refusal partial_sig_verify_'s own `s >= secp256k1.n` check
        # answers
        bindings_verdict = False
    assert btclib_verdict == bindings_verdict


@needs_bindings
@pytest.mark.parametrize("case", sig_agg_valid_vectors())
def test_partial_sig_agg_matches_bindings(case: dict[str, Any]) -> None:
    """partial_sig_agg answers the same signature as musig_partial_sig_agg."""
    pub_nonces = [_SA_PUB_NONCES[i] for i in case["nonce_indices"]]
    pub_keys = [_SA_PUB_KEYS[i] for i in case["key_indices"]]
    tweaks = [_SA_TWEAKS[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    psigs = [_SA_PSIGS[i] for i in case["psig_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])

    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, tweaks, is_xonly, _SA_MSG)
    sig = musig2.partial_sig_agg(psigs, session_ctx)

    cache = libsecp256k1_musig.KeyAggCache(pub_keys)
    for tweak, xonly in zip(tweaks, is_xonly, strict=True):
        (cache.pubkey_xonly_tweak_add if xonly else cache.pubkey_ec_tweak_add)(tweak)
    session = libsecp256k1_musig.Session(
        libsecp256k1_musig.nonce_agg(pub_nonces), _SA_MSG, cache
    )
    assert session.partial_sig_agg(psigs) == sig.serialize()


# btclib's own tests, past the vectors: the whole interactive protocol,
# once through, over a message that is not 32 bytes -- which is the
# precondition issue #190 names, BIP327 signing a message of any size and
# the bindings taking none but a 32-byte one (issue #169)
_SK_1 = "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
_SK_2 = "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9"
_MSG = b"a message the two signers agree on, and not of 32 bytes"


@pytest.mark.parametrize(
    "tweaks, is_xonly",
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
    """Run a full two-signer session over a message that is not 32 bytes."""
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


def test_adapt_and_extract_adaptor_round_trip() -> None:
    """A pre-signature does not verify; adapt and extract_adaptor invert.

    No vector file covers adaptor signatures, so this is the round trip
    the module docstring calls the floor: `partial_sig_agg_adaptor` on a
    session carrying an adaptor answers a `PreSignature` that fails
    `ssa.verify_`; `adapt` with the secret behind it answers an `ssa.Sig`
    that passes `ssa.assert_as_valid_`; and `extract_adaptor` on that
    pair answers exactly the secret `adapt` consumed.

    Both parities of the final nonce R are exercised in the same run,
    fresh keys and adaptor each time, rather than pinned offline for one
    parity and pragma'd for the other as `ssa_test.test_musig1` pins
    randomness against the coverage gate: `adapt` and `extract_adaptor`
    each negate on the odd parity, which is exactly where a sign error
    would hide, and this is the test the issue asks be strong enough to
    catch one.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    pub_keys = musig2.key_sort([pk_1, pk_2])
    agg_pk = musig2.key_agg(pub_keys).x_only_pub_key
    sk_of = {pk_1: _SK_1, pk_2: _SK_2}

    parities_seen: set[int] = set()
    for _ in range(64):
        t = 1 + secrets.randbelow(secp256k1.n - 1)
        adaptor = bytes_from_point(mult(t, ec=secp256k1), secp256k1)

        sec_nonce_of = {}
        pub_nonce_of = {}
        for pk, sk in ((pk_1, _SK_1), (pk_2, _SK_2)):
            sec_nonce_of[pk], pub_nonce_of[pk] = musig2.nonce_gen(sk, pk, agg_pk, _MSG)
        agg_nonce = musig2.nonce_agg([pub_nonce_of[pk] for pk in pub_keys])
        session_ctx = musig2.SessionContext(agg_nonce, pub_keys, [], [], _MSG, adaptor)
        parities_seen.add(musig2.session_values(session_ctx).R[1] % 2)

        psigs = [
            musig2.sign(sec_nonce_of[pk], sk_of[pk], session_ctx) for pk in pub_keys
        ]
        pre_sig = musig2.partial_sig_agg_adaptor(psigs, session_ctx)
        assert not ssa.verify_(_MSG, agg_pk, ssa.Sig(pre_sig.r, pre_sig.s, secp256k1))

        sig = musig2.adapt(pre_sig, t, session_ctx)
        ssa.assert_as_valid_(_MSG, agg_pk, sig)

        extracted = musig2.extract_adaptor(sig, pre_sig, session_ctx)
        assert extracted == t.to_bytes(32, "big")

    assert parities_seen == {0, 1}


def test_a_pre_signature_needs_the_matching_adaptor() -> None:
    """Verify adapt with the wrong secret answers a signature that fails."""
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    agg_nonce = musig2.nonce_agg([pub_nonce])
    t = 1 + secrets.randbelow(secp256k1.n - 1)
    adaptor = bytes_from_point(mult(t, ec=secp256k1), secp256k1)
    session_ctx = musig2.SessionContext(agg_nonce, [pk_1], [], [], _MSG, adaptor)
    psig = musig2.sign(sec_nonce, _SK_1, session_ctx)
    pre_sig = musig2.partial_sig_agg_adaptor([psig], session_ctx)

    agg_pk = musig2.key_agg([pk_1]).x_only_pub_key
    wrong_t = 1 + secrets.randbelow(secp256k1.n - 1)
    sig = musig2.adapt(pre_sig, wrong_t, session_ctx)
    assert not ssa.verify_(_MSG, agg_pk, sig)


def test_partial_sig_agg_and_its_adaptor_twin_refuse_each_others_sessions() -> None:
    """Verify each of the two aggregators refuses the other's session.

    `partial_sig_agg` on a session that carries an adaptor would answer
    a sum still missing the adaptor's secret; `partial_sig_agg_adaptor`
    on a session with no adaptor would answer a `PreSignature` for a sum
    that already is a valid `ssa.Sig`. Both are refused rather than
    silently answered, since the return type says which is which and
    the session is what a caller might get wrong.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce_plain, pub_nonce_plain = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    plain_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce_plain]), [pk_1], [], [], _MSG
    )
    psig_plain = musig2.sign(sec_nonce_plain, _SK_1, plain_ctx)
    with pytest.raises(BTClibValueError, match="call partial_sig_agg instead"):
        musig2.partial_sig_agg_adaptor([psig_plain], plain_ctx)

    sec_nonce_adp, pub_nonce_adp = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    t = 1 + secrets.randbelow(secp256k1.n - 1)
    adaptor = bytes_from_point(mult(t, ec=secp256k1), secp256k1)
    adaptor_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce_adp]), [pk_1], [], [], _MSG, adaptor
    )
    psig_adp = musig2.sign(sec_nonce_adp, _SK_1, adaptor_ctx)
    with pytest.raises(BTClibValueError, match="call partial_sig_agg_adaptor instead"):
        musig2.partial_sig_agg([psig_adp], adaptor_ctx)


def test_adaptor_must_be_a_valid_point() -> None:
    """Verify a malformed adaptor is InvalidContributionError, not a crash.

    The all-zero placeholder is what `_cpoint_ext` reads as infinity for
    an aggregate nonce; the adaptor point is parsed with the plain
    `_cpoint` instead, which refuses it -- a public adaptor, unlike a
    nonce half, is never the infinity point.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    del sec_nonce
    agg_nonce = musig2.nonce_agg([pub_nonce])
    session_ctx = musig2.SessionContext(agg_nonce, [pk_1], [], [], _MSG, bytes(33))
    with pytest.raises(InvalidContributionError) as exc_info:
        musig2.session_values(session_ctx)
    assert exc_info.value.signer is None
    assert exc_info.value.contrib == "adaptor"


def test_sec_nonce_signs_once() -> None:
    """Verify signing zeroes the secnonce, so a second sign raises."""
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
    """Verify sign refuses a secnonce whose second scalar is zero."""
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


def test_sec_nonce_second_half_at_the_bottom_of_its_range() -> None:
    """1 is a scalar sign may use, where the test above has it refuse 0.

    A bound and not a zero test, which is the difference a range checked
    at one value only cannot say. The partial signature this makes does
    not verify -- the pubnonce the session holds is the one the generated
    scalar produced, not this one -- and that is deliberately not what is
    asserted: what is, is that the scalar was accepted.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    sec_nonce[32:64] = (1).to_bytes(32, "big")
    session_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce]), [pk_1], [], [], _MSG
    )
    assert len(musig2.sign(sec_nonce, _SK_1, session_ctx)) == 32


def test_sec_nonce_of_another_key() -> None:
    """Verify sign refuses a secnonce generated for another key."""
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    session_ctx = musig2.SessionContext(
        musig2.nonce_agg([pub_nonce]), [pk_1, pk_2], [], [], _MSG
    )
    with pytest.raises(BTClibValueError, match="does not match nonce_gen argument"):
        musig2.sign(sec_nonce, _SK_2, session_ctx)


def test_session_context_normalizes() -> None:
    """Verify a SessionContext built from hex equals one from bytes."""
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    del sec_nonce
    agg_nonce = musig2.nonce_agg([pub_nonce])
    from_octets = musig2.SessionContext(
        agg_nonce.hex(), [pk_1.hex()], [], [], _MSG.hex()
    )
    assert from_octets == musig2.SessionContext(agg_nonce, [pk_1], [], [], _MSG)


def test_session_values_cache_is_invisible_to_equality() -> None:
    """A populated `session_values` cache must not perturb equality.

    `session_values` memoizes its answer as `_values` in
    `SessionContext.__dict__`, outside the five fields the frozen
    dataclass declares -- `__eq__` and `__hash__` are generated from
    those fields alone, so a context whose cache has been populated by
    signing must stay equal, and equally hashing, to an untouched twin
    built from the same arguments, and the twin's own cache must stay
    unpopulated: comparing two contexts does not itself derive one.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    agg_nonce = musig2.nonce_agg([pub_nonce])
    session_ctx = musig2.SessionContext(agg_nonce, [pk_1], [], [], _MSG)
    twin = musig2.SessionContext(agg_nonce, [pk_1], [], [], _MSG)
    hash_before = hash(session_ctx)
    assert session_ctx == twin
    assert hash_before == hash(twin)

    musig2.sign(sec_nonce, _SK_1, session_ctx)  # populates the cache
    assert "_values" in session_ctx.__dict__
    assert "_values" not in twin.__dict__

    assert session_ctx == twin
    assert hash(session_ctx) == hash_before == hash(twin)


def test_key_agg_coeff_cache_is_invisible_to_equality() -> None:
    """A populated key-aggregation-coefficient cache must not perturb equality.

    Issue #1069's `L`, `second` and `pub_keys_set` are folded into the
    same `_values` `test_session_values_cache_is_invisible_to_equality`
    above already pins, rather than a second cached field on
    `SessionContext` -- so this is the same invariant, checked with two
    signers so that `second` is a real key rather than the one-signer
    placeholder, and populated through `partial_sig_verify_`,
    `_session_key_agg_coeff`'s other caller.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    pub_keys = musig2.key_sort([pk_1, pk_2])
    sk_of = {pk_1: _SK_1, pk_2: _SK_2}
    nonces = {pk: musig2.nonce_gen(sk_of[pk], pk, None, _MSG) for pk in pub_keys}
    agg_nonce = musig2.nonce_agg([nonces[pk][1] for pk in pub_keys])
    session_ctx = musig2.SessionContext(agg_nonce, pub_keys, [], [], _MSG)
    twin = musig2.SessionContext(agg_nonce, pub_keys, [], [], _MSG)
    hash_before = hash(session_ctx)

    signer = pub_keys[0]
    psig = musig2.sign(nonces[signer][0], sk_of[signer], session_ctx)
    assert musig2.partial_sig_verify_(psig, nonces[signer][1], signer, twin)

    assert session_ctx == twin
    assert hash(session_ctx) == hash_before == hash(twin)


def test_tweaks_and_is_xonly_pair_up() -> None:
    """Verify tweaks and is_xonly of unequal lengths are refused."""
    pk_1 = musig2.individual_pub_key(_SK_1)
    with pytest.raises(BTClibValueError, match="must have the same length"):
        musig2.key_agg_and_tweak([pk_1], [bytes(32)], [])
    with pytest.raises(BTClibValueError, match="must have the same length"):
        musig2.SessionContext(bytes(66), [pk_1], [bytes(32)], [], _MSG)


@pytest.mark.parametrize("not_a_flag", ["false", "", 0, 1, None])
def test_the_kind_of_a_tweak_is_a_bool(not_a_flag: Any) -> None:
    """Verify a kind that is not a bool is refused wherever one is taken.

    Not read for its truth: `"false"` is true, and what the flag decides
    is which of two aggregate keys the group signs under, so an odd-y key
    tweaked by a string would answer a key the signers passing `False`
    never see. The three doors are the one that reads it and the two that
    carry a sequence of them.
    """
    pk_1 = musig2.individual_pub_key(_SK_1)
    key_agg_ctx = musig2.key_agg([pk_1])
    with pytest.raises(BTClibTypeError, match="invalid is_xonly type"):
        musig2.apply_tweak(key_agg_ctx, bytes(32), not_a_flag)
    with pytest.raises(BTClibTypeError, match="invalid is_xonly type"):
        musig2.key_agg_and_tweak([pk_1], [bytes(32)], [not_a_flag])
    with pytest.raises(BTClibTypeError, match="invalid is_xonly type"):
        musig2.SessionContext(bytes(66), [pk_1], [bytes(32)], [not_a_flag], _MSG)


def test_the_two_kinds_of_tweak_differ_on_an_odd_key() -> None:
    """Verify the flag is what the refusal above is protecting.

    An aggregate key with an odd y is the case where the two kinds part
    company: the x-only one negates it first. A key with an even y
    tweaks the same either way, which is why the refusal cannot be left
    to the arithmetic to notice.
    """
    key_agg_ctx = musig2.key_agg([musig2.individual_pub_key(_SK_1)])
    assert key_agg_ctx.Q[1] % 2
    plain = musig2.apply_tweak(key_agg_ctx, bytes(32), False)
    x_only = musig2.apply_tweak(key_agg_ctx, bytes(32), True)
    assert plain != x_only


def test_tweak_size() -> None:
    """Verify a tweak that is not 32 bytes is refused."""
    pk_1 = musig2.individual_pub_key(_SK_1)
    key_agg_ctx = musig2.key_agg([pk_1])
    with pytest.raises(BTClibValueError, match="must be a 32-byte array"):
        musig2.apply_tweak(key_agg_ctx, bytes(31), False)


def test_a_nonce_per_key() -> None:
    """Verify partial_sig_verify refuses fewer nonces than keys."""
    pk_1 = musig2.individual_pub_key(_SK_1)
    pk_2 = musig2.individual_pub_key(_SK_2)
    sec_nonce, pub_nonce = musig2.nonce_gen(_SK_1, pk_1, None, _MSG)
    del sec_nonce
    with pytest.raises(BTClibValueError, match="must have the same length"):
        musig2.partial_sig_verify(bytes(32), [pub_nonce], [pk_1, pk_2], [], [], _MSG, 0)


def test_invalid_contribution_names_the_party() -> None:
    """Verify InvalidContributionError's message names the culprit."""
    exc = InvalidContributionError(2, "pubkey")
    assert exc.signer == 2
    assert exc.contrib == "pubkey"
    assert str(exc) == "invalid pubkey from signer 2"
    # the aggregator has no key, so it has no index either
    assert str(InvalidContributionError(None, "aggnonce")) == (
        "invalid aggnonce from the aggregator"
    )


def test_a_tweak_needs_a_flag_and_a_flag_needs_a_tweak() -> None:
    """The two arrays are one list of pairs, so their lengths are equal.

    Not "no more flags than tweaks", which is what the check reads as
    once it is an ordering: a flag left over is a tweak nobody named, and
    a tweak left over would be applied with whichever flag the shorter
    array ran out of.
    """
    pub_keys = _TW_PUB_KEYS
    tweak = bytes(range(1, 33))
    err_msg = "must have the same length"
    with pytest.raises(BTClibValueError, match=err_msg):
        musig2.key_agg_and_tweak(pub_keys, [tweak, tweak], [True])
    with pytest.raises(BTClibValueError, match=err_msg):
        musig2.key_agg_and_tweak(pub_keys, [tweak], [True, False])
    # and the pair that is a pair
    assert musig2.key_agg_and_tweak(pub_keys, [tweak], [True]).Q
