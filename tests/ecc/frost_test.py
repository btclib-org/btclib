# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.frost` module.

The vectors are BIP445's own, all six signing-algorithm files of
`bitcoin/bips#2070`'s `bip-0445/python/vectors/`, vendored under
`tests/ecc/_data/bip445/`; `tests/_data/README.md` pins the revision.
Every case of every file is exercised, the error cases included, and an
error case is checked against the exception the file names -- which
party misbehaved and how, or the message of a plain value error.

There is no oracle to cross-validate against, unlike `musig2_test.py`'s
own `btclib_secp256k1.musig`: BIP445 has no C implementation this
library wraps, so every function here is the Python arithmetic and the
vectors are its only authority. `ValidateThresholdInfo` ships no
vector file of its own, `tests/_data/README.md` and BIP445's own
`test_vectors_summary.md` giving the same reason -- it checks key
material a key generation protocol produced, and this module produces
none -- so its tests below build `ThresholdInfo` from the vectors' own
already-consistent key material instead, tampering with one share at a
time to reach each refusal.
"""

from typing import Any

import pytest

from btclib.curves import bytes_from_point, mult
from btclib.ecc import frost, ssa
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    InvalidContributionError,
)
from tests import load, vector_id

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
    """Check the raised exception against what the vector expects.

    BIP445's own JSON schema, not BIP327's: `"type"` spells
    `"InvalidContributionError"` and `"ValueError"`, capitalized, and the
    signer field is `"signer_index"` rather than `"signer"` --
    `tests/ecc/musig2_test.py`'s `assert_error` reads a different shape
    because BIP327's vectors are written to a different one.
    """
    if error["type"] == "InvalidContributionError":
        assert isinstance(exc, InvalidContributionError)
        assert exc.signer == error["signer_index"]
        assert exc.contrib == error["contrib"]
    else:
        assert error["type"] == "ValueError"
        assert isinstance(exc, BTClibValueError)
        # the message, byte for byte: the vectors compare BIP445's own
        # reference strings this way, and frost.py copies them verbatim
        assert str(exc) == error["message"]


# --------------------------------------------------------------------
# nonce_gen_vectors.json
# --------------------------------------------------------------------


def nonce_gen_vectors() -> list[Any]:
    """One param per case of nonce_gen_vectors.json."""
    test_data = load("ecc", "_data", "bip445", "nonce_gen_vectors.json")
    return [
        pytest.param(case, id=vector_id(index, case["comment"]))
        for index, case in enumerate(test_data["valid_tests"])
    ]


@pytest.mark.parametrize("case", nonce_gen_vectors())
def test_nonce_gen_vectors(case: dict[str, Any]) -> None:
    """Reproduce BIP445's nonce_gen_vectors.json."""

    def value(key: str) -> bytes | None:
        return None if case[key] is None else bytes.fromhex(case[key])

    sec_nonce, pub_nonce = frost.nonce_gen_(
        bytes.fromhex(case["rand"]),
        value("secshare"),
        value("pubshare"),
        value("thresh_pk_xonly"),
        value("msg"),
        value("extra_in"),
    )
    expected_sec_nonce, expected_pub_nonce = case["expected"]
    assert bytes(sec_nonce) == bytes.fromhex(expected_sec_nonce)
    assert pub_nonce == bytes.fromhex(expected_pub_nonce)


def test_nonce_gen_draws_fresh_randomness() -> None:
    """`nonce_gen` is `nonce_gen_` with `secrets.token_bytes` for `rand_`."""
    sec_nonce, pub_nonce = frost.nonce_gen()
    assert len(sec_nonce) == 64
    assert len(pub_nonce) == 66
    assert _pub_nonce_of(bytes(sec_nonce)) == pub_nonce
    # two calls draw two different secnonces, with overwhelming probability
    sec_nonce_2, _ = frost.nonce_gen()
    assert bytes(sec_nonce) != bytes(sec_nonce_2)


# --------------------------------------------------------------------
# nonce_agg_vectors.json
# --------------------------------------------------------------------

_NONCE_AGG = load("ecc", "_data", "bip445", "nonce_agg_vectors.json")


def nonce_agg_valid_vectors() -> list[Any]:
    """One param per valid case of nonce_agg_vectors.json."""
    pub_nonces = _hex_all(_NONCE_AGG["pubnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pubnonce_indices"]],
            bytes.fromhex(case["expected"]),
            id=vector_id(index, case.get("comment")),
        )
        for index, case in enumerate(_NONCE_AGG["valid_tests"])
    ]


@pytest.mark.parametrize("pub_nonces, expected", nonce_agg_valid_vectors())
def test_nonce_agg_vectors(pub_nonces: list[bytes], expected: bytes) -> None:
    """Reproduce the valid cases of BIP445's nonce_agg_vectors.json."""
    assert frost.nonce_agg(pub_nonces) == expected


def nonce_agg_error_vectors() -> list[Any]:
    """One param per error case of nonce_agg_vectors.json."""
    pub_nonces = _hex_all(_NONCE_AGG["pubnonces"])
    return [
        pytest.param(
            [pub_nonces[i] for i in case["pubnonce_indices"]],
            case["error"],
            id=vector_id(index, case.get("comment")),
        )
        for index, case in enumerate(_NONCE_AGG["error_tests"])
    ]


@pytest.mark.parametrize("pub_nonces, error", nonce_agg_error_vectors())
def test_nonce_agg_error_vectors(pub_nonces: list[bytes], error: Any) -> None:
    """Reproduce the error cases of BIP445's nonce_agg_vectors.json."""
    with pytest.raises(_ERRORS) as excinfo:
        frost.nonce_agg(pub_nonces)
    assert_error(error, excinfo.value)


# --------------------------------------------------------------------
# sign_verify_vectors.json
# --------------------------------------------------------------------

_SIGN_VERIFY = load("ecc", "_data", "bip445", "sign_verify_vectors.json")


def _group_params(group: dict[str, Any], cases_key: str) -> list[Any]:
    return [
        pytest.param(group, case, id=vector_id(index, case.get("comment")))
        for index, case in enumerate(group[cases_key])
    ]


def _all_group_params(data: dict[str, Any], cases_key: str) -> list[Any]:
    params = []
    for group in data["test_groups"]:
        params.extend(_group_params(group, cases_key))
    return params


def test_sign_verify_vectors_consistency() -> None:
    """Each group's own cross-reference: pubshares match secshares."""
    for group in _SIGN_VERIFY["test_groups"]:
        n = group["n"]
        pub_shares = _hex_all(group["pubshares"])[:n]
        sec_shares = _hex_all(group["secshares"])[:n]
        for pub_share, sec_share in zip(pub_shares, sec_shares, strict=True):
            d = int.from_bytes(sec_share, "big")
            assert pub_share == bytes_from_point(mult(d))


@pytest.mark.parametrize("group, case", _all_group_params(_SIGN_VERIFY, "valid_tests"))
def test_sign_verify_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])

    ids = case["ids"]
    valid_pub_shares = (
        None
        if case["pubshare_indices"] is None
        else [pub_shares[i] for i in case["pubshare_indices"]]
    )
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    assert frost.nonce_agg(pub_nonces_case) == agg_nonce
    msg = bytes.fromhex(case["msg"])
    my_id = case["my_id"]
    signer_index = ids.index(my_id)
    sec_share = sec_shares[case["secshare_index"]]
    expected = bytes.fromhex(case["expected"])

    session_ctx = frost.SessionContext(
        n, t, ids, valid_pub_shares, thresh_pk, agg_nonce, [], [], msg
    )
    # a copy: signing consumes the secnonce, and the vectors reuse it
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])
    assert frost.sign(sec_nonce, sec_share, my_id, session_ctx) == expected
    if valid_pub_shares is not None:
        assert frost.partial_sig_verify(
            expected,
            pub_nonces_case,
            n,
            t,
            ids,
            valid_pub_shares,
            thresh_pk,
            [],
            [],
            msg,
            signer_index,
        )


@pytest.mark.parametrize(
    "group, case", _all_group_params(_SIGN_VERIFY, "sign_error_tests")
)
def test_sign_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the sign error cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    msg = bytes.fromhex(case["msg"])
    my_id = case["my_id"]
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])
    sec_share = sec_shares[case["secshare_index"]]

    with pytest.raises(_ERRORS) as excinfo:
        session_ctx = frost.SessionContext(
            n, t, ids, pub_shares_case, thresh_pk, agg_nonce, [], [], msg
        )
        frost.sign(sec_nonce, sec_share, my_id, session_ctx)
    assert_error(case["error"], excinfo.value)


@pytest.mark.parametrize(
    "group, case", _all_group_params(_SIGN_VERIFY, "verify_fail_tests")
)
def test_verify_fail_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the verify fail cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])

    psig = bytes.fromhex(case["psig"])
    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    msg = bytes.fromhex(case["msg"])
    signer_index = case["signer_index"]
    assert not frost.partial_sig_verify(
        psig,
        pub_nonces_case,
        n,
        t,
        ids,
        pub_shares_case,
        thresh_pk,
        [],
        [],
        msg,
        signer_index,
    )


@pytest.mark.parametrize(
    "group, case", _all_group_params(_SIGN_VERIFY, "verify_error_tests")
)
def test_verify_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the verify error cases of BIP445's sign_verify_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])

    psig = bytes.fromhex(case["psig"])
    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    msg = bytes.fromhex(case["msg"])
    signer_index = case["signer_index"]
    with pytest.raises(_ERRORS) as excinfo:
        frost.partial_sig_verify(
            psig,
            pub_nonces_case,
            n,
            t,
            ids,
            pub_shares_case,
            thresh_pk,
            [],
            [],
            msg,
            signer_index,
        )
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# tweak_vectors.json
# --------------------------------------------------------------------

_TWEAK = load("ecc", "_data", "bip445", "tweak_vectors.json")


@pytest.mark.parametrize("group, case", _all_group_params(_TWEAK, "valid_tests"))
def test_tweak_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's tweak_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    pub_nonces = _hex_all(group["pubnonces"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    pub_nonces_case = [pub_nonces[i] for i in case["pubnonce_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    assert frost.nonce_agg(pub_nonces_case) == agg_nonce
    msg = bytes.fromhex(case["msg"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    my_id = case["my_id"]
    signer_index = ids.index(my_id)
    sec_share = sec_shares[case["secshare_index"]]
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])
    expected = bytes.fromhex(case["expected"])

    session_ctx = frost.SessionContext(
        n, t, ids, pub_shares_case, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
    )
    assert frost.sign(sec_nonce, sec_share, my_id, session_ctx) == expected
    assert frost.partial_sig_verify(
        expected,
        pub_nonces_case,
        n,
        t,
        ids,
        pub_shares_case,
        thresh_pk,
        tweaks_case,
        is_xonly,
        msg,
        signer_index,
    )


@pytest.mark.parametrize("group, case", _all_group_params(_TWEAK, "error_tests"))
def test_tweak_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP445's tweak_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])
    sec_nonces = _hex_all(group["secnonces"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    msg = bytes.fromhex(case["msg"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    my_id = case["my_id"]
    sec_share = sec_shares[case["secshare_index"]]
    sec_nonce = bytearray(sec_nonces[case["secnonce_index"]])

    with pytest.raises(_ERRORS) as excinfo:
        session_ctx = frost.SessionContext(
            n, t, ids, pub_shares_case, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
        )
        frost.sign(sec_nonce, sec_share, my_id, session_ctx)
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# det_sign_vectors.json
# --------------------------------------------------------------------

_DET_SIGN = load("ecc", "_data", "bip445", "det_sign_vectors.json")


@pytest.mark.parametrize("group, case", _all_group_params(_DET_SIGN, "valid_tests"))
def test_det_sign_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's det_sign_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])

    ids = case["ids"]
    valid_pub_shares = (
        None
        if case["pubshare_indices"] is None
        else [pub_shares[i] for i in case["pubshare_indices"]]
    )
    sec_share = sec_shares[case["secshare_index"]]
    agg_other_nonce = (
        bytes.fromhex(case["aggothernonce"])
        if case["aggothernonce"] is not None
        else None
    )
    tweaks = _hex_all(case["tweaks"])
    is_xonly = case["is_xonly"]
    msg = bytes.fromhex(case["msg"])
    my_id = case["my_id"]
    signer_index = ids.index(my_id)
    aux_rand = bytes.fromhex(case["aux_rand"]) if case["aux_rand"] is not None else None
    expected = _hex_all(case["expected"])

    pub_nonce, psig = frost.deterministic_sign(
        sec_share,
        my_id,
        agg_other_nonce,
        n,
        t,
        ids,
        valid_pub_shares,
        thresh_pk,
        tweaks,
        is_xonly,
        msg,
        aux_rand,
    )
    assert pub_nonce == expected[0]
    assert psig == expected[1]

    agg_nonce = (
        frost.nonce_agg([pub_nonce, agg_other_nonce])
        if agg_other_nonce is not None
        else pub_nonce
    )
    session_ctx = frost.SessionContext(
        n, t, ids, valid_pub_shares, thresh_pk, agg_nonce, tweaks, is_xonly, msg
    )
    # a signer always knows its own public share, even in a session whose
    # public share list is absent, so the self-check runs either way
    own_pub_share = (
        pub_shares[my_id]
        if valid_pub_shares is None
        else valid_pub_shares[signer_index]
    )
    assert frost.partial_sig_verify_(psig, my_id, pub_nonce, own_pub_share, session_ctx)


@pytest.mark.parametrize("group, case", _all_group_params(_DET_SIGN, "error_tests"))
def test_det_sign_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP445's det_sign_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    sec_shares = _hex_all(group["secshares"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    sec_share = sec_shares[case["secshare_index"]]
    agg_other_nonce = (
        bytes.fromhex(case["aggothernonce"])
        if case["aggothernonce"] is not None
        else None
    )
    tweaks = _hex_all(case["tweaks"])
    is_xonly = case["is_xonly"]
    msg = bytes.fromhex(case["msg"])
    my_id = case["my_id"]
    aux_rand = bytes.fromhex(case["aux_rand"]) if case["aux_rand"] is not None else None

    with pytest.raises(_ERRORS) as excinfo:
        frost.deterministic_sign(
            sec_share,
            my_id,
            agg_other_nonce,
            n,
            t,
            ids,
            pub_shares_case,
            thresh_pk,
            tweaks,
            is_xonly,
            msg,
            aux_rand,
        )
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# sig_agg_vectors.json
# --------------------------------------------------------------------

_SIG_AGG = load("ecc", "_data", "bip445", "sig_agg_vectors.json")


@pytest.mark.parametrize("group, case", _all_group_params(_SIG_AGG, "valid_tests"))
def test_sig_agg_valid_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the valid cases of BIP445's sig_agg_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    valid_pub_shares = (
        None
        if case["pubshare_indices"] is None
        else [pub_shares[i] for i in case["pubshare_indices"]]
    )
    agg_nonce = bytes.fromhex(case["aggnonce"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    psigs = _hex_all(case["psigs"])
    msg = bytes.fromhex(case["msg"])
    expected = bytes.fromhex(case["expected"])

    session_ctx = frost.SessionContext(
        n, t, ids, valid_pub_shares, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
    )
    sig = frost.partial_sig_agg(psigs, session_ctx)
    assert sig.serialize() == expected
    # the aggregate is an ordinary BIP340 signature, and btclib's own
    # verifier is what says so
    tweaked_pk = frost.thresh_pubkey_and_tweak(
        thresh_pk, tweaks_case, is_xonly
    ).x_only_pub_key
    assert ssa.verify_(msg, tweaked_pk, sig)


@pytest.mark.parametrize("group, case", _all_group_params(_SIG_AGG, "error_tests"))
def test_sig_agg_error_vectors(group: dict[str, Any], case: dict[str, Any]) -> None:
    """Reproduce the error cases of BIP445's sig_agg_vectors.json."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])
    tweaks = _hex_all(group["tweaks"])

    ids = case["ids"]
    pub_shares_case = [pub_shares[i] for i in case["pubshare_indices"]]
    agg_nonce = bytes.fromhex(case["aggnonce"])
    tweaks_case = [tweaks[i] for i in case["tweak_indices"]]
    is_xonly = case["is_xonly"]
    psigs = _hex_all(case["psigs"])
    msg = bytes.fromhex(case["msg"])

    session_ctx = frost.SessionContext(
        n, t, ids, pub_shares_case, thresh_pk, agg_nonce, tweaks_case, is_xonly, msg
    )
    with pytest.raises(_ERRORS) as excinfo:
        frost.partial_sig_agg(psigs, session_ctx)
    assert_error(case["error"], excinfo.value)


# --------------------------------------------------------------------
# ValidateThresholdInfo: no vector file, per test_vectors_summary.md and
# tests/_data/README.md. Built from the sign_verify_vectors groups' own
# already-consistent key material, one refusal reached at a time.
# --------------------------------------------------------------------


def _threshold_info_groups() -> list[Any]:
    return [
        pytest.param(group, id=group["tg_id"]) for group in _SIGN_VERIFY["test_groups"]
    ]


@pytest.mark.parametrize("group", _threshold_info_groups())
def test_validate_threshold_info_accepts_consistent_key_material(
    group: dict[str, Any],
) -> None:
    """Every group's own full pubshare list validates against its own key."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, pub_shares))


@pytest.mark.parametrize("group", _threshold_info_groups())
def test_validate_threshold_info_accepts_shares_left_unknown(
    group: dict[str, Any],
) -> None:
    """A `None` entry beyond `t` known shares does not stop validation."""
    n, t = group["n"], group["t"]
    if n <= t:
        pytest.skip("group has no share to leave unknown beyond t")
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares: list[bytes | None] = list(_hex_all(group["pubshares"])[:n])
    pub_shares[-1] = None
    frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, pub_shares))


@pytest.mark.parametrize("group", _threshold_info_groups())
def test_validate_threshold_info_refuses_a_share_off_the_polynomial(
    group: dict[str, Any],
) -> None:
    """A share swapped in from another group breaks the polynomial fit."""
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares: list[bytes | None] = list(_hex_all(group["pubshares"])[:n])
    if n <= t:
        pytest.skip("no share beyond the base t to tamper with")
    foreign_group = next(g for g in _SIGN_VERIFY["test_groups"] if g is not group)
    pub_shares[-1] = bytes.fromhex(foreign_group["pubshares"][0])
    with pytest.raises(BTClibValueError, match="do not lie on a single polynomial"):
        frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, pub_shares))


def test_validate_threshold_info_refuses_a_key_the_shares_do_not_match() -> None:
    """A threshold public key that is not the shares' own constant term."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    pub_shares = _hex_all(group["pubshares"])[:n]
    other_thresh_pk = bytes.fromhex(_SIGN_VERIFY["test_groups"][1]["thresh_pk"])
    with pytest.raises(BTClibValueError, match="do not match"):
        frost.validate_threshold_info(
            frost.ThresholdInfo(t, other_thresh_pk, pub_shares)
        )


def test_validate_threshold_info_refuses_an_invalid_threshold_public_key() -> None:
    """A `thresh_pk` that does not decode to a compressed point."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    pub_shares = _hex_all(group["pubshares"])[:n]
    not_a_point = bytes.fromhex("02" + "ff" * 32)
    with pytest.raises(BTClibValueError, match="Invalid threshold public key"):
        frost.validate_threshold_info(frost.ThresholdInfo(t, not_a_point, pub_shares))


def test_validate_threshold_info_refuses_an_invalid_pubshare() -> None:
    """A present pubshare that does not decode to a compressed point."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares: list[bytes | None] = list(_hex_all(group["pubshares"])[:n])
    pub_shares[0] = bytes.fromhex("02" + "ff" * 32)
    with pytest.raises(BTClibValueError, match=r"Invalid pubshare at index 0\."):
        frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, pub_shares))


def test_validate_threshold_info_refuses_fewer_than_t_present_shares() -> None:
    """Fewer than `t` non-`None` entries in `pub_shares`."""
    group = next(g for g in _SIGN_VERIFY["test_groups"] if g["t"] > 1)
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares: list[bytes | None] = list(_hex_all(group["pubshares"])[:n])
    for i in range(1, n):
        pub_shares[i] = None
    with pytest.raises(BTClibValueError, match="At least t pubshares must be present"):
        frost.validate_threshold_info(frost.ThresholdInfo(t, thresh_pk, pub_shares))


def test_validate_threshold_info_refuses_a_threshold_outside_1_to_n() -> None:
    """`t` greater than `n`, `n` being `len(pub_shares)`."""
    group = _SIGN_VERIFY["test_groups"][0]
    n = group["n"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    with pytest.raises(BTClibValueError, match=r"1 <= t <= n"):
        frost.validate_threshold_info(frost.ThresholdInfo(n + 1, thresh_pk, pub_shares))


def test_validate_threshold_info_refuses_more_than_128_participants() -> None:
    """`len(pub_shares)` past the security bound the module docstring gives."""
    group = _SIGN_VERIFY["test_groups"][0]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares: list[bytes | None] = [None] * 129
    with pytest.raises(BTClibValueError, match=r"n <= 128"):
        frost.validate_threshold_info(frost.ThresholdInfo(1, thresh_pk, pub_shares))


# --------------------------------------------------------------------
# Session-parameter refusals no vector reaches: none of the six files
# varies n or t in an error case, or asks pubshares and ids to disagree
# in length, or drives partial_sig_verify's own upfront checks.
# --------------------------------------------------------------------


def test_session_values_refuses_a_threshold_outside_1_to_n() -> None:
    """No vector varies `n` or `t` in an error case; `SessionContext` does."""
    group = _SIGN_VERIFY["test_groups"][0]
    n = group["n"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    session_ctx = frost.SessionContext(
        n, n + 1, [0], None, thresh_pk, bytes(66), [], [], b"msg"
    )
    with pytest.raises(BTClibValueError, match=r"1 <= t <= n"):
        frost.session_values(session_ctx)


def test_session_values_refuses_more_than_128_participants() -> None:
    """`n` past the security bound the module docstring gives."""
    group = _SIGN_VERIFY["test_groups"][0]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    session_ctx = frost.SessionContext(
        129, 1, [0], None, thresh_pk, bytes(66), [], [], b"msg"
    )
    with pytest.raises(BTClibValueError, match=r"n <= 128"):
        frost.session_values(session_ctx)


def test_session_values_refuses_mismatched_pubshares_and_ids_length() -> None:
    """`pub_shares` present and shorter than `ids`."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:1]
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares, thresh_pk, bytes(66), [], [], b"msg"
    )
    with pytest.raises(BTClibValueError, match="same length"):
        frost.session_values(session_ctx)


def test_partial_sig_verify_refuses_mismatched_list_lengths() -> None:
    """`pub_nonces`, `pub_shares` and `ids` of disagreeing lengths."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_nonces = _hex_all(group["pubnonces"])[:2]
    pub_shares = _hex_all(group["pubshares"])[:1]
    with pytest.raises(BTClibValueError, match="same length"):
        frost.partial_sig_verify(
            bytes(32),
            pub_nonces,
            n,
            t,
            [0, 1],
            pub_shares,
            thresh_pk,
            [],
            [],
            b"msg",
            0,
        )


def test_partial_sig_verify_refuses_a_signer_index_out_of_range() -> None:
    """`i` outside `0 <= i < len(ids)`."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_nonces = _hex_all(group["pubnonces"])[:1]
    pub_shares = _hex_all(group["pubshares"])[:1]
    with pytest.raises(BTClibValueError, match="signer index"):
        frost.partial_sig_verify(
            bytes(32),
            pub_nonces,
            n,
            t,
            [0],
            pub_shares,
            thresh_pk,
            [],
            [],
            b"msg",
            1,
        )


# --------------------------------------------------------------------
# TweakContext.plain_pub_key: no vector calls GetPlainPubkey, so this is
# a direct check against the x-only property every tweak vector already
# exercises -- the two are the same point, compressed and x-only.
# --------------------------------------------------------------------


def test_tweak_context_plain_pub_key() -> None:
    """`plain_pub_key` is the compressed point behind `x_only_pub_key`."""
    group = _TWEAK["test_groups"][0]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    tweak_ctx = frost.tweak_ctx_init(thresh_pk)
    assert tweak_ctx.plain_pub_key == thresh_pk
    assert tweak_ctx.plain_pub_key[1:] == tweak_ctx.x_only_pub_key


# --------------------------------------------------------------------
# A secret nonce signs once, `frost.sign`'s own module docstring promise.
# --------------------------------------------------------------------


def test_sec_nonce_signs_once() -> None:
    """Verify signing zeroes the secnonce, so a second sign raises."""
    group = next(g for g in _SIGN_VERIFY["test_groups"] if g["t"] == 1)
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    sec_share = bytes.fromhex(group["secshares"][0])
    sec_nonce, pub_nonce = frost.nonce_gen(sec_share, pub_shares[0])
    session_ctx = frost.SessionContext(
        n, t, [0], pub_shares[:1], thresh_pk, frost.nonce_agg([pub_nonce]), [], [], b"m"
    )
    frost.sign(sec_nonce, sec_share, 0, session_ctx)
    # the bytearray has been zeroed, which is the whole defence
    assert bytes(sec_nonce[:64]) == bytes(64)
    with pytest.raises(BTClibValueError, match="first secnonce value is out of range"):
        frost.sign(sec_nonce, sec_share, 0, session_ctx)


# --------------------------------------------------------------------
# `_assert_octets_sequence`'s guard (issue #1405, `musig2`'s own
# reason): reached from a class `__init__`, so the generic walk in
# `tests/input_validation_test.py` does not drive it -- that walk calls
# module-level functions only, never a constructor.
# --------------------------------------------------------------------


def test_threshold_info_refuses_pub_shares_that_is_not_a_sequence_of_them() -> None:
    """`pub_shares` itself an `Octets`, not a `Sequence` (issue #1405)."""
    with pytest.raises(BTClibTypeError, match="invalid pub_shares type"):
        frost.ThresholdInfo(1, bytes(33), b"\xaa\xbb\xcc\xdd")  # type: ignore[arg-type]


# --------------------------------------------------------------------
# `partial_sig_verify_`'s own two parse failures: unreachable through
# the convenience `partial_sig_verify`, which validates every pubshare
# before this is ever called and aggregates every pubnonce through
# `nonce_agg`, which raises `InvalidContributionError` on a malformed
# one before this function sees it either -- `musig2_test.py`'s own
# "the bindings have no C equivalent" shape, here with no bindings arm
# to reach it from at all. Called directly, as `sign`'s own module
# docstring says a caller may.
# --------------------------------------------------------------------


def test_partial_sig_verify_internal_refuses_a_malformed_pub_nonce() -> None:
    """A `pub_nonce` that does not decode to two compressed points."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    pub_nonces = _hex_all(group["pubnonces"])
    agg_nonce = frost.nonce_agg(pub_nonces[:2])
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares[:2], thresh_pk, agg_nonce, [], [], b"m"
    )
    not_a_point = bytes.fromhex("02" + "ff" * 32) * 2
    assert not frost.partial_sig_verify_(
        bytes(32), 0, not_a_point, pub_shares[0], session_ctx
    )


def test_partial_sig_verify_internal_refuses_a_malformed_pub_share() -> None:
    """A `pub_share` that does not decode to a compressed point."""
    group = _SIGN_VERIFY["test_groups"][0]
    n, t = group["n"], group["t"]
    thresh_pk = bytes.fromhex(group["thresh_pk"])
    pub_shares = _hex_all(group["pubshares"])[:n]
    pub_nonces = _hex_all(group["pubnonces"])
    agg_nonce = frost.nonce_agg(pub_nonces[:2])
    session_ctx = frost.SessionContext(
        n, t, [0, 1], pub_shares[:2], thresh_pk, agg_nonce, [], [], b"m"
    )
    not_a_point = bytes.fromhex("02" + "ff" * 32)
    assert not frost.partial_sig_verify_(
        bytes(32), 0, pub_nonces[0], not_a_point, session_ctx
    )
