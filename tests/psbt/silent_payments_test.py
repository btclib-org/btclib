# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.silent_payments` module, BIP375's roles.

The vectors are BIP375's own `bip375_test_vectors.json`, already vendored
under `tests/psbt/_data/` for `bip375_test.py`, which holds the codec to
them; this module holds the two roles to the same file, and where that one
had to say that seventeen of the invalid psbts are accepted, here **all 22
are refused and all 19 valid ones pass**.

The `checks` field of a case names which of BIP375's four checks it is
about, so each is asserted against the check that should refuse it rather
than against "something raised": a psbt refused for the wrong reason is a
psbt this module got right by accident.

**The k ordering is measured here, not assumed**, because BIP375's prose
and its own vectors disagree and the disagreement is load-bearing. The
prose says to sort the codes of one scan key lexicographically; the
vectors' scripts are the ones output-index order derives, and one case
published as *valid* has its two spend keys in descending order, so the
two readings differ on it. `test_the_k_ordering_is_the_output_index` pins
that, so a revision settling it the other way fails here rather than
passing quietly.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from btclib import silent_payments as sp
from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.ecc import dleq
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt
from btclib.psbt import silent_payments as role
from btclib.script import serialize
from tests import load, vector_id

_VECTORS = load("psbt", "_data", "bip375_test_vectors.json", encoding="utf-8")

# which of BIP375's four checks each invalid case is about, read off the
# description's own prefix: the file groups them that way, and the
# categories are the ones its README lists
_CATEGORIES = ("psbt structure", "ecdh coverage", "input eligibility", "output scripts")


def _params(group: str) -> tuple[list[dict[str, Any]], list[str]]:
    vectors = _VECTORS[group]
    ids = [vector_id(i, v["description"]) for i, v in enumerate(vectors)]
    return vectors, ids


_VALID, _VALID_IDS = _params("valid")
_INVALID, _INVALID_IDS = _params("invalid")


def _category(description: str) -> str:
    """Return which of the four checks a case is about."""
    for category in _CATEGORIES:
        if description.startswith(category):
            return category
    msg = f"vector in no category: {description}"
    raise AssertionError(msg)


@pytest.mark.parametrize("vector", _VALID, ids=_VALID_IDS)
def test_every_valid_psbt_passes_every_check(vector: dict[str, Any]) -> None:
    """The whole file's valid half, both roles applied.

    Including the "in progress" ones, which is the half that says the
    checks know what a psbt under construction looks like: an output whose
    script is not derived yet is not an output whose script is wrong.
    """
    psbt = Psbt.b64decode(vector["psbt"])
    role.assert_as_valid(psbt)
    # and each check on its own, so that a pass is not one check masking
    # another's opinion
    role.assert_shares_as_valid(psbt)
    role.assert_eligibility_as_valid(psbt)
    role.assert_output_scripts_as_valid(psbt)


@pytest.mark.parametrize("vector", _INVALID, ids=_INVALID_IDS)
def test_every_invalid_psbt_is_refused(vector: dict[str, Any]) -> None:
    """All 22, where the codec alone refused five.

    The other seventeen are what this module adds, and each is refused by
    the check its own category names -- `Psbt.parse` and `assert_valid`
    for the structural ones, and one of the three role checks otherwise.
    """
    category = _category(vector["description"])
    if category == "psbt structure":
        # the codec's own, five of the six: parse refuses four for a
        # length and one for a missing script, and the sixth is the
        # modifiable flags, which is a Signer's obligation
        with pytest.raises(BTClibValueError):
            role.assert_as_valid(Psbt.b64decode(vector["psbt"]))
        return

    psbt = Psbt.b64decode(vector["psbt"])
    checks = {
        "ecdh coverage": (
            role.assert_shares_as_valid,
            role.assert_output_scripts_as_valid,
        ),
        "input eligibility": (role.assert_eligibility_as_valid,),
        "output scripts": (role.assert_output_scripts_as_valid,),
    }[category]
    # its own category's check refuses it, and not merely the whole
    with pytest.raises(BTClibValueError):
        # `no branch`: the first check of the category refuses, which is
        # what the enclosing `raises` asserts, so the loop is never
        # exhausted -- the several entries are the checks that must all
        # be reached across the categories, not several to be run here
        for check in checks:  # pragma: no branch
            check(psbt)
    with pytest.raises(BTClibValueError):
        role.assert_as_valid(psbt)


def _vector(group: str, prefix: str) -> dict[str, Any]:
    """Return the one case whose description starts with the prefix."""
    return next(v for v in _VECTORS[group] if v["description"].startswith(prefix))


def test_the_k_ordering_is_the_output_index() -> None:
    """BIP375's prose and BIP375's vectors disagree; the vectors win.

    "If there are multiple silent payment codes with the same scan key,
    sort the codes lexicographically in ascending order to determine the
    ordering of the k value" -- and the case below is published as valid,
    shares one scan key across two outputs, and has its spend keys in
    *descending* order. So the lexicographic rule would give output 1 the
    k of 0, and the scripts the file carries are the ones output index
    order derives.

    Asserted rather than described, in both directions: index order
    reproduces both scripts, and the byte order and the address order --
    the two readings of "the codes" -- reproduce neither. Upstream's own
    validator walks index order too, so the prose is the outlier.
    """
    vector = _vector("valid", "can finalize: two sp outputs - output 0 uses label=3")
    psbt = Psbt.b64decode(vector["psbt"])
    outputs = [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_v0_info]
    assert len(outputs) == 2
    scan_key = outputs[0][1].sp_v0_info[: sp._PK_SIZE]
    # one scan key, and the spend keys the other way round
    assert all(o.sp_v0_info[: sp._PK_SIZE] == scan_key for _, o in outputs)
    assert outputs[0][1].sp_v0_info > outputs[1][1].sp_v0_info

    found = role._share_and_sum(psbt, scan_key)
    assert found is not None
    share, A_sum = found
    secret = role.shared_secret_from_share(psbt, share, A_sum)

    def script(psbt_out: Any, k: int) -> bytes:
        B_m = psbt_out.sp_v0_info[sp._PK_SIZE :]
        return serialize(["OP_1", sp.output_key(secret, B_m, k)])

    # index order: k is the position among the silent payment outputs
    for k, (_, psbt_out) in enumerate(outputs):
        assert psbt_out.script_pub_key == script(psbt_out, k)
    # the lexicographic order would swap them, and neither script matches
    for k, (_, psbt_out) in enumerate(reversed(outputs)):
        assert psbt_out.script_pub_key != script(psbt_out, k)

    # and what the module derives is what the file carries
    assert role.output_scripts(psbt) == {i: o.script_pub_key for i, o in outputs}


def test_the_two_ordering_vectors_are_refused_whatever_the_order() -> None:
    """The invalid cases named after ordering are not about ordering.

    Both have all three candidate orderings agree -- their spend keys are
    already ascending, or identical -- so what makes them invalid is that
    their scripts match no k assignment at all. Worth pinning: a reader of
    the descriptions would expect them to be the vectors that decide the
    ordering question, and they are not; the valid case above is.
    """
    for prefix in (
        "output scripts: two sp outputs (same scan / different spend keys)",
        "output scripts: k values assigned to wrong output indices",
    ):
        psbt = Psbt.b64decode(_vector("invalid", prefix)["psbt"])
        outputs = [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_v0_info]
        by_index = [i for i, _ in outputs]
        by_bytes = [
            i for i, _ in sorted(outputs, key=lambda p: (p[1].sp_v0_info, p[0]))
        ]
        assert by_index == by_bytes
        with pytest.raises(BTClibValueError, match="not the silent payment script"):
            role.assert_output_scripts_as_valid(psbt)


def test_an_input_pub_key_comes_from_the_derivation_or_the_script() -> None:
    """Where BIP375 says to look, and what a psbt not saying costs.

    A taproot input's key is in the script_pub_key, so it is readable
    whatever else the psbt carries. Every other eligible kind keeps it in
    PSBT_IN_BIP32_DERIVATION, which BIP375 asks an Updater to add for
    exactly this -- an unsigned input has no witness and no scriptSig to
    read one out of, which is why `btclib.silent_payments`'s reader cannot
    serve here.
    """
    psbt = Psbt.b64decode(_vector("valid", "can finalize: one P2PKH input")["psbt"])
    psbt_in = psbt.inputs[0]
    pub_key = role.input_pub_key(psbt_in)
    assert pub_key is not None
    assert bytes_from_point(pub_key) in psbt_in.hd_key_paths

    # the field gone, the key is gone with it, and a share that named it
    # is then a share nothing can prove
    stripped = deepcopy(psbt)
    stripped.inputs[0].hd_key_paths = {}
    assert role.input_pub_key(stripped.inputs[0]) is None
    assert role.eligible_pub_keys(stripped) == {}
    with pytest.raises(BTClibValueError, match="no public key to prove it against"):
        role.assert_shares_as_valid(stripped)

    # a taproot input needs no field: the output key is the script's
    taproot = Psbt.b64decode(_vector("valid", "in progress: two P2TR inputs")["psbt"])
    for taproot_in in taproot.inputs:
        assert role.input_pub_key(taproot_in) is not None


def test_an_ineligible_input_is_passed_over_rather_than_refused() -> None:
    """A share on an input BIP352 does not count proves nothing.

    And is not an error: one of BIP375's valid vectors carries exactly
    that, a p2sh multisig input beside the eligible ones. It contributes
    to no sum and is held to no proof -- which is a different thing from
    an input that *is* counted and carries no public key, the case above,
    and one of the invalid vectors.
    """
    psbt = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs using per-input ECDH")["psbt"]
    )
    eligible = role.eligible_pub_keys(psbt)
    assert len(eligible) < len(psbt.inputs)
    ineligible = next(i for i in range(len(psbt.inputs)) if i not in eligible)
    assert role.input_pub_key(psbt.inputs[ineligible]) is None
    role.assert_as_valid(psbt)


def test_a_share_needs_its_proof_and_a_proof_its_share() -> None:
    """Each half of the pair is useless alone, so neither stands alone."""
    psbt = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    scan_key = next(iter(psbt.sp_ecdh_shares))

    no_proof = deepcopy(psbt)
    no_proof.sp_dleq_proofs = {}
    with pytest.raises(
        BTClibValueError, match="global ECDH share with no proof beside it"
    ):
        role.assert_shares_as_valid(no_proof)

    no_share = deepcopy(psbt)
    no_share.sp_ecdh_shares = {}
    with pytest.raises(
        BTClibValueError, match="global DLEQ proof with no share to prove"
    ):
        role.assert_shares_as_valid(no_share)

    # and the same for the per-input pair
    per_input = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs single-signer using per")["psbt"]
    )
    damaged = deepcopy(per_input)
    damaged.inputs[0].sp_dleq_proofs = {}
    with pytest.raises(
        BTClibValueError, match="input 0 ECDH share with no proof beside it"
    ):
        role.assert_shares_as_valid(damaged)
    damaged = deepcopy(per_input)
    damaged.inputs[0].sp_ecdh_shares = {}
    with pytest.raises(
        BTClibValueError, match="input 0 DLEQ proof with no share to prove"
    ):
        role.assert_shares_as_valid(damaged)

    # a proof of the right shape that proves the wrong thing is refused by
    # the verification and not by a length, which is the point of carrying
    # one at all
    forged = deepcopy(psbt)
    forged.sp_ecdh_shares[scan_key] = bytes_from_point(mult(2))
    with pytest.raises(BTClibValueError, match="invalid global DLEQ proof"):
        role.assert_shares_as_valid(forged)


def test_the_share_is_not_the_shared_secret() -> None:
    """`a*B_scan` carries no input hash; BIP352's secret does.

    The step the two BIPs give no shared name, and the one an
    implementation gets wrong silently: skip the input hash and every
    output script comes out different, with nothing else to say so.
    """
    psbt = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    scan_key, share = next(iter(psbt.sp_ecdh_shares.items()))
    A_sum = sp.pub_key_sum(list(role.eligible_pub_keys(psbt).values()))
    secret = role.shared_secret_from_share(psbt, share, A_sum)

    outpoints = [psbt_in.prev_out for psbt_in in psbt.inputs]
    h = sp.input_hash(outpoints, A_sum)
    assert secret == mult(h, sp.pub_key_sum([share]))
    # the share alone is a different point, and would derive different
    # scripts with nothing to report
    assert secret != sp.pub_key_sum([share])
    assert bytes_from_point(secret) != share
    # and the share is what a DLEQ proof is about, the secret is not
    assert dleq.verify_proof(A_sum, scan_key, share, psbt.sp_dleq_proofs[scan_key])


def test_a_signer_writes_the_shares_it_can_prove() -> None:
    """The Signer's side, held to the Extractor's.

    A psbt stripped of its shares is written again from the private keys
    the vector publishes, and what says the two agree is not a byte
    comparison but the checks themselves: the proofs verify, the scripts
    derive to what the file already carried, and `assert_as_valid` passes
    over the result.
    """
    vector = _vector("valid", "can finalize: two inputs single-signer using per")
    psbt = Psbt.b64decode(vector["psbt"])
    prv_keys = {
        i["input_index"]: i["private_key"]
        for i in vector["supplementary"]["inputs"]
        if i["private_key"]
    }
    expected = {i: o.script_pub_key for i, o in enumerate(psbt.outputs) if o.sp_v0_info}

    stripped = deepcopy(psbt)
    for psbt_in in stripped.inputs:
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    for i in role.eligible_pub_keys(stripped):
        role.set_input_share(stripped, i, prv_keys[i], aux=bytes(32))
    role.assert_shares_as_valid(stripped)
    assert role.output_scripts(stripped) == expected
    role.assert_as_valid(stripped)

    # the same psbt with one global share instead, which is what a signer
    # holding every key may write: a different psbt, the same outputs
    global_psbt = deepcopy(stripped)
    for psbt_in in global_psbt.inputs:
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    eligible = list(role.eligible_pub_keys(global_psbt))
    role.set_global_share(global_psbt, [prv_keys[i] for i in eligible], aux=bytes(32))
    role.assert_shares_as_valid(global_psbt)
    assert role.output_scripts(global_psbt) == expected
    role.assert_as_valid(global_psbt)


def test_a_signer_is_held_to_the_key_of_the_input_it_writes_for() -> None:
    """A share proved against the wrong key is refused before it is written.

    Which is worth doing at the writing end: every reader of the psbt
    would reject it, and the signer would have published a proof of its
    own error.
    """
    vector = _vector("valid", "can finalize: two inputs single-signer using per")
    psbt = Psbt.b64decode(vector["psbt"])
    prv_keys = {
        i["input_index"]: i["private_key"]
        for i in vector["supplementary"]["inputs"]
        if i["private_key"]
    }
    eligible = list(role.eligible_pub_keys(psbt))
    other = prv_keys[eligible[1]]
    with pytest.raises(BTClibValueError, match="not the one of its public key"):
        role.set_input_share(psbt, eligible[0], other)

    # and the ineligible-input refusal, which needs a psbt that has one:
    # the P2SH multisig case, where a share would contribute to no sum
    excluded = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs using per-input ECDH")["psbt"]
    )
    excluded_eligible = role.eligible_pub_keys(excluded)
    ineligible = next(
        i for i in range(len(excluded.inputs)) if i not in excluded_eligible
    )
    with pytest.raises(BTClibValueError, match="no share BIP352 would count"):
        role.set_input_share(excluded, ineligible, next(iter(prv_keys.values())))

    with pytest.raises(BTClibValueError, match="private keys for"):
        role.set_global_share(psbt, [next(iter(prv_keys.values()))])
    with pytest.raises(BTClibValueError, match="do not sum to"):
        role.set_global_share(psbt, [other] * len(eligible))


def test_a_signer_derives_the_scripts_and_freezes_the_psbt() -> None:
    """BIP375: the scripts written, and nothing left modifiable.

    The scripts are a function of the input set and of where the codes
    sit, so a psbt that publishes one and still invites inputs invites its
    own scripts to become wrong. The flags are cleared in the same step
    that writes them, and `assert_as_valid` refuses the state where they
    are not.
    """
    vector = _vector("valid", "in progress: one P2TR input / one sp output")
    psbt = Psbt.b64decode(vector["psbt"])
    psbt_out = next(o for o in psbt.outputs if o.sp_v0_info)
    assert not psbt_out.script_pub_key

    # no share yet: nothing to derive from, and it says so rather than
    # writing half a transaction
    with pytest.raises(BTClibValueError, match="no ECDH share to derive"):
        role.set_output_scripts(psbt)

    signed = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    expected = {
        i: o.script_pub_key for i, o in enumerate(signed.outputs) if o.sp_v0_info
    }
    stripped = deepcopy(signed)
    for i in expected:
        stripped.outputs[i].script_pub_key = b""
    stripped.tx_modifiable = 0xFF

    role.set_output_scripts(stripped)
    assert {
        i: o.script_pub_key for i, o in enumerate(stripped.outputs) if o.sp_v0_info
    } == expected
    assert stripped.tx_modifiable is not None
    assert not stripped.tx_modifiable & 0b11
    # the five bits BIP370 leaves undefined are untouched: dropping a flag
    # somebody set is the change with consequences
    assert stripped.tx_modifiable == 0xFF & ~0b11
    role.assert_as_valid(stripped)


def test_a_psbt_with_no_silent_payment_output_passes() -> None:
    """There is nothing to derive, so there is nothing to refuse.

    The BIP371 taproot psbts of `bip371_test_vectors.json` are what say
    so: none of them carries a BIP375 field, and every role check has to
    be a no-op over them rather than an opinion.
    """
    checked = 0
    for case in load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"]:
        psbt = Psbt.b64decode(case["encoded psbt"])
        assert not any(o.sp_v0_info for o in psbt.outputs), case["description"]
        role.assert_shares_as_valid(psbt)
        role.assert_eligibility_as_valid(psbt)
        role.assert_output_scripts_as_valid(psbt)
        assert role.output_scripts(psbt) == {}
        # and the whole check, which for a version 0 psbt is also what
        # reaches the modifiable rule with no field to read: BIP370's flags
        # do not exist there, and no silent payment script depends on them
        role.assert_as_valid(psbt)
        assert psbt.tx_modifiable is None
        checked += 1
    assert checked


def test_the_categories_cover_every_invalid_vector() -> None:
    """The dispatch above is only as good as the prefixes it knows.

    A description in none of the four would otherwise pick a check by
    accident, so it raises -- and this is what says the raise is reachable
    rather than decoration, which is the failure mode of every guard
    written in the negative.
    """
    for vector in _VECTORS["invalid"]:
        assert _category(vector["description"]) in _CATEGORIES
    with pytest.raises(AssertionError, match="vector in no category"):
        _category("something upstream has not grouped yet")


def test_a_witness_version_is_read_off_the_shape() -> None:
    """What `assert_eligibility_as_valid` asks of every input's script.

    None where the script is no witness program at all, which is most
    scripts: a p2pkh, and a p2pk whose push length happens to fit the
    shape a program has. The versions above 1 are the ones refused, and
    v0 and v1 are the ones every silent payment is made of.
    """
    p2wpkh = bytes.fromhex("0014" + "11" * 20)
    p2tr = bytes.fromhex("5120" + "11" * 32)
    v2 = bytes.fromhex("5220" + "11" * 32)
    v16 = bytes.fromhex("6020" + "11" * 32)
    # the shape of a program -- one opcode, then a push of the rest -- with
    # an opcode that is no witness version: OP_NOP, which is what says the
    # shape alone does not make a program
    shaped = bytes.fromhex("6102" + "1111")
    p2pkh = bytes.fromhex("76a914" + "11" * 20 + "88ac")
    assert role._witness_version(p2wpkh) == 0
    assert role._witness_version(p2tr) == 1
    assert role._witness_version(v2) == 2
    assert role._witness_version(v16) == 16
    assert role._witness_version(shaped) is None
    # the shape does not fit
    assert role._witness_version(p2pkh) is None
    assert role._witness_version(b"") is None


def test_a_global_share_with_no_input_to_prove_it_against() -> None:
    """A share is a claim about the inputs, so it needs one.

    Not a psbt any signer writes -- it would have had a key to write the
    share with -- but a psbt a reader can be handed, and "no eligible
    input" is then a different failure from "the proof does not verify":
    there is nothing to verify it against.
    """
    psbt = Psbt.b64decode(
        _vector("valid", "can finalize: two inputs single-signer using global")["psbt"]
    )
    # every input made ineligible, the shares left in place
    for psbt_in in psbt.inputs:
        psbt_in.hd_key_paths = {}
        psbt_in.sp_ecdh_shares = {}
        psbt_in.sp_dleq_proofs = {}
    assert role.eligible_pub_keys(psbt) == {}
    with pytest.raises(BTClibValueError, match="no eligible input to prove it against"):
        role.assert_shares_as_valid(psbt)


def test_the_modifiable_flags_are_asked_about_only_once_a_script_is_there() -> None:
    """Before that the psbt is under construction and may still change.

    Which is what makes the check about the derivation rather than about
    tidiness: the flags matter from the moment a script depends on the
    input set, and not one step earlier.
    """
    psbt = Psbt.b64decode(
        _vector("valid", "in progress: one P2TR input / one sp output")["psbt"]
    )
    assert not any(o.sp_v0_info and o.script_pub_key for o in psbt.outputs)
    psbt.tx_modifiable = 0b11
    role.assert_as_valid(psbt)


def test_deriving_nothing_leaves_the_psbt_alone() -> None:
    """A psbt with no silent payment output has no script to derive.

    `set_output_scripts` is then a no-op rather than an error, and in
    particular does not clear the modifiable flags: there is no derived
    script for them to protect, and a Constructor still has work to do.
    """
    case = load("psbt", "_data", "bip371_test_vectors.json")["valid psbts"][0]
    psbt = Psbt.b64decode(case["encoded psbt"])
    before = psbt.serialize()
    role.set_output_scripts(psbt)
    assert psbt.serialize() == before


def test_private_keys_summing_to_zero_write_no_global_share() -> None:
    """The sum is the scalar the share is computed with, and zero is none.

    BIP352 fails on it for the sending side; here it is the same fact one
    step earlier, and refusing it is what stops a share of the point at
    infinity being written and proved.
    """
    vector = _vector("valid", "can finalize: two inputs single-signer using per")
    psbt = Psbt.b64decode(vector["psbt"])
    eligible = list(role.eligible_pub_keys(psbt))
    assert len(eligible) == 2
    a = 0x0F694E068028A717F8AF6B9411F9A133DD3565258714CC226594B34DB90C1F2C
    with pytest.raises(BTClibValueError, match="sum to zero"):
        role.set_global_share(psbt, [a, secp256k1.n - a])
