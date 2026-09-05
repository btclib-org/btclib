# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The BIP375 roles: sending a silent payment through a psbt.

https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki

`btclib.psbt.psbt_in` and `btclib.psbt.psbt_out` carry BIP375's six
fields; this is what the two roles BIP375 adds *do* with them, and it is
a module rather than a function for the reason `btclib.psbt.musig2` is:
a role is a sequence of steps different parties take at different times.

**Why it matters more than a signature does.** A silent payment output
script is derived, not signed: get it wrong and the transaction is still
consensus-valid, so it confirms and the money is gone. The shares and the
BIP374 proofs are what make that derivation checkable by somebody holding
none of the keys -- and the Transaction Extractor is where the check has
to happen, being the last party before the bytes go on the wire.

The Signer's side, in the order BIP375 puts it:

- `set_input_share` writes an ECDH share and its proof for one input the
  Signer holds the key of; `set_global_share` writes the one pair that
  stands for every eligible input, which a Signer holding all the keys
  may do instead.
- `assert_shares_as_valid` is what a Signer does with the shares it did
  *not* write: every proof verified against the key of the input it
  covers, or against the sum of them for a global one.
- `set_output_scripts` computes what the recipients are paid, once every
  eligible input is covered, and clears the two modifiable flags -- the
  scripts depend on the input set, so nothing may be added afterwards.

`assert_as_valid` is the Extractor's, and it is the four checks BIP375's
own validator publishes, in its order: the fields, then the share
coverage and the proofs, then which inputs are allowed to be there at
all, then the output scripts recomputed and compared.

**What a psbt input's public key is, and why it needs its own reader.**
`btclib.silent_payments.pub_key_from_input` reads it off a *signed*
input, from the witness or the scriptSig. An unsigned input has neither,
and BIP375 says where to look instead: the Updater "should add a
PSBT_IN_BIP32_DERIVATION for any p2wpkh, p2sh-p2wpkh, or p2pkh input so
the public key is available for creating the ecdh_shared_secret when the
private key is not known". `input_pub_key` is that reader, and it answers
None for an input BIP352 does not count -- a taproot NUMS internal key, a
p2sh wrapping anything but p2wpkh, a script type off the list.

**The share is not the shared secret**, which is the thing in BIP375
easiest to get wrong: `a*B_scan` carries no input hash, and BIP352's
shared secret is `input_hash*a*B_scan`. So the Extractor multiplies the
share by the input hash, and the input hash needs the *sum of the public
keys* of the eligible inputs -- which is why reading those keys is the
first thing here and not an aside.

**The k of an output** is BIP375's own rule and not BIP352's ordering: it
counts per scan key, over the outputs in index order. That is what the
BIP's vectors and its reference validator do and *not* what its prose
says, which asks for the codes to be sorted lexicographically;
`_ordered_sp_outputs` is where the discrepancy is documented, and
`tests/psbt/silent_payments_test.py` says which of the vectors pins it.
"""

from __future__ import annotations

from collections.abc import Sequence

from btclib import silent_payments as sp
from btclib.alias import Integer, Octets, Point
from btclib.curves import (
    bytes_from_point,
    mult,
    point_from_pub_key,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.ecc import dleq
from btclib.ecc.ssa import point_from_bip340pub_key
from btclib.exceptions import BTClibValueError
from btclib.psbt.psbt import INPUTS_MODIFIABLE, OUTPUTS_MODIFIABLE, Psbt, _prev_out
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_utils import SP_SCAN_KEY_SIZE
from btclib.script import serialize
from btclib.script.script_pub_key import (
    is_p2pkh,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
)
from btclib.script.sig_hash import ALL

__all__ = [
    "assert_as_valid",
    "assert_eligibility_as_valid",
    "assert_output_scripts_as_valid",
    "assert_shares_as_valid",
    "eligible_pub_keys",
    "input_pub_key",
    "output_scripts",
    "set_global_share",
    "set_input_share",
    "set_output_scripts",
    "shared_secret_from_share",
]

# the highest witness version an input may spend while a silent payment
# output is present. Above it the spent script is one this protocol
# version has no rule for, and BIP352 skips such a transaction rather
# than guess -- so a sender must not build one
_MAX_WITNESS_VERSION = 1

# OP_1, which a version 1 witness program starts with: the versions run
# OP_1..OP_16 as 0x51..0x60, so a first byte above this is a version above 1
_OP_1 = 0x51


def _witness_version(script: bytes) -> int | None:
    """Return the witness version of a program, or None if it is none.

    The shape and not the length, which is deliberate: what this answers
    is whether a version is above 1, and a v2-or-later program of a length
    no BIP defines is still an input BIP352 has no rule for.
    """
    if len(script) < 2 or script[1] != len(script) - 2:
        return None
    if script[0] == 0:
        return 0
    if _OP_1 <= script[0] <= _OP_1 + 15:
        return script[0] - _OP_1 + 1
    return None


def _script_pub_key(psbt_in: PsbtIn) -> bytes:
    """Return the script_pub_key of the output an input spends, or b""."""
    prev_out = _prev_out(psbt_in)
    return b"" if prev_out is None else prev_out.script_pub_key.script


def _is_eligible(psbt_in: PsbtIn) -> bool:
    """Answer whether BIP352 counts this input, reading the psbt fields.

    The four eligible script types, minus the two exclusions that are not
    the script type: a taproot input whose internal key is BIP341's NUMS
    point has no key path to derive from, and a p2sh input is eligible
    only for the one redeem script BIP352 lists, p2wpkh.

    Both come from a field rather than from a witness, which is where a
    psbt reader differs from `btclib.silent_payments`: an input that has
    not been signed has no witness to read either out of.
    """
    script = _script_pub_key(psbt_in)
    if is_p2tr(script):
        return psbt_in.taproot_internal_key != sp.NUMS_H
    if is_p2sh(script):
        return is_p2wpkh(psbt_in.redeem_script)
    return is_p2pkh(script) or is_p2wpkh(script)


def input_pub_key(psbt_in: PsbtIn) -> Point | None:
    """Return the public key of one psbt input, or None if it does not count.

    A taproot input's key is the output key the script_pub_key carries:
    it is what the recipient sums, script path or not, and the psbt need
    not say anything for it to be readable. Every other eligible kind
    keeps its key in the key data of PSBT_IN_BIP32_DERIVATION, which is
    what BIP375 asks an Updater to add for exactly this.

    The lowest such key where there is more than one, rather than an
    arbitrary first: a dict's order is the order the psbt happened to be
    parsed in, and an answer that depends on it is an answer two readers
    of one psbt could disagree about. An eligible input has one key
    anyway -- p2pkh, p2wpkh and p2sh-p2wpkh each commit to a single hash
    -- so this decides nothing that a correct psbt leaves open.
    """
    if not _is_eligible(psbt_in):
        return None
    script = _script_pub_key(psbt_in)
    if is_p2tr(script):
        return point_from_bip340pub_key(script[2:34], secp256k1)
    keys = sorted(k for k in psbt_in.hd_key_paths if len(k) == SP_SCAN_KEY_SIZE)
    if not keys:
        return None
    return point_from_pub_key(keys[0])


def eligible_pub_keys(psbt: Psbt) -> dict[int, Point]:
    """Return the public key of every input BIP352 counts, by index.

    The index is kept because the per-input shares are filed per input: a
    coverage rule that answered "how many" rather than "which" could not
    name the input whose share is missing.
    """
    keys = {}
    for i, psbt_in in enumerate(psbt.inputs):
        pub_key = input_pub_key(psbt_in)
        if pub_key is not None:
            keys[i] = pub_key
    return keys


def _scan_keys(psbt: Psbt) -> list[bytes]:
    """Return the scan key of every silent payment output, deduplicated."""
    seen: dict[bytes, None] = {}
    for psbt_out in psbt.outputs:
        if psbt_out.sp_v0_info:
            seen[psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE]] = None
    return list(seen)


def _share_and_sum(psbt: Psbt, scan_key: bytes) -> tuple[bytes, Point] | None:
    """Return the share standing for every eligible input, and their sum.

    The global share where there is one, else the sum of the per-input
    shares of the eligible inputs -- which is what makes the two
    interchangeable downstream: `a_1*B + a_2*B` is `(a_1 + a_2)*B`, so a
    transaction whose signers each contributed one share derives the same
    outputs as one whose single signer contributed the lot.

    None when there is nothing to derive from: no share at all, or no
    eligible input to take a public key from.
    """
    pub_keys = eligible_pub_keys(psbt)
    if not pub_keys:
        return None
    A_sum = sp.pub_key_sum(list(pub_keys.values()))

    share = psbt.sp_ecdh_shares.get(scan_key)
    if share is not None:
        return share, A_sum

    shares = [
        psbt.inputs[i].sp_ecdh_shares[scan_key]
        for i in pub_keys
        if scan_key in psbt.inputs[i].sp_ecdh_shares
    ]
    if not shares:
        return None
    total = sp.pub_key_sum(shares)
    return bytes_from_point(total, secp256k1), A_sum


def shared_secret_from_share(psbt: Psbt, share: Octets, A_sum: Point) -> Point:
    """Return BIP352's shared secret from a BIP375 share.

    The step the two BIPs do not share a name for, and the one worth
    spelling out: the psbt carries `a*B_scan`, with no input hash in it,
    where BIP352's secret is `input_hash*a*B_scan`. So the share is
    multiplied by the input hash here, and the input hash is what binds
    the derivation to this transaction's smallest outpoint -- which is why
    the psbt is an argument and the share alone would not do.
    """
    outpoints = [psbt_in.prev_out for psbt_in in psbt.inputs]
    return sp.shared_secret(sp.input_hash(outpoints, A_sum), share)


def _ordered_sp_outputs(psbt: Psbt) -> list[tuple[int, PsbtOut]]:
    """Return the silent payment outputs in the order their k follows.

    Output index order, per scan key -- which is **not** what BIP375's
    prose says, and the discrepancy is upstream's rather than a choice
    made here. The BIP says: "If there are multiple silent payment codes
    with the same scan key, sort the codes lexicographically in ascending
    order to determine the ordering of the k value."

    Measured against `bip375_test_vectors.json`, that sort produces the
    wrong scripts. Its "two sp outputs - output 0 uses label=3 / output 1
    uses label=1" case is published as *valid* and its two spend keys are
    in descending order, so a lexicographic sort assigns k = 0 to output 1
    -- and the scripts the file carries are the ones index order derives.
    Neither reading of "the codes" rescues the prose: sorting the 66-byte
    info fields and sorting the bech32m address strings both order that
    pair the other way round.

    So two of upstream's three artefacts agree on index order -- the
    vectors and `bip-0375/validator/validate_psbt.py`, which tracks k per
    scan key while walking the outputs in index order -- and only the
    prose dissents. Index order is therefore what interoperates, and the
    two "output scripts" invalid vectors named after ordering are refused
    under it anyway: each carries a k assignment no ascending rule
    produces, the two values swapped in one and three permuted in the
    other. `tests/psbt/silent_payments_test.py` pins each of those facts,
    so a revision of the BIP that settles it the other way fails here
    rather than passing quietly -- which is what bips PR 2207 proposes,
    correcting the vectors and the validator to match the prose.
    """
    return [(i, o) for i, o in enumerate(psbt.outputs) if o.sp_v0_info]


def output_scripts(psbt: Psbt) -> dict[int, bytes]:
    """Return the script every silent payment output should pay, by index.

    An output whose scan key has no share is absent from the answer rather
    than raising: a psbt under construction is allowed to have one, which
    is the "in progress" half of BIP375's own vectors, and what refuses
    the ones that are not allowed is `assert_output_scripts_as_valid`.
    """
    scripts: dict[int, bytes] = {}
    counters: dict[bytes, int] = {}
    for i, psbt_out in _ordered_sp_outputs(psbt):
        scan_key = psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE]
        found = _share_and_sum(psbt, scan_key)
        if found is None:
            continue
        share, A_sum = found
        k = counters.get(scan_key, 0)
        counters[scan_key] = k + 1
        secret = shared_secret_from_share(psbt, share, A_sum)
        B_m = psbt_out.sp_v0_info[SP_SCAN_KEY_SIZE:]
        # `serialize(["OP_1", key])` and not `ScriptPubKey.p2tr(key)`: that
        # classmethod takes an *internal* key and applies BIP341's tweak,
        # where what BIP352 derives is already the output key. Tweaking it
        # a second time is a script no recipient scans for
        scripts[i] = serialize(["OP_1", sp.output_key(secret, B_m, k)])
    return scripts


def _assert_pair(
    shares: dict[bytes, bytes], proofs: dict[bytes, bytes], what: str
) -> None:
    """Raise unless the shares and the proofs name the same scan keys.

    Each half is useless without the other: a share nobody can hold its
    writer to is what carrying a proof exists to prevent, and a proof of a
    share that is not there proves nothing at all.
    """
    for scan_key in shares:
        if scan_key not in proofs:
            err_msg = f"{what} ECDH share with no proof beside it: scan key "
            err_msg += scan_key.hex()
            raise BTClibValueError(err_msg)
    for scan_key in proofs:
        if scan_key not in shares:
            err_msg = f"{what} DLEQ proof with no share to prove: scan key "
            err_msg += scan_key.hex()
            raise BTClibValueError(err_msg)


def _assert_global_shares(psbt: Psbt, A_sum: Point | None) -> None:
    """Raise unless the global shares are proved against the input sum.

    A global share stands for every eligible input at once, so what proves
    it is the sum of their public keys -- and a psbt carrying one with no
    eligible input to sum is a psbt whose share nothing can be checked
    against, which is a different failure from a proof that does not
    verify.
    """
    _assert_pair(psbt.sp_ecdh_shares, psbt.sp_dleq_proofs, "global")
    for scan_key, share in psbt.sp_ecdh_shares.items():
        if A_sum is None:
            err_msg = "global ECDH share with no eligible input to prove it against"
            raise BTClibValueError(err_msg)
        if not dleq.verify_proof(A_sum, scan_key, share, psbt.sp_dleq_proofs[scan_key]):
            raise BTClibValueError(f"invalid global DLEQ proof for {scan_key.hex()}")


def _assert_input_shares(psbt: Psbt, pub_keys: dict[int, Point]) -> None:
    """Raise unless every per-input share is proved against its own key.

    A share on an input BIP352 does not count is passed over rather than
    refused: `_share_and_sum` gives it no weight either, and one of
    BIP375's valid vectors carries exactly that. An input that *is*
    counted and carries no public key is the opposite case and is refused
    -- BIP375 asks an Updater for PSBT_IN_BIP32_DERIVATION so that there
    is one, and one of its invalid vectors is that field missing.
    """
    for i, psbt_in in enumerate(psbt.inputs):
        if psbt_in.sp_ecdh_shares and not _is_eligible(psbt_in):
            continue
        _assert_pair(psbt_in.sp_ecdh_shares, psbt_in.sp_dleq_proofs, f"input {i}")
        for scan_key, share in psbt_in.sp_ecdh_shares.items():
            A = pub_keys.get(i)
            if A is None:
                err_msg = f"input {i}: ECDH share on an input with no public key to "
                err_msg += "prove it against; BIP375 asks an Updater for "
                err_msg += "PSBT_IN_BIP32_DERIVATION so that there is one"
                raise BTClibValueError(err_msg)
            proof = psbt_in.sp_dleq_proofs[scan_key]
            if not dleq.verify_proof(A, scan_key, share, proof):
                err_msg = f"input {i}: invalid DLEQ proof for {scan_key.hex()}"
                raise BTClibValueError(err_msg)


def assert_shares_as_valid(psbt: Psbt) -> None:
    """Raise unless every ECDH share the psbt carries is proved.

    BIP375's second check, and the one that makes a share worth reading: a
    proof is verified against the public key of what it covers -- the sum
    of the eligible inputs' keys for a global share, that one input's key
    for a per-input one -- so a share can be trusted by a party holding
    none of the private keys.
    """
    pub_keys = eligible_pub_keys(psbt)
    A_sum = sp.pub_key_sum(list(pub_keys.values())) if pub_keys else None
    _assert_global_shares(psbt, A_sum)
    _assert_input_shares(psbt, pub_keys)


def _assert_covered(psbt: Psbt, scan_key: bytes) -> None:
    """Raise unless every eligible input contributes to this scan key.

    Asked only of a scan key whose output script is already set: before
    that the psbt is under construction, and a share that has not arrived
    is a signer that has not signed. Once the script is there it is a
    claim about every eligible input, so a missing share means the script
    was derived from fewer keys than the recipient will sum -- and the
    recipient would find nothing.
    """
    if scan_key in psbt.sp_ecdh_shares:
        return
    for i in eligible_pub_keys(psbt):
        if scan_key not in psbt.inputs[i].sp_ecdh_shares:
            err_msg = f"input {i}: no ECDH share for scan key {scan_key.hex()}, "
            err_msg += "whose output script is already set"
            raise BTClibValueError(err_msg)


def assert_eligibility_as_valid(psbt: Psbt) -> None:
    """Raise unless every input may be there at all, silent payments present.

    BIP375's third check, and the two rules are BIP352's reasons in a
    psbt's terms. An input spending a witness program above version 1 is
    one this protocol version has no derivation rule for, so BIP352 skips
    the whole transaction -- which makes building one a way to pay an
    address nobody will scan. And a sighash type other than SIGHASH_ALL
    lets the inputs or the outputs change after the scripts were derived
    from them: BIP352 permits NONE and SINGLE, BIP375 does not, because
    here the scripts are computed from the number and the position of the
    codes.
    """
    if not _scan_keys(psbt):
        return
    for i, psbt_in in enumerate(psbt.inputs):
        version = _witness_version(_script_pub_key(psbt_in))
        if version is not None and version > _MAX_WITNESS_VERSION:
            err_msg = f"input {i}: spends witness version {version}, which a psbt "
            err_msg += "with a silent payment output must not"
            raise BTClibValueError(err_msg)
        if psbt_in.sig_hash_type is not None and psbt_in.sig_hash_type != ALL:
            err_msg = f"input {i}: sig hash type {psbt_in.sig_hash_type}, where a "
            err_msg += "psbt with a silent payment output requires SIGHASH_ALL"
            raise BTClibValueError(err_msg)


def assert_output_scripts_as_valid(psbt: Psbt) -> None:
    """Raise unless every silent payment script is the one derived.

    BIP375's fourth check and the Extractor's reason to exist: this is the
    error a signature cannot catch, a wrong output script being
    consensus-valid. An output that carries no script yet is passed over
    -- that is a psbt still being built -- and one that carries a script
    without the shares to derive it is not.
    """
    derived = output_scripts(psbt)
    for i, psbt_out in enumerate(psbt.outputs):
        if not psbt_out.sp_v0_info:
            continue
        script = psbt_out.script_pub_key
        scan_key = psbt_out.sp_v0_info[:SP_SCAN_KEY_SIZE]
        if not script:
            continue
        _assert_covered(psbt, scan_key)
        if i not in derived:
            err_msg = f"output {i}: PSBT_OUT_SCRIPT with no ECDH share to derive it "
            err_msg += f"from, for scan key {scan_key.hex()}"
            raise BTClibValueError(err_msg)
        if script != derived[i]:
            err_msg = f"output {i}: PSBT_OUT_SCRIPT is not the silent payment script "
            err_msg += f"its address derives: {script.hex()} instead of "
            err_msg += derived[i].hex()
            raise BTClibValueError(err_msg)


def _assert_modifiable_cleared(psbt: Psbt) -> None:
    """Raise if a derived output script may still have its inputs changed.

    BIP375: a Signer that sets a missing PSBT_OUT_SCRIPT "must set the
    Inputs Modifiable and Outputs Modifiable flags to False". The script
    is a function of the input set and of the position of the codes, so a
    psbt that publishes one and still invites changes publishes a script
    that the next Constructor invalidates.
    """
    if psbt.tx_modifiable is None:
        return
    if not any(o.sp_v0_info and o.script_pub_key for o in psbt.outputs):
        return
    if psbt.tx_modifiable & (INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE):
        err_msg = "PSBT_GLOBAL_TX_MODIFIABLE still invites changes, with a silent "
        err_msg += "payment output script already derived from what it would change"
        raise BTClibValueError(err_msg)


def assert_as_valid(psbt: Psbt) -> None:
    """Raise unless the psbt satisfies BIP375, the roles included.

    `Psbt.assert_valid` is the format; this is the protocol on top of it,
    and it is what a Transaction Extractor owes a silent payment before it
    hands the bytes over. The four checks in BIP375's own order, each
    naming what failed: the fields, the shares and their proofs, which
    inputs may be present, and the output scripts.

    A psbt with no silent payment output passes everything here, there
    being nothing to derive.
    """
    psbt.assert_valid()
    _assert_modifiable_cleared(psbt)
    assert_shares_as_valid(psbt)
    assert_eligibility_as_valid(psbt)
    assert_output_scripts_as_valid(psbt)


def _share_for(a: int, scan_key: bytes, aux: Octets | None) -> tuple[bytes, bytes]:
    """Return the ECDH share for one scalar and scan key, and its proof."""
    B_scan = point_from_pub_key(scan_key)
    share = bytes_from_point(mult(a, B_scan), secp256k1)
    return share, dleq.generate_proof(a, B_scan, aux)


def set_input_share(
    psbt: Psbt, vin_i: int, prv_key: Integer, aux: Octets | None = None
) -> None:
    """Write the ECDH share and proof of one input, for every recipient.

    What a Signer holding one input's key does: one share per scan key the
    psbt pays, each with the BIP374 proof that it was computed with the
    private key of *this* input's public key -- which is what lets the
    other signers check it without holding that key.

    The input must be one BIP352 counts, and the key must be its own: a
    share proved against a public key the input does not have is a share
    every verifier rejects, so it is refused here instead of written.
    """
    psbt_in = psbt.inputs[vin_i]
    A = input_pub_key(psbt_in)
    if A is None:
        err_msg = f"input {vin_i}: no public key, so no share BIP352 would count"
        raise BTClibValueError(err_msg)
    a = scalar_from_prv_key(prv_key)
    if mult(a) != A:
        err_msg = f"input {vin_i}: the private key is not the one of its public key"
        raise BTClibValueError(err_msg)
    for scan_key in _scan_keys(psbt):
        share, proof = _share_for(a, scan_key, aux)
        psbt_in.sp_ecdh_shares[scan_key] = share
        psbt_in.sp_dleq_proofs[scan_key] = proof


def set_global_share(
    psbt: Psbt, prv_keys: Sequence[Integer], aux: Octets | None = None
) -> None:
    """Write the one ECDH share standing for every eligible input.

    What a Signer holding *every* eligible input's key may do instead of
    one share each: the sum of those keys, once, with one proof against
    the sum of their public keys. Fewer bytes in the psbt and one
    verification for every reader of it.

    The keys are given in the order of the eligible inputs, and the sum is
    checked against the sum of their public keys before anything is
    written: a global share proved against the wrong sum is a share that
    fails for every recipient at once.
    """
    pub_keys = eligible_pub_keys(psbt)
    if len(prv_keys) != len(pub_keys):
        err_msg = f"{len(prv_keys)} private keys for {len(pub_keys)} eligible inputs"
        raise BTClibValueError(err_msg)
    a = 0
    for prv_key in prv_keys:
        a = (a + scalar_from_prv_key(prv_key)) % secp256k1.n
    if a == 0:
        raise BTClibValueError("input private keys sum to zero")
    if mult(a) != sp.pub_key_sum(list(pub_keys.values())):
        err_msg = "the private keys do not sum to the eligible inputs' public keys"
        raise BTClibValueError(err_msg)
    for scan_key in _scan_keys(psbt):
        share, proof = _share_for(a, scan_key, aux)
        psbt.sp_ecdh_shares[scan_key] = share
        psbt.sp_dleq_proofs[scan_key] = proof


def set_output_scripts(psbt: Psbt) -> None:
    """Derive every silent payment output script, and freeze the psbt.

    The Signer's last step before it signs: BIP375 forbids a signature
    while an output has no script, and requires the two modifiable flags
    cleared once one is written -- the script is a function of the input
    set, so a psbt that still invites inputs invites its own scripts to
    become wrong.

    Every silent payment output must be derivable, or nothing is written:
    a psbt half-derived is one whose recipients each need the other's
    signer to have finished.
    """
    scripts = output_scripts(psbt)
    missing = [
        i for i, o in enumerate(psbt.outputs) if o.sp_v0_info and i not in scripts
    ]
    if missing:
        err_msg = f"no ECDH share to derive the script of output(s) {missing}"
        raise BTClibValueError(err_msg)
    if not scripts:
        return
    for i, script in scripts.items():
        psbt.outputs[i].script_pub_key = script
    psbt.tx_modifiable = (psbt.tx_modifiable or 0) & ~(
        INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE
    )
