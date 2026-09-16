# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the anti-exfil protocol of `btclib.ecc.ssa`.

bitcoin-core/secp256k1#1140 proposes the same handshake for
`schnorrsig`, carrying over the ECDSA one BlockstreamResearch/secp256k1-zkp's
`secp256k1_ecdsa_s2c.h` specifies -- `tests/ecc/dsa_anti_exfil_test.py` is
that module's test, and its own docstring is where the two are put side
by side. The pull request is open and unmerged, so unlike that one this
file pins no vendored vector: its own `test_s2c_anti_exfil` draws its
data at random rather than fixing it, so there is nothing there to
reproduce byte for byte.
"""

from hashlib import sha1, sha256

import pytest

from btclib.ecc import ssa
from btclib.exceptions import BTClibValueError

_PRV_KEY = bytes.fromhex("55" * 32)
_PUB_KEY = ssa.gen_keys(_PRV_KEY)[1]

# a handshake of its own, so that nothing here leans on a vendored
# fixture. rho is a constant because a test has to be reproducible; a
# host draws it from a cryptographically secure generator, which is what
# the protocol asks of it and the one thing a test cannot check
_MSG = sha256(b"to be signed").digest()
_RHO = sha256(b"the host's randomness").digest()
_OTHER_RHO = sha256(b"a second draw").digest()


def test_step_2_and_step_4_reach_one_nonce() -> None:
    """The R promised in step 2 is the R the signature of step 4 has.

    Which is what `commit_entropy_` buys by hashing the committed value
    before it enters the derivation: the device can reach the nonce
    knowing only a hash of rho, so it can publish R before rho is
    revealed.
    """
    commitment = ssa.anti_exfil_host_commit(_RHO)
    # the raw data is not the commitment, or the assertion below would
    # not need the commitment at all
    assert commitment != _RHO

    R = ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, commitment)
    sig = ssa.anti_exfil_sign(_MSG, _PRV_KEY, _RHO)
    assert ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, _RHO, R)


def test_the_whole_handshake() -> None:
    """The five steps, in order, and then what each of them refuses."""
    # 1. the host draws rho and commits to it
    commitment = ssa.anti_exfil_host_commit(_RHO)
    # 2. the device answers with the point its nonce will have
    R = ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, commitment)
    # 3. the host reveals rho
    # 4. the device signs, committing to it
    sig = ssa.anti_exfil_sign(_MSG, _PRV_KEY, _RHO)
    # 5. the host checks the signature against that R and its own rho
    assert ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, _RHO, R)

    # an ordinary BIP340 signature, which is the whole point: nothing on
    # the chain says the nonce was negotiated
    assert ssa.verify_(_MSG, _PUB_KEY, sig)
    assert ssa.verify_(_MSG, _PUB_KEY, sig.serialize())

    # not against another message, another rho, or another R
    assert not ssa.anti_exfil_host_verify(
        sha256(b"another message").digest(), _PUB_KEY, sig, _RHO, R
    )
    assert not ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, _OTHER_RHO, R)
    other_point = ssa.anti_exfil_signer_commit(
        _MSG, _PRV_KEY, ssa.anti_exfil_host_commit(_OTHER_RHO)
    )
    assert not ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, _RHO, other_point)


def test_the_signer_keeps_no_state() -> None:
    """A rho that does not match the commitment fails step 5, and only that.

    The device does not remember the commitment it answered step 2 with,
    and does not have to: it re-derives one from whatever rho arrives.
    A host that reveals something else gets a valid signature over an R
    that is not the R it holds, so step 5 says no -- and because that R
    belonged to the commitment it came from, no nonce was reused and the
    key was never what was at stake.
    """
    commitment = ssa.anti_exfil_host_commit(_RHO)
    R = ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, commitment)

    # step 3 reveals the wrong value; step 4 signs it all the same
    sig = ssa.anti_exfil_sign(_MSG, _PRV_KEY, _OTHER_RHO)
    assert ssa.verify_(_MSG, _PUB_KEY, sig)
    assert not ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, _RHO, R)

    # and what it does open under is the R of the rho it was given, a
    # point the host never saw
    other_R = ssa.anti_exfil_signer_commit(
        _MSG, _PRV_KEY, ssa.anti_exfil_host_commit(_OTHER_RHO)
    )
    assert other_R != R
    assert ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, _OTHER_RHO, other_R)


def test_a_restart_takes_the_same_rho() -> None:
    """Step 2 is a function of its arguments, so the host's check bites.

    Restarting with the same rho must reach the same R, or the host has
    nothing to compare and a device could bias the nonces it lets
    through by aborting selectively. Restarting with a fresh rho reaches
    a different R, which is why the protocol asks for the old one.
    """
    commitment = ssa.anti_exfil_host_commit(_RHO)
    assert ssa.anti_exfil_host_commit(_RHO) == commitment
    R = ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, commitment)
    assert ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, commitment) == R

    redrawn = ssa.anti_exfil_host_commit(_OTHER_RHO)
    assert redrawn != commitment
    assert ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, redrawn) != R


def test_rho_and_the_commitment_are_hf_len() -> None:
    """The sizes follow hf, and the two signing steps refuse any other.

    Not decoration: rho is what the device cannot predict, and a host
    drawing four bytes of it hands the device a value to guess and grind
    against. Refused where it is drawn and where it is signed with;
    `anti_exfil_host_verify` answers False instead, verify never raising
    over what is merely an input the signature does not match.
    """
    short = b"\x00" * 31
    with pytest.raises(BTClibValueError, match="invalid size"):
        ssa.anti_exfil_host_commit(short)
    with pytest.raises(BTClibValueError, match="invalid size"):
        ssa.anti_exfil_sign(_MSG, _PRV_KEY, short)
    with pytest.raises(BTClibValueError, match="invalid size"):
        ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, short)

    commitment = ssa.anti_exfil_host_commit(_RHO)
    R = ssa.anti_exfil_signer_commit(_MSG, _PRV_KEY, commitment)
    sig = ssa.anti_exfil_sign(_MSG, _PRV_KEY, _RHO)
    assert not ssa.anti_exfil_host_verify(_MSG, _PUB_KEY, sig, short, R)

    # hf is the one that says what the sizes are, all the way through:
    # the 20 bytes below reach step 5 and the 32 above would not, each
    # step measuring against the hf it was handed
    msg = sha1(b"to be signed").digest()  # noqa: S324
    rho = sha1(b"the host's randomness").digest()  # noqa: S324
    commitment = ssa.anti_exfil_host_commit(rho, sha1)
    with pytest.raises(BTClibValueError, match="invalid size"):
        ssa.anti_exfil_signer_commit(msg, _PRV_KEY, _RHO, hf=sha1)
    R = ssa.anti_exfil_signer_commit(msg, _PRV_KEY, commitment, hf=sha1)
    sig = ssa.anti_exfil_sign(msg, _PRV_KEY, rho, hf=sha1)
    assert ssa.anti_exfil_host_verify(msg, _PUB_KEY, sig, rho, R, sha1)
