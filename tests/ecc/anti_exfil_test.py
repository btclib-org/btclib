# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the ECDSA Anti-Exfil Protocol of `btclib.ecc.dsa`.

The protocol is libsecp256k1-zkp's, and its `ecdsa_s2c` module carries
the vectors: the fixture below is that module's `ecdsa_s2c_tests`, whose
third column, `expected_s2c_exfil_opening`, is the R that
`anti_exfil_signer_commit` has to answer with.

The second column is what makes the fixture worth more than two numbers.
`expected_s2c_opening` is the receipt of a sign-to-contract signature
over the same data, so the two columns are one `anti_exfil_host_commit`
apart -- and that is exactly the property the handshake stands on, step
2 and step 4 reaching one nonce. It is checked here against upstream's
own bytes rather than against btclib run twice.

```text
repo    BlockstreamResearch/secp256k1-zkp
path    src/modules/ecdsa_s2c/tests_impl.h
commit  baac08d207003151d095423487d3954503a52aeb  2026-04-20
blob    ba4f158c5d5c63b195011cda8c24331e5d21a4d4
```

Read at master `2af926dc309a673461f0e2da090105c8f05b4505`, whose tree
carries that blob; the commit above is the tip of the path. The protocol
rationale quoted in the docstrings is `include/secp256k1_ecdsa_s2c.h` at
the same master, blob `c931457d6a53ca8aed8189257e7a2ff496fd084c`.
"""

from hashlib import sha1, sha256

import pytest

from btclib.curves import bytes_from_point, secp256k1
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError

# the key and the message of test_ecdsa_s2c_fixed_vectors, which
# test_ecdsa_anti_exfil_signer_commit reuses verbatim
_PRV_KEY = bytes.fromhex("55" * 32)
_MSG_HASH = bytes.fromhex("88" * 32)
_PUB_KEY = dsa.gen_keys(_PRV_KEY)[1]

# s2c_data, expected_s2c_opening, expected_s2c_exfil_opening
_ZKP_VECTORS = [
    pytest.param(
        "1bf6fb42f41eb876c4d7aa0d67242b00baab99dc2084493e4e63277fa1f77f22",
        "03f030def3188c0f56fcea87435b307643f45dafe22cbc82fd56034fae97417d3a",
        "02df63755d1f3292bffed82986b106497c93b1f8bdc0454b6b0b0a4779c0ef7188",
        id="zkp-0",
    ),
    pytest.param(
        "35199a8fbf84ad6ef69a184c1b19285befbe06e60b6264e6d373893f6855e24a",
        "03901717ce7c7484a2ce1b7dc7403b14e0354971393ec092a7f3e0c8e4e2d2639d",
        "02c04ac7f771e8ebdbf315ff5e58b7fe9516102103500066172c4fac5b20f9e0ea",
        id="zkp-1",
    ),
]

# a handshake of its own, so that nothing here leans on the fixture's
# message. rho is a constant because a test has to be reproducible; a
# host draws it from a cryptographically secure generator, which is what
# the protocol asks of it and the one thing a test cannot check
_HANDSHAKE_MSG_HASH = sha256(b"to be signed").digest()
_RHO = sha256(b"the host's randomness").digest()
_OTHER_RHO = sha256(b"a second draw").digest()


@pytest.mark.parametrize("rho, opening, exfil_opening", _ZKP_VECTORS)
def test_signer_commit_vectors(rho: str, opening: str, exfil_opening: str) -> None:
    """R is the opening test_ecdsa_anti_exfil_signer_commit expects.

    That fixture hands the raw s2c_data to `anti_exfil_signer_commit` as
    the host commitment -- an unreachable value in a real handshake,
    where the commitment is a hash -- so this pins the derivation and
    nothing about the protocol. Which is what a vector is for: the
    commitment enters as RFC6979 additional data, unhashed, and no other
    layout reaches these bytes.
    """
    R = dsa.anti_exfil_signer_commit(_MSG_HASH, _PRV_KEY, rho)
    assert bytes_from_point(R, secp256k1).hex() == exfil_opening
    # the other column is a different R, the s2c signature deriving its
    # nonce from a hash of this same data: which is the next test
    assert exfil_opening != opening


@pytest.mark.parametrize("rho, opening, exfil_opening", _ZKP_VECTORS)
def test_step_2_and_step_4_reach_one_nonce(
    rho: str, opening: str, exfil_opening: str
) -> None:
    """The R promised in step 2 is the R the signature of step 4 has.

    Which is what `commit_entropy_` buys by hashing the committed value
    before it enters the derivation: the device can reach the nonce
    knowing only a hash of rho, so it can publish R before rho is
    revealed. Upstream's two columns are one host commitment apart and
    say so in their own bytes -- the R derived from
    `anti_exfil_host_commit(rho)` is the receipt of the sign-to-contract
    signature over rho.
    """
    commitment = dsa.anti_exfil_host_commit(rho)
    # the raw data is not the commitment, or the two columns would agree
    assert commitment.hex() != rho
    assert (
        bytes_from_point(
            dsa.anti_exfil_signer_commit(_MSG_HASH, _PRV_KEY, rho), secp256k1
        ).hex()
        == exfil_opening
    )

    R = dsa.anti_exfil_signer_commit(_MSG_HASH, _PRV_KEY, commitment)
    assert bytes_from_point(R, secp256k1).hex() == opening

    sig, receipt = dsa.sign_(_MSG_HASH, _PRV_KEY, commit_hash=rho)
    assert receipt == R
    assert dsa.anti_exfil_sign(_MSG_HASH, _PRV_KEY, rho) == sig
    assert dsa.anti_exfil_host_verify(_MSG_HASH, _PUB_KEY, sig, rho, R)


def test_the_whole_handshake() -> None:
    """The five steps, in order, and then what each of them refuses."""
    # 1. the host draws rho and commits to it
    commitment = dsa.anti_exfil_host_commit(_RHO)
    # 2. the device answers with the point its nonce will have
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    # 3. the host reveals rho
    # 4. the device signs, committing to it
    sig = dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, _RHO)
    # 5. the host checks the signature against that R and its own rho
    assert dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _RHO, R)

    # an ordinary ECDSA signature, which is the whole point: nothing on
    # the chain says the nonce was negotiated
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig)
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig.serialize())

    # not against another message, another rho, or another R
    assert not dsa.anti_exfil_host_verify(
        sha256(b"another message").digest(), _PUB_KEY, sig, _RHO, R
    )
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _OTHER_RHO, R
    )
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH,
        _PUB_KEY,
        sig,
        _RHO,
        secp256k1.add(R, secp256k1.G),
    )

    # lower_s defaults to True here too: the malleated twin shares r, so
    # the commitment check alone would still open, and only the default
    # refuses it
    malleated = dsa.Sig(sig.r, sig.ec.n - sig.s)
    assert dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, malleated, _RHO, R, lower_s=False
    )
    assert not dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, malleated, _RHO, R
    )


def test_the_signer_keeps_no_state() -> None:
    """A rho that does not match the commitment fails step 5, and only that.

    The device does not remember the commitment it answered step 2 with,
    and does not have to: it re-derives one from whatever rho arrives.
    A host that reveals something else gets a valid signature over an R
    that is not the R it holds, so step 5 says no -- and because that R
    belonged to the commitment it came from, no nonce was reused and the
    key was never what was at stake.
    """
    commitment = dsa.anti_exfil_host_commit(_RHO)
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)

    # step 3 reveals the wrong value; step 4 signs it all the same
    sig = dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, _OTHER_RHO)
    assert dsa.verify_(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig)
    assert not dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _RHO, R)

    # and what it does open under is the R of the rho it was given, a
    # point the host never saw
    other_R = dsa.anti_exfil_signer_commit(
        _HANDSHAKE_MSG_HASH, _PRV_KEY, dsa.anti_exfil_host_commit(_OTHER_RHO)
    )
    assert other_R != R
    assert dsa.anti_exfil_host_verify(
        _HANDSHAKE_MSG_HASH, _PUB_KEY, sig, _OTHER_RHO, other_R
    )


def test_a_restart_takes_the_same_rho() -> None:
    """Step 2 is a function of its arguments, so the host's check bites.

    Restarting with the same rho must reach the same R, or the host has
    nothing to compare and a device could bias the nonces it lets
    through by aborting selectively. Restarting with a fresh rho reaches
    a different R, which is why the protocol asks for the old one.
    """
    commitment = dsa.anti_exfil_host_commit(_RHO)
    assert dsa.anti_exfil_host_commit(_RHO) == commitment
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    assert dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment) == R

    redrawn = dsa.anti_exfil_host_commit(_OTHER_RHO)
    assert redrawn != commitment
    assert dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, redrawn) != R


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
        dsa.anti_exfil_host_commit(short)
    with pytest.raises(BTClibValueError, match="invalid size"):
        dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, short)
    with pytest.raises(BTClibValueError, match="invalid size"):
        dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, short)

    commitment = dsa.anti_exfil_host_commit(_RHO)
    R = dsa.anti_exfil_signer_commit(_HANDSHAKE_MSG_HASH, _PRV_KEY, commitment)
    sig = dsa.anti_exfil_sign(_HANDSHAKE_MSG_HASH, _PRV_KEY, _RHO)
    assert not dsa.anti_exfil_host_verify(_HANDSHAKE_MSG_HASH, _PUB_KEY, sig, short, R)

    # hf is the one that says what the sizes are, all the way through:
    # the 20 bytes below reach step 5 and the 32 above would not, each
    # step measuring against the hf it was handed
    msg_hash = sha1(b"to be signed").digest()  # noqa: S324
    rho = sha1(b"the host's randomness").digest()  # noqa: S324
    commitment = dsa.anti_exfil_host_commit(rho, sha1)
    with pytest.raises(BTClibValueError, match="invalid size"):
        dsa.anti_exfil_signer_commit(msg_hash, _PRV_KEY, _RHO, secp256k1, sha1)
    R = dsa.anti_exfil_signer_commit(msg_hash, _PRV_KEY, commitment, secp256k1, sha1)
    sig = dsa.anti_exfil_sign(msg_hash, _PRV_KEY, rho, True, secp256k1, sha1)
    assert dsa.anti_exfil_host_verify(msg_hash, _PUB_KEY, sig, rho, R, True, sha1)
