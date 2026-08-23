# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The conformance checks, against signers built to break each one.

`SoftwareSigner` passing is one half of the evidence and the weaker
half: a checker that never refuses passes everything. So each check has
a signer here that breaks exactly it and nothing else, wrapping the
conforming one, which is what says the check is the thing that fired.
"""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

import pytest
from typing_extensions import override

from btclib.bip32.bip32 import derive
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.mnemonic import bip39
from btclib.psbt.psbt import Psbt
from btclib.psbt_signer import PsbtSigner, SignerCapabilities, SoftwareSigner
from btclib.psbt_signer_contract import (
    _SOMEBODY_ELSES_KEY,
    assert_psbt_signer,
    optional_protocols,
    unsignable_psbt,
)
from btclib.script import serialize, sig_hash
from btclib.script.script_pub_key import ScriptPubKey
from btclib.to_pub_key import pub_keyinfo_from_key
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut

if TYPE_CHECKING:
    from btclib.bip32.der_path import DerPath

_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
_ACCOUNT = "m/84h/0h/0h"


def _signer() -> SoftwareSigner:
    """Return the reference signer every check is expected to pass."""
    return SoftwareSigner(bip39.mxprv_from_mnemonic(_MNEMONIC, "", "mainnet"))


class _Wrapper:
    """A signer that forwards everything, so a subclass breaks one thing."""

    def __init__(self) -> None:
        self._signer = _signer()

    @property
    def master_fingerprint(self) -> bytes:
        return self._signer.master_fingerprint

    def xpub(self, der_path: DerPath) -> str:
        return self._signer.xpub(der_path)

    def sign_psbt(self, psbt: Psbt) -> Psbt:
        return self._signer.sign_psbt(psbt)

    @property
    def capabilities(self) -> SignerCapabilities:
        return self._signer.capabilities

    def close(self) -> None:
        self._signer.close()


def _signable() -> Psbt:
    """Return a psbt the reference signer holds the key of one input of."""
    signer = _signer()
    xprv = derive(
        bip39.mxprv_from_mnemonic(_MNEMONIC, "", "mainnet"), f"{_ACCOUNT}/0/0"
    )
    pub_key = pub_keyinfo_from_key(xprv)[0]
    script_pub_key = ScriptPubKey.p2wpkh(pub_key)

    tx_in = TxIn(OutPoint(b"\xbb" * 32, 0))
    tx_out = TxOut(9_000, script_pub_key)
    psbt = Psbt.from_tx(Tx(version=2, lock_time=0, vin=[tx_in], vout=[tx_out]))
    psbt_in = psbt.inputs[0]
    psbt_in.witness_utxo = TxOut(10_000, script_pub_key)
    psbt_in.hd_key_paths[pub_key] = BIP32KeyOrigin(
        signer.master_fingerprint, f"{_ACCOUNT}/0/0"
    )
    return psbt


def test_the_reference_signer_conforms() -> None:
    """What the checks are calibrated against."""
    assert_psbt_signer(_signer(), der_path=_ACCOUNT, signable=_signable())


def test_the_optional_protocols_are_reported() -> None:
    """SoftwareSigner offers both; a signer of the four methods, neither."""
    assert optional_protocols(_signer()) == (True, True)
    assert optional_protocols(_Wrapper()) == (False, False)


def test_something_that_is_not_a_signer_is_refused() -> None:
    """The one check a caller cannot make with a type annotation."""
    with pytest.raises(BTClibValueError, match="does not implement PsbtSigner"):
        assert_psbt_signer(object())


def test_a_fingerprint_of_the_wrong_width_is_refused() -> None:
    """Four bytes is BIP32's own, and every key origin is written to it."""

    class _TooLong(_Wrapper):
        @property
        @override
        def master_fingerprint(self) -> bytes:
            return b"\x00" * 5

    with pytest.raises(BTClibValueError, match="is 5 bytes, not 4"):
        assert_psbt_signer(_TooLong())

    # and short of it, which a width checked as a ceiling would accept: a
    # three-byte fingerprint is what a key origin would then be written to
    class _TooShort(_Wrapper):
        @property
        @override
        def master_fingerprint(self) -> bytes:
            return b"\x00" * 3

    with pytest.raises(BTClibValueError, match="is 3 bytes, not 4"):
        assert_psbt_signer(_TooShort())


def test_a_fingerprint_that_changes_is_refused() -> None:
    """A signer answers for one master, so the answer is one answer."""

    class _Drifting(_Wrapper):
        def __init__(self) -> None:
            super().__init__()
            self._asked = 0

        @property
        @override
        def master_fingerprint(self) -> bytes:
            self._asked += 1
            return bytes([self._asked, 0, 0, 0])

    with pytest.raises(BTClibValueError, match="two different values"):
        assert_psbt_signer(_Drifting())

    # drifting the other way, which is the same disagreement: what the
    # check asks is whether the two answers are one answer, and an
    # ordering would ask which of them is larger
    class _Receding(_Wrapper):
        def __init__(self) -> None:
            super().__init__()
            self._asked = 4

        @property
        @override
        def master_fingerprint(self) -> bytes:
            self._asked -= 1
            return bytes([self._asked, 0, 0, 0])

    with pytest.raises(BTClibValueError, match="two different values"):
        assert_psbt_signer(_Receding())


def test_an_xpub_that_is_not_an_extended_key_is_refused() -> None:
    """A string is a string: that it spells a key is not a type."""

    class _Nonsense(_Wrapper):
        @override
        def xpub(self, der_path: DerPath) -> str:
            return "not a key at all"

    with pytest.raises(BTClibValueError, match="not an extended key"):
        assert_psbt_signer(_Nonsense(), der_path=_ACCOUNT)


def test_an_xpub_that_is_private_is_refused() -> None:
    """The one answer that is not merely wrong."""

    class _Leaking(_Wrapper):
        @override
        def xpub(self, der_path: DerPath) -> str:
            return derive(bip39.mxprv_from_mnemonic(_MNEMONIC, "", "mainnet"), der_path)

    with pytest.raises(BTClibValueError, match="answered a private key"):
        assert_psbt_signer(_Leaking(), der_path=_ACCOUNT)


def test_an_xpub_that_changes_is_refused() -> None:
    """One path is one key, or the descriptors built from it are fiction."""

    class _Drifting(_Wrapper):
        def __init__(self) -> None:
            super().__init__()
            self._asked = 0

        @override
        def xpub(self, der_path: DerPath) -> str:
            self._asked += 1
            return self._signer.xpub(f"m/84h/0h/{self._asked}h")

    with pytest.raises(BTClibValueError, match="two different keys"):
        assert_psbt_signer(_Drifting(), der_path=_ACCOUNT)

    # and the two keys the other way round: whichever of the two base58
    # strings sorts first, they are two keys for one path
    class _Receding(_Wrapper):
        def __init__(self) -> None:
            super().__init__()
            self._asked = 4

        @override
        def xpub(self, der_path: DerPath) -> str:
            self._asked -= 1
            return self._signer.xpub(f"m/84h/0h/{self._asked}h")

    with pytest.raises(BTClibValueError, match="two different keys"):
        assert_psbt_signer(_Receding(), der_path=_ACCOUNT)


def test_signing_an_input_of_another_master_is_refused() -> None:
    """The check that needs a signature to be real, so it makes one.

    The key of the unsignable input is the generator point, whose
    private key is 1 and is therefore available to a test: a rogue
    signer can produce a signature that verifies, which is what it takes
    to reach the check rather than being stopped by
    `request_signatures`.
    """

    class _Rogue(_Wrapper):
        @override
        def sign_psbt(self, psbt: Psbt) -> Psbt:
            answer = deepcopy(psbt)
            psbt_in = answer.inputs[0]
            assert psbt_in.witness_utxo is not None
            msg_hash = sig_hash.from_tx(
                [psbt_in.witness_utxo], answer.tx, 0, sig_hash.ALL
            )
            signature = dsa.sign_(msg_hash, 1).serialize() + b"\x01"
            psbt_in.partial_sigs[_SOMEBODY_ELSES_KEY] = signature
            return answer

    with pytest.raises(BTClibValueError, match="names another master"):
        assert_psbt_signer(_Rogue())


def test_a_signer_that_signs_nothing_it_was_said_to_sign_is_refused() -> None:
    """The end-to-end half: the caller says it can, so it has to."""

    class _Idle(_Wrapper):
        @override
        def sign_psbt(self, psbt: Psbt) -> Psbt:
            return deepcopy(psbt)

    with pytest.raises(BTClibValueError, match="added no signature"):
        assert_psbt_signer(_Idle(), signable=_signable())


def test_the_unsignable_psbt_names_another_master() -> None:
    """What the psbt is for, said against the psbt itself."""
    fingerprint = _signer().master_fingerprint
    psbt = unsignable_psbt(fingerprint)
    ((_, origin),) = psbt.inputs[0].hd_key_paths.items()
    assert origin.master_fingerprint != fingerprint
    assert origin.master_fingerprint[1:] == fingerprint[1:]


def test_a_conforming_signer_is_closed_twice() -> None:
    """`close` is documented idempotent, so the checks close twice."""
    closed = 0

    class _Counting(_Wrapper):
        @override
        def close(self) -> None:
            nonlocal closed
            closed += 1
            super().close()

    # the forwarding wrapper answers every question here, which is what
    # says the checks pass for a signer that is not SoftwareSigner itself
    assert_psbt_signer(_Counting(), der_path=_ACCOUNT)
    assert closed == 2


def test_the_wrapper_is_a_signer() -> None:
    """The stand-in every broken signer builds on has to be one itself."""
    assert isinstance(_Wrapper(), PsbtSigner)


def test_something_that_is_not_a_psbt_is_refused() -> None:
    """`signable` is checked rather than assumed, being typed `object`."""
    with pytest.raises(BTClibValueError, match="is str, not a Psbt"):
        assert_psbt_signer(_signer(), signable="not a psbt")


def test_capabilities_that_change_are_refused() -> None:
    """A caller acts on the first answer for the rest of the session."""

    class _Drifting(_Wrapper):
        def __init__(self) -> None:
            super().__init__()
            self._asked = 0

        @property
        @override
        def capabilities(self) -> SignerCapabilities:
            self._asked += 1
            return SignerCapabilities(taproot=self._asked % 2 == 0)

    with pytest.raises(BTClibValueError, match="capabilities answered two"):
        assert_psbt_signer(_Drifting())


# two more seeds, so a quorum can hold a signature that is not the
# reference signer's: BIP39's own second and third test vectors
_OTHER_MNEMONICS = (
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
)


def _partly_signed_quorum() -> Psbt:
    """Return a 3-of-3 the reference signer holds one key of, two signed.

    What `_signable` cannot be and what the count in `_check_signable`
    needs: a psbt whose input already carries signatures. With none there
    the sum it computes is `1 - 0`, and every arithmetic operator agrees
    on that -- so the check reads as though it were counting when nothing
    says it is.
    """
    root = bip39.mxprv_from_mnemonic(_MNEMONIC, "", "mainnet")
    roots = [
        root,
        *(bip39.mxprv_from_mnemonic(m, "", "mainnet") for m in _OTHER_MNEMONICS),
    ]
    keys = [pub_keyinfo_from_key(derive(r, f"{_ACCOUNT}/0/0"))[0] for r in roots]
    witness_script = serialize(["OP_3", *keys, "OP_3", "OP_CHECKMULTISIG"])
    script_pub_key = ScriptPubKey.p2wsh(witness_script)

    tx_in = TxIn(OutPoint(b"\xcc" * 32, 0))
    tx_out = TxOut(9_000, script_pub_key)
    psbt = Psbt.from_tx(Tx(version=2, lock_time=0, vin=[tx_in], vout=[tx_out]))
    psbt_in = psbt.inputs[0]
    psbt_in.witness_utxo = TxOut(10_000, script_pub_key)
    psbt_in.witness_script = witness_script
    for key, one in zip(keys, roots, strict=True):
        psbt_in.hd_key_paths[key] = BIP32KeyOrigin(
            SoftwareSigner(one).master_fingerprint, f"{_ACCOUNT}/0/0"
        )

    # the other two sign first, which is what leaves the reference signer
    # one signature to add rather than the only one
    for one in roots[1:]:
        psbt = SoftwareSigner(one).sign_psbt(psbt)
    assert len(psbt.inputs[0].partial_sigs) == 2
    return psbt


def test_a_quorum_the_signer_adds_one_signature_to_is_accepted() -> None:
    """The check counts, and counting is what a psbt with signatures asks.

    Two of the three are there before the signer is called, so what
    `_check_signable` compares is 3 against 2 rather than 1 against
    nothing -- and a sum that is right for the second is not necessarily
    right for the first.
    """
    assert_psbt_signer(_signer(), der_path=_ACCOUNT, signable=_partly_signed_quorum())


def test_a_signer_that_adds_nothing_to_a_signed_quorum_is_refused() -> None:
    """Handing back a psbt untouched is abstaining, whatever is in it.

    The same `_Idle` signer as above, over a psbt that already holds two
    signatures: the answer has as many as the request, so nothing was
    added, and the count has to say so rather than answering with what is
    there.
    """

    class _Idle(_Wrapper):
        @override
        def sign_psbt(self, psbt: Psbt) -> Psbt:
            return deepcopy(psbt)

    with pytest.raises(BTClibValueError, match="added no signature"):
        assert_psbt_signer(_Idle(), signable=_partly_signed_quorum())
