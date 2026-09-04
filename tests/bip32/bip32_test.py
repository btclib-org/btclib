# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.bip32` module."""

import hmac
import itertools
import re
from dataclasses import FrozenInstanceError, fields, replace
from typing import Any

import pytest

from btclib import base58
from btclib._libsecp256k1 import keys as libsecp256k1_keys
from btclib.b58 import p2pkh
from btclib.bip32 import (
    BIP328_CHAIN_CODE,
    BIP32Key,
    BIP32KeyData,
    # the module, not only the names in it: `libsecp256k1_keys` is a
    # module attribute, and putting it out of reach is how
    # no_bindings_bip32 below proves the Python arm asked nothing of it
    bip32,
    crack_prv_key_var,
    derive,
    derive_,
    derive_from_account,
    derive_from_account_,
    derive_from_account_range,
    derive_from_account_range_,
    fingerprint,
    point_from_xpub,
    prv_keyinfo_from_xprv,
    pub_key_derivation_tweaks,
    pub_keyinfo_from_xkey,
    pub_keyinfo_from_xpub,
    rootxprv_from_seed,
    rootxprv_from_seed_,
    xpub_from_xprv,
    xpub_from_xprv_,
)
from btclib.bip32.bip32 import (
    _BIP32KeyData,
    _derive,
    _pub_key_tweak_chain,
    _PythonPubKeyTweakChain,
)
from btclib.bip32.der_path import _indexes_from_der_path_str
from btclib.curves import (
    bytes_from_point,
    bytes_from_prv_key_int,
    # the module: `mod_sqrt_var` is a function on it, and patching it to
    # raise is how the test below pins that validating an xpub takes no
    # modular square root
    curve_group,
    mult,
    point_from_octets,
)
from btclib.curves import secp256k1 as ec
from btclib.ecc.musig2 import key_agg
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS
from tests import load, needs_bindings, replace_unchecked, vector_id
from tests.curves.curve_test import no_bindings, no_bindings_anywhere


def _p2pkh_of(xkey: BIP32Key) -> str:
    """Return the p2pkh address of an extended key, whichever half it is.

    The composition `bip44` performs, spelled here because an address
    builder takes a public key and no extended key (issue #1188): what
    an xprv and its xpub both derive to is one public key, so both
    spellings answer one address. The network travels with it, the key's
    version bytes being where it is stated and the SEC octets carrying
    no network at all.
    """
    sec, network = pub_keyinfo_from_xkey(xkey)
    return p2pkh(sec, network)


def test_the_three_key_reads_answer_for_one_half_each() -> None:
    """Each names the half it reads, and refuses the other.

    The reads a caller reaches for now that no converter resolves an
    extended key (issue #1188): the scalar of an xprv, the SEC octets of
    an xpub, the point of an xpub, and the SEC octets of either half.
    `network` and `compressed` are consistency checks throughout, an
    extended key stating both in its version bytes.
    """
    xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xpub = xpub_from_xprv(xprv)

    q, network, compressed = prv_keyinfo_from_xprv(xprv)
    assert (network, compressed) == ("mainnet", True)
    assert prv_keyinfo_from_xprv(xprv, "mainnet") == (q, "mainnet", True)
    assert pub_keyinfo_from_xpub(xpub) == pub_keyinfo_from_xkey(xpub)
    assert pub_keyinfo_from_xkey(xprv) == pub_keyinfo_from_xkey(xpub)
    assert point_from_xpub(xpub) == mult(q)

    # a BIP32 key is always compressed, so uncompressed is another format
    err_msg = "uncompressed SEC / compressed BIP32 mismatch"
    with pytest.raises(BTClibValueError, match=err_msg):
        prv_keyinfo_from_xprv(xprv, compressed=False)
    with pytest.raises(BTClibValueError, match="ompressed SEC / compressed BIP32"):
        pub_keyinfo_from_xpub(xpub, compressed=False)

    # the version bytes say which network claims the key, so a network
    # the caller names has to be that one
    with pytest.raises(BTClibValueError, match="not a testnet key: version "):
        prv_keyinfo_from_xprv(xprv, "testnet")
    with pytest.raises(BTClibValueError, match="Not a testnet key: version "):
        pub_keyinfo_from_xpub(xpub, "testnet")

    # and each public read refuses the private half by its prefix
    with pytest.raises(BTClibValueError, match="not a public key: prefix 0x00"):
        pub_keyinfo_from_xpub(xprv)
    with pytest.raises(BTClibValueError, match="not a public key: prefix 0x00"):
        point_from_xpub(xprv)


def test_exceptions() -> None:
    """Refuse a bad checksum, a public key, and seeds of the wrong size."""
    with pytest.raises(BTClibValueError, match="invalid checksum: "):
        # invalid checksum
        xprv = "xppp9s21ZrQH143K2oxHiQ5f7D7WYgXD9h6HAXDBuMoozDGGiYHWsq7TLBj2yvGuHTLSPCaFmUyN1v3fJRiY2A4YuNSrqQMPVLZKt76goL6LP7L"
        pub_keyinfo_from_xkey(xprv)

    with pytest.raises(BTClibValueError, match="not a private key"):
        xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
        xpub_from_xprv(xpub)

    seed = "5b56c417303faa3fcba7e57400e120a0"
    with pytest.raises(BTClibValueError, match="unknown extended key version: "):
        version = b"\x04\x88\xad\xe5"
        rootxprv_from_seed(seed, version)

    with pytest.raises(BTClibValueError, match="too many bits for seed: "):
        rootxprv_from_seed(seed * 5)

    with pytest.raises(BTClibValueError, match="too few bits for seed: "):
        rootxprv_from_seed(seed[:-2])

    # both boundaries themselves, not only past them: seeds come in whole
    # bytes, so bit_length is always a multiple of 8, and every value a
    # `< 128`/`> 512` neighbor would treat differently from `< 127`/`>
    # 513` is one no byte-sized seed can ever reach
    assert rootxprv_from_seed("00" * 16)
    assert rootxprv_from_seed("00" * 64)


def test_an_xkey_decodes_however_its_text_is_held() -> None:
    """`b58decode` takes a String, and a String is text or any buffer.

    They used to be refused outright, with "invalid base58 string type:
    bytearray", by a check written against the narrower `String` -- and
    written there rather than left to `base58.decode` for a reason the
    widening does not remove: the `lru_cache` in front of the decoding
    keys on the argument, a bytearray cannot key one at all, and a
    memoryview of one raises `ValueError: cannot hash writable
    memoryview object`. Copied for the cache before the lookup, so each
    spelling decodes to what the text decodes to (issue #1238).
    """
    xkey = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
    expected = BIP32KeyData.b58decode(xkey)
    octets = xkey.encode("ascii")
    for spelling in (octets, bytearray(octets), memoryview(octets)):
        assert BIP32KeyData.b58decode(spelling) == expected


def test_bip32keydata_is_still_a_dataclass() -> None:
    """Frozen trades the hand-written __init__ for object.__setattr__.

    The same shape `test_dsa_sig_is_still_a_dataclass` checks for the
    three `Sig` classes (issue 727): what `dataclasses` generates around
    a written-out `__init__` is what is left to check once the
    generated one is gone, and it must not go missing too.
    """
    xkey = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
    xkey_data = BIP32KeyData.b58decode(xkey)

    assert [f.name for f in fields(xkey_data)] == [
        "version",
        "depth",
        "parent_fingerprint",
        "index",
        "chain_code",
        "key",
    ]
    assert xkey_data == BIP32KeyData.b58decode(xkey)
    assert hash(xkey_data) == hash(BIP32KeyData.b58decode(xkey))
    assert replace(xkey_data, index=xkey_data.index) == xkey_data
    assert "check_validity" not in repr(xkey_data)

    # frozen: the hand-written __init__ assigns through
    # object.__setattr__, which must not leave the class writable
    with pytest.raises(FrozenInstanceError):
        xkey_data.index = 1  # type: ignore[misc]


def test_assert_valid2() -> None:
    """Corrupt each BIP32KeyData field and check the error it raises.

    Frozen, so `object.__setattr__` and not a plain attribute write: a
    fixture built to fail `assert_valid` on purpose is the one reason to
    reach past the guard `__init__` puts there for everyone else.
    """
    xkey = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "version", xkey_data.version[:-1])
    with pytest.raises(BTClibValueError, match="invalid version length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "version", "1234")
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "depth", -1)
    with pytest.raises(BTClibValueError, match="invalid depth: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "depth", 256)
    with pytest.raises(BTClibValueError, match="invalid depth: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "depth", ())
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(
        xkey_data, "parent_fingerprint", xkey_data.parent_fingerprint[:-1]
    )
    with pytest.raises(BTClibValueError, match="invalid parent_fingerprint length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "parent_fingerprint", "1234")
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "index", -1)
    with pytest.raises(BTClibValueError, match="invalid index: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "index", 0xFFFFFFFF + 1)
    with pytest.raises(BTClibValueError, match="invalid index: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "index", ())
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "chain_code", xkey_data.chain_code[:-1])
    with pytest.raises(BTClibValueError, match="invalid chain_code length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "chain_code", "length is 32 but not a chaincode")
    assert len(xkey_data.chain_code) == 32
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "key", xkey_data.key[:-1])
    with pytest.raises(BTClibValueError, match="invalid key length: "):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "key", "length is 33, but not a key      ")
    assert len(xkey_data.key) == 33
    with pytest.raises(TypeError):
        xkey_data.assert_valid()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "parent_fingerprint", bytes.fromhex("deadbeef"))
    err_msg = "zero depth with non-zero parent fingerprint: "
    with pytest.raises(BTClibValueError, match=err_msg):
        xkey_data.b58encode()

    xkey_data = BIP32KeyData.b58decode(xkey)
    object.__setattr__(xkey_data, "index", 1)
    with pytest.raises(BTClibValueError, match="zero depth with non-zero index: "):
        xkey_data.b58encode()


def test_serialization() -> None:
    """Check b58decode's fields against the raw base58 byte layout."""
    xkey = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xkey_data = BIP32KeyData.b58decode(xkey)

    decoded_key = base58.decode(xkey, 78)
    assert xkey_data.version == decoded_key[:4]
    assert xkey_data.depth == decoded_key[4]
    assert xkey_data.parent_fingerprint == decoded_key[5:9]
    assert xkey_data.index == int.from_bytes(decoded_key[9:13], "big", signed=False)
    assert xkey_data.chain_code == decoded_key[13:45]
    assert xkey_data.key == decoded_key[45:]

    assert xkey_data.b58encode() == xkey

    xpub = xpub_from_xprv(xkey)
    xpub2 = xpub_from_xprv(xkey_data)
    assert xpub == xpub2


def no_bindings_bip32(monkeypatch: pytest.MonkeyPatch) -> None:
    """Switch the dispatch off, and bip32's own bindings out of reach.

    `no_bindings` clears `_libsecp256k1_available`, which is what every
    `_libsecp256k1_serves` in the package reads, so it is the whole
    dispatch and not one module's copy of a predicate. What it cannot
    show is that *this* module asked: bip32 imports `keys` as a module,
    and a stand-in refusing every name in it is the proof -- a derivation
    that still reaches libsecp256k1 fails here rather than quietly
    measuring the bindings against themselves.
    """

    class Refuse:
        def __getattr__(self, name: str) -> Any:
            # a green suite is one where this never runs, which is the
            # pragma curve_test.no_bindings carries for the same reason
            raise AssertionError(  # pragma: no cover
                f"the dispatch is switched off, and bip32 asked for {name}"
            )

    no_bindings(monkeypatch)
    monkeypatch.setattr(bip32, "libsecp256k1_keys", Refuse())


def bip32_vectors() -> list[Any]:
    """One case per derivation of BIP32 test vectors #1 to #4.

    The file groups the derivations by seed, and the seed is the id of
    the vector it belongs to: "vector 3, m/0h" rather than a number that
    says nothing, and a failing derivation does not silence the rest.
    """
    test_vectors = load("bip32", "_data", "bip32_test_vectors.json")
    return [
        pytest.param(
            seed, der_path, xpub, xprv, id=vector_id(index, seed[:16], der_path)
        )
        for index, seed in enumerate(test_vectors)
        for der_path, xpub, xprv in test_vectors[seed]
    ]


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
@pytest.mark.parametrize("seed, der_path, xpub, xprv", bip32_vectors())
def test_bip32_vectors(
    seed: str,
    der_path: str,
    xpub: str,
    xprv: str,
    bindings: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BIP32 test vectors #1, #2, #3, and #4.

    https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

    Both arms of the derivation, because BIP32 is what each of them
    answers to: `keys.prvkey_tweak_add` and `keys.PubkeyTweakChain` where
    the bindings are installed, and the two sums written out in Python
    where they are not. The vectors are the authority either way, so
    neither arm is checked against the other's answer here.
    """
    if not bindings:
        no_bindings_bip32(monkeypatch)

    mxprv = rootxprv_from_seed(seed)
    assert xprv == derive(mxprv, der_path)
    assert xpub == xpub_from_xprv(xprv)


@pytest.mark.parametrize(
    "xkey, err_msg",
    [
        pytest.param(xkey, err_msg, id=vector_id(index, err_msg))
        for index, (xkey, err_msg) in enumerate(
            load("bip32", "_data", "bip32_invalid_keys.json")
        )
    ],
)
def test_invalid_bip32_xkeys(xkey: str, err_msg: str) -> None:
    """BIP32 test vectors #5.

    https://github.com/bitcoin/bips/pull/921

    btclib is the upstream of these: that pull request is Ferdinando
    Ametrano's, and it landed the day the file was vendored. The 16 keys
    are the BIP's; the second column is btclib's own, holding btclib error
    messages the BIP does not and should not carry, so a refresh from
    upstream refreshes the keys and never the messages.
    tests/_data/README.md pins the revision.
    """
    with pytest.raises(BTClibValueError, match=re.escape(err_msg)):
        BIP32KeyData.b58decode(xkey)


@needs_bindings
def test_public_key_validation_does_not_lift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validating an extended public key asks for existence, not for y.

    The y computed to validate an xpub was thrown away, and the modular
    square root that found it was paid once per extended key -- so by
    every level of every derivation path (issue 615). What pins the
    predicate in place of the lift is reaching no square root at all,
    not a stopwatch: mod_sqrt_var is patched to raise, and the accepted key
    and the refused one both have to get their answer without it.
    """

    def refuse(*_: object) -> int:
        # a green suite is one where this never runs, which is the pragma
        # curve_test.no_bindings carries for the same reason
        raise AssertionError(  # pragma: no cover
            "the y of an extended public key was computed"
        )

    monkeypatch.setattr(curve_group, "mod_sqrt_var", refuse)

    xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    assert BIP32KeyData.b58decode(xpub).b58encode() == xpub
    assert derive(xpub, "m/0/1")

    # 0x02 || 7, the x of no point: BIP32 test vector #5's "invalid
    # pubkey 0200...07", which bip32_invalid_keys.json carries in full
    decoded = base58.decode(xpub)
    bad_xpub = base58.encode(decoded[:45] + b"\x02" + (7).to_bytes(32, "big"), 78)
    err_msg = "invalid public key: 0x02000000"
    with pytest.raises(BTClibValueError, match=err_msg) as excinfo:
        BIP32KeyData.b58decode(bad_xpub)
    # a predicate has no exception to chain: the message is the whole error
    assert excinfo.value.__cause__ is None


@needs_bindings
def test_public_derivation_builds_no_point(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public derivation keeps the key serialized, end to end.

    `_BIP32KeyData` carries the intermediate results derivation reuses,
    and a cached point stopped being one of them when the arithmetic went
    to libsecp256k1: it was built for every public extended key, so at
    every level of every path, and read nowhere. What pins its removal is
    the shape of the calls rather than a stopwatch -- the class declares
    the one cache that is read, and the bindings are asked for the
    compressed spelling an extended key holds, not for the uncompressed
    one whose y went into that point. `PubkeyTweakChain.tweak_add` is
    where that ask is made, one call per level of the path, its own
    parsed point never surfacing above the bindings that hold it.
    """
    inherited = {field.name for field in fields(BIP32KeyData)}
    cached = [f.name for f in fields(_BIP32KeyData) if f.name not in inherited]
    assert cached == ["prv_key_int"]

    compressed_asked: list[bool] = []
    chain_tweak_add = libsecp256k1_keys.PubkeyTweakChain.tweak_add

    def record(chain: Any, tweak: Any, compressed: bool = True) -> bytes:
        compressed_asked.append(compressed)
        return chain_tweak_add(chain, tweak, compressed)

    monkeypatch.setattr(libsecp256k1_keys.PubkeyTweakChain, "tweak_add", record)

    xpub = BIP32KeyData.b58decode(
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    )
    parent = _derive(xpub, "m/0", None)
    compressed_asked.clear()
    child = _derive(xpub, "m/0/1", None)
    assert compressed_asked == [True, True]

    # and it is the same key: what the bindings compress is what the
    # parity of an uncompressed y used to be read off to rebuild
    (tweak,) = pub_key_derivation_tweaks(parent.key, parent.chain_code, "m/1")
    uncompressed = libsecp256k1_keys.pubkey_tweak_add(parent.key, tweak, False)
    assert child.key == bytes_from_point(point_from_octets(uncompressed))


def test_private_functions_do_not_validate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wrapper validates, the private function below it does not.

    `derive` validated the same extended key three times: on decoding
    it, on building the `_BIP32KeyData` out of the object it had just
    decoded, and on serializing the result (issue 633). Two of the three
    are the rule -- input validation at the boundary, and the check the
    wrapper makes on what it hands back -- and the third was the private
    function doing what a leading underscore says it does not.
    """
    validations = 0
    real = BIP32KeyData.assert_valid

    def counting(self: BIP32KeyData) -> None:
        nonlocal validations
        validations += 1
        real(self)

    monkeypatch.setattr(BIP32KeyData, "assert_valid", counting)

    xpub = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    derive(xpub, "m/0/1")
    assert validations == 2

    xpub_data = BIP32KeyData.b58decode(xpub)
    validations = 0
    _derive(xpub_data, "m/0/1", None)
    assert validations == 0

    # and the wrapper validates the object spelling too, which nothing
    # downstream would: `_derive` builds with `check_validity=False`
    validations = 0
    derive(xpub_data, "m/0/1")
    assert validations == 2


def test_derive_validates_before_it_changes_the_depth() -> None:
    """The depth-zero rule is about the key handed in, not the one built.

    It is the one check whose meaning depends on a field `_derive`
    rewrites: at the final depth of a two-index path, an index of 7 is
    no contradiction, so validating the key after that assignment would
    accept what `b58decode` refuses.
    """
    root_xpub = xpub_from_xprv(rootxprv_from_seed("5b56c417303faa3fcba7e57400e120a0"))
    raw = bytearray(base58.decode(root_xpub))
    assert raw[4] == 0  # depth
    raw[9:13] = (7).to_bytes(4, "big")  # a non-zero index at depth zero
    bad = base58.encode(bytes(raw), 78)

    err_msg = "zero depth with non-zero index: 7"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(bad, "m/0/1")
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(BIP32KeyData.b58decode(bad, check_validity=False), "m/0/1")


def test_derive() -> None:
    """Derive p2pkh addresses along paths in irregular spellings."""
    test_vectors = {
        "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS": [
            ["m / 0 h / 0 h / 463 h", "1DyfBWxhVLmrJ7keyiHeMbt7N3UdeGU4G5"],
            ["M / 0H / 0h // 267' / ", "11x2mn59Qy43DjisZWQGRResjyQmgthki"],
        ],
        "tprv8ZgxMBicQKsPe3g3HwF9xxTLiyc5tNyEtjhBBAk29YA3MTQUqULrmg7aj9qTKNfieuu2HryQ6tGVHse9x7ANFGs3f4HgypMc5nSSoxwf7TK": [
            ["m / 0 h / 0 h / 51 h", "mfXYCCsvWPgeCv8ZYGqcubpNLYy5nYHbbj"],
            ["m / 0 h / 1 h / 150 h", "mfaUnRFxVvf55uD1P3zWXpprN1EJcKcGrb"],
        ],
    }

    # `p2pkh` takes a public key and no extended key, so what is handed
    # to it is `pub_keyinfo_from_xkey` of the derived one (issue #1188)
    for rootxprv, value in test_vectors.items():
        for der_path, address in value:
            assert address == _p2pkh_of(derive(rootxprv, der_path))

            indexes = _indexes_from_der_path_str(der_path, True)
            assert address == _p2pkh_of(derive(rootxprv, indexes))

        assert derive(rootxprv, "m") == rootxprv


def test_derive_exceptions() -> None:
    """Refuse malformed paths, excess depth, and mismatched key prefixes."""
    # root key, zero depth
    rootmxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xprv = BIP32KeyData.b58decode(rootmxprv)
    # the empty path derives the key itself, both as the object _derive
    # hands back and as the string derive encodes it to
    assert xprv == _derive(xprv, "m", None)
    assert rootmxprv == derive(xprv, "m")
    assert rootmxprv == derive(xprv, "")

    fingerprint = hash160(pub_keyinfo_from_xkey(xprv)[0])[:4]
    assert (
        fingerprint == _derive(xprv, bytes.fromhex("80000000"), None).parent_fingerprint
    )

    for der_path in ("/1", "800000", "80000000"):
        xkey = _derive(xprv, der_path, None)
        assert fingerprint == xkey.parent_fingerprint

    err_msg = "invalid derivation index: "
    for der_path in (";/0", "invalid index"):
        with pytest.raises(BTClibValueError, match=err_msg):
            derive(xprv, der_path)

    with pytest.raises(BTClibValueError, match="depth greater than 255: "):
        derive(xprv, "m" + 256 * "/0")

    with pytest.raises(BTClibValueError, match="index are not a multiple of 4-bytes: "):
        derive(xprv, b"\x00" * 5)

    # an index no path step can hold, refused by the reader rather than
    # by the `to_bytes(4, signed=False)` that used to answer it with an
    # OverflowError -- an ArithmeticError, outside every `except
    # ValueError` a caller of this library writes
    for index in (2**32, 0x8000000000, -1):
        with pytest.raises(BTClibValueError, match="invalid index: "):
            derive(xprv, index)

    # the boundary itself, not only one past it: `> 255` weakened to
    # `>= 255` or to `> 254` would refuse the 255 the vector above stops
    # one short of
    assert derive(XKEY, "m" + 255 * "/0")

    xprv = _derive(xprv, "1", None)
    err_msg = "final depth greater than 255: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(xprv, "m" + 255 * "/0")

    rootxprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"

    temp = base58.decode(rootxprv)
    bad_xprv = base58.encode(temp[:45] + b"\x02" + temp[46:], 78)
    err_msg = "invalid private key prefix: "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(bad_xprv, 0x80000000)

    xpub = xpub_from_xprv(rootxprv)
    temp = base58.decode(xpub)
    bad_xpub = base58.encode(temp[:45] + b"\x00" + temp[46:], 78)
    err_msg = r"invalid public key prefix not in \(0x02, 0x03\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(bad_xpub, 0x80000000)

    err_msg = "hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(xpub, 0x80000000)


def test_derive_from_account() -> None:
    """Match account derivation to full paths; refuse bad branch or index."""
    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    rmxprv = rootxprv_from_seed(seed)

    der_path = "m / 44 h / 0 h"
    mxpub = xpub_from_xprv(derive(rmxprv, der_path))

    test_vectors = [
        [0, 0],
        [0, 1],
        [0, 2],
        [1, 0],
        [1, 1],
        [1, 2],
    ]

    for branch, index in test_vectors:
        full_path = f"{der_path}/{branch}/{index}"
        addr = _p2pkh_of(derive(rmxprv, full_path))
        assert addr == _p2pkh_of(derive_from_account(mxpub, branch, index))

    err_msg = "invalid private derivation at branch level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0x80000000, 0, True)

    err_msg = "invalid branch number: 65536"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0xFFFF + 1, 0, branches_0_1_only=False)

    err_msg = "invalid branch number: 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 2, 0)

    err_msg = "invalid private derivation at address index level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0x80000000, max_index=0xFFFFFFFF)

    err_msg = "invalid address index: 65536"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0xFFFF + 1)

    # max_index's own default, not one passed in: `0xffff` widened to
    # 65536 or narrowed to 65534 would move the boundary this vector
    # relies on being exactly 65535
    assert derive_from_account(mxpub, 0, 0xFFFF)

    # strictly above the offset, not only at it: `>= _HARDENED_OFFSET`
    # weakened to `==` would refuse only the exact boundary above, the
    # one 0x80000000 case already covers
    err_msg = "invalid private derivation at branch level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0x80000000 + 1, 0, True)

    err_msg = "invalid private derivation at address index level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0x80000000 + 1, max_index=0xFFFFFFFF)

    der_path = "m / 44 h / 0"
    mxpub = xpub_from_xprv(derive(rmxprv, der_path))
    err_msg = "unhardened account/master key"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account(mxpub, 0, 0)


def test_crack() -> None:
    """Recover a parent xprv from its xpub and a child xprv; refuse else."""
    parent_xpub = "xpub6BabMgRo8rKHfpAb8waRM5vj2AneD4kDMsJhm7jpBDHSJvrFAjHJHU5hM43YgsuJVUVHWacAcTsgnyRptfMdMP8b28LYfqGocGdKCFjhQMV"
    child_xprv = "xprv9xkG88dGyiurKbVbPH1kjdYrA8poBBBXa53RKuRGJXyruuoJUDd8e4m6poiz7rV8Z4NoM5AJNcPHN6aj8wRFt5CWvF8VPfQCrDUcLU5tcTm"
    parent_xprv = crack_prv_key_var(parent_xpub, child_xprv)
    assert xpub_from_xprv(parent_xprv) == parent_xpub
    # same check with XKeyDict
    parent_xprv = crack_prv_key_var(
        BIP32KeyData.b58decode(parent_xpub), BIP32KeyData.b58decode(child_xprv)
    )
    assert xpub_from_xprv(parent_xprv) == parent_xpub

    err_msg = "extended parent key is not a public key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key_var(parent_xprv, child_xprv)

    err_msg = "extended child key is not a private key: "
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key_var(parent_xpub, parent_xpub)

    child_xpub = xpub_from_xprv(child_xprv)
    with pytest.raises(BTClibValueError, match="not a parent's child: wrong depths"):
        crack_prv_key_var(child_xpub, child_xprv)

    child0_xprv = derive(parent_xprv, 0)
    grandchild_xprv = derive(child0_xprv, 0)
    err_msg = "not a parent's child: wrong parent fingerprint"
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key_var(child_xpub, grandchild_xprv)

    hardened_child_xprv = derive(parent_xprv, 0x80000000)
    with pytest.raises(BTClibValueError, match="hardened child derivation"):
        crack_prv_key_var(parent_xpub, hardened_child_xprv)


def test_bips_pr905() -> None:
    """Https://github.com/bitcoin/bips/pull/905."""
    seed = "57fb1e450b8afb95c62afbcd49e4100d6790e0822b8905608679180ac34ca0bd45bf7ccc6c5f5218236d0eb93afc78bd117b9f02a6b7df258ea182dfaef5aad7"
    xroot = rootxprv_from_seed(seed)
    der_path = "m/44H/60H/0H"
    xprv = "xprv9yqXG1Cns3YEQi6fsCJ7NGV5sHPiyZcbgLVst61dbLYyn7qy1G9aFtRmaYp481ounqnVf9Go2ymQ4gmxZLEwYSRhU868aDk4ZxzGvqHJVhe"
    assert derive(xroot, der_path) == xprv
    xpub = "xpub6CpsfWjghR6XdCB8yDq7jQRpRKEDP2LT3ZRUgURF9g5xevB7YoTpogkFRqq5nQtVSN8YCMZo2CD8u4zCaxRv85ctCWmzEi9gQ5DBhBFaTNo"
    assert xpub_from_xprv(xprv) == xpub


def test_pub_key_derivation() -> None:
    """Check a public child's parent fingerprint, zeroed for an orphan."""
    parent_xpub = "xpub6CpsfWjghR6XdCB8yDq7jQRpRKEDP2LT3ZRUgURF9g5xevB7YoTpogkFRqq5nQtVSN8YCMZo2CD8u4zCaxRv85ctCWmzEi9gQ5DBhBFaTNo"
    proper_child = "xpub6FCCuDg6j52SWRVZ1TugkjrnGkqPcDuNNKDzohU2mmd4dxiGJypZa535iqYT8KcN2oouRF7A6tXEGAX6HCSjQe7HVSDR4LQ4yUT3HwF1Tqi"
    assert derive(parent_xpub, "m/0") == proper_child
    parent_key = BIP32KeyData.b58decode(parent_xpub).key
    parent_fingerprint = hash160(parent_key)[:4]
    assert BIP32KeyData.b58decode(proper_child).parent_fingerprint == parent_fingerprint

    orphan_child_key = replace_unchecked(
        BIP32KeyData.b58decode(proper_child), parent_fingerprint=b"\x00" * 4
    )
    orphan_child = "xpub6DXuQW1FgeHbhsSchbuDWE9Bj8mPiPUpiroAmAvRdRqYbGHXHTyEkttkxSvtCac64QzpasL1Tvd5Znvn5GQMswQUrpRBsPRz7npvyZ8ExWi"
    assert orphan_child_key.b58encode() == orphan_child


def test_no_key_material_in_repr_or_exceptions() -> None:
    """Private key material must not reach reprs or exception messages.

    https://github.com/btclib-org/btclib/issues/137
    """
    xprv = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"
    xprv_data = BIP32KeyData.b58decode(xprv)

    # the dataclass-generated repr would print key and chain code
    for secret in (xprv_data.key, xprv_data.chain_code):
        assert secret.hex() not in repr(xprv_data)
        assert repr(secret) not in repr(xprv_data)
    # while the non-secret fields remain readable
    assert xprv_data.version.hex() in repr(xprv_data)

    # the derivation cache must not print the private scalar either
    prv_int = int.from_bytes(xprv_data.key, byteorder="big", signed=False)
    assert str(prv_int) not in repr(_derive(xprv_data, "m", None))

    # public material is not masked
    xpub_data = BIP32KeyData.b58decode(xpub_from_xprv(xprv))
    assert xpub_data.key.hex() in repr(xpub_data)
    assert xpub_data.chain_code.hex() in repr(xpub_data)

    # the seed must not reach the exception message
    seed = "5b56c417303faa3fcba7e57400e120"
    with pytest.raises(BTClibValueError, match="too few bits for seed: ") as excinfo:
        rootxprv_from_seed(seed)
    assert seed not in str(excinfo.value)

    # an xprv passed where an xpub is expected must not be echoed
    child_xprv = derive(xprv, "m/0")
    with pytest.raises(BTClibValueError, match="not a public key: ") as excinfo:
        crack_prv_key_var(xprv, child_xprv)
    assert xprv not in str(excinfo.value)


class _ForcedHmac:
    """An hmac whose digest is chosen rather than computed."""

    def __init__(self, digest: bytes) -> None:
        self._digest = digest

    def digest(self) -> bytes:
        return self._digest


def _force_hmac(monkeypatch: pytest.MonkeyPatch, il: int, chain_code: bytes) -> None:
    """Make every derivation see il as the left half of its hmac.

    The three children BIP32 calls invalid are unreachable at odds of
    about 2^-127, which is exactly why the branches rejecting them can
    only be tested by dictating the hmac. bip32 calls hmac.new through
    the module, so patching it there is what the derivation sees.
    """
    digest = il.to_bytes(32, byteorder="big", signed=False) + chain_code
    monkeypatch.setattr(hmac, "new", lambda *args, **kwargs: _ForcedHmac(digest))


def test_derivation_is_the_arithmetic_bip32_defines() -> None:
    """Both derivations, against the scalar and point arithmetic in Python.

    libsecp256k1 adds the offset to the key, privately and publicly, and
    what holds that delegation to BIP32's own equations is having them
    here -- `ki = parse256(IL) + kpar (mod n)` and `Ki =
    point(parse256(IL)) + Kpar` -- written out over the same hmac the
    derivation takes, and the shipped vectors for the rest.

    Written out here and not read out of the library's own Python arm,
    which is the same two equations and would be checking a copy against
    itself. That arm is checked where it has an authority to answer to:
    `test_bip32_vectors[python]`.
    """
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    parent = BIP32KeyData.b58decode(rootxprv)
    index = 42
    parent_prv_key = int.from_bytes(parent.key[1:], byteorder="big", signed=False)
    parent_pub_key = bytes_from_prv_key_int(parent_prv_key)

    hmac_ = hmac.new(
        parent.chain_code,
        parent_pub_key + index.to_bytes(4, byteorder="big", signed=False),
        "sha512",
    ).digest()
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)

    child_prv_key = (parent_prv_key + offset) % ec.n
    child = BIP32KeyData.b58decode(derive(rootxprv, f"m/{index}"))
    assert child.chain_code == hmac_[32:]
    assert child.key == b"\x00" + child_prv_key.to_bytes(
        32, byteorder="big", signed=False
    )

    child_pub_key_point = ec.add_var(point_from_octets(parent_pub_key), mult(offset))
    child_pub = BIP32KeyData.b58decode(derive(xpub_from_xprv(rootxprv), f"m/{index}"))
    assert child_pub.chain_code == hmac_[32:]
    assert child_pub.key == bytes_from_point(child_pub_key_point)
    # and the two derivations of one index meet, as BIP32 requires
    assert child_pub.key == bytes_from_prv_key_int(child_prv_key)


@needs_bindings
def test_the_py_arm_reaches_no_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Python arm must be Python throughout, or it has no reason to be.

    A mixed arm is the one shape that is never right: with libsecp256k1
    in reach `keys.PubkeyTweakChain` and `keys.prvkey_tweak_add` are the
    better calls, and out of reach there is nothing to mix. So the arm
    holds no call that could delegate -- which today it does not by
    construction, `mult` and the lift under `point_from_octets` gating on
    `_libsecp256k1_serves(secp256k1, None)`, the very call that chose the
    arm. Construction is a thing to check rather than to trust, and a
    per-operation dispatch would end it without touching this file.

    `no_bindings_anywhere` is the check, generic to any arm of this shape:
    it puts the whole of btclib_secp256k1 out of reach, which takes both
    halves -- the package's own callables, for a caller holding the module
    and reaching through it as bip32 does, and every name btclib has
    already bound from it, `from ... import x as y` having copied the
    object rather than looked it up again -- and switches the dispatch
    off.

    Not the same thing as `no_bindings_bip32` below, which switches the
    dispatch off and refuses bip32's own module: this refuses what every
    layer beneath it would have called too.
    """
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    rootxpub = xpub_from_xprv(rootxprv)
    xpub = BIP32KeyData.b58decode(rootxpub)
    # what the bindings answer, taken while they are still in reach
    delegated = (
        derive(rootxprv, "m/0h/1/2h"),
        derive(rootxpub, "m/1/2"),
        pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1/2"),
    )

    no_bindings_anywhere(monkeypatch)

    # the two bip32 itself would have called, so that a walk reaching
    # nothing would fail here rather than pass by touching nothing
    with pytest.raises(AssertionError, match="reached libsecp256k1"):
        libsecp256k1_keys.prvkey_tweak_add(b"\x01" * 32, b"\x02" * 32)
    with pytest.raises(AssertionError, match="reached libsecp256k1"):
        libsecp256k1_keys.PubkeyTweakChain(b"\x02" + b"\x01" * 32)

    assert (
        derive(rootxprv, "m/0h/1/2h"),
        derive(rootxpub, "m/1/2"),
        pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1/2"),
    ) == delegated


@needs_bindings
def test_the_py_arm_answers_what_the_primitive_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each arm of the two sums, against the call the other one makes.

    The bindings are the authority on the answer here as everywhere else
    the library keeps a Python path. `_pub_key_tweak_chain` answers one
    secp256k1_ec_pubkey_tweak_add per step where they serve and
    `add_var(P, mult(t))` where they do not, so the two are asserted step
    by step over a spread of parent keys and tweaks; the private sum is
    `keys.prvkey_tweak_add` against `(kpar + IL) % n` over the same
    spread.

    Successive steps rather than one apiece, the chain's whole point
    being that a step starts from what the last one answered: an arm that
    dropped the walk would still pass a one-step comparison.

    The spread holds what a derivation's own tweaks never will, those
    being hmac output: a zero tweak, which libsecp256k1's header says it
    answers with the key unchanged; a tweak of n-1; and the two sums it
    declines, the zero child and the child at infinity.
    """
    keys = [bytes_from_prv_key_int(q) for q in (1, 2, 7, ec.n // 2, ec.n - 1)]
    tweaks = [0, 1, 2, 7, ec.n // 2, ec.n - 1]

    def walk(key: bytes) -> list[bytes | str]:
        """Step through the tweaks, stopping where the chain refuses."""
        chain = _pub_key_tweak_chain(key)
        steps: list[bytes | str] = []
        for t in tweaks:
            try:
                steps.append(
                    chain.tweak_add(t.to_bytes(32, byteorder="big", signed=False))
                )
            except ValueError:
                # a refused step ends the chain, so what the arms have to
                # agree on is where it happened and not what comes after:
                # n-1 tweaked by 1 is the sum at infinity, and this walk
                # is the one caller that reaches it
                steps.append("refused")
                break
        return steps

    delegated = [walk(key) for key in keys]
    assert any("refused" in steps for steps in delegated)
    with monkeypatch.context() as no_c:
        no_bindings_bip32(no_c)
        assert [walk(key) for key in keys] == delegated

    # the sum neither implementation has an answer for, and both refuse
    # by raising what the callers turn into BIP32's invalid children.
    #
    # The Python one is matched on its message, which is what makes its
    # guard load-bearing: `bytes_from_point` refuses infinity too, with a
    # BTClibValueError of its own, so deleting the guard leaves the type
    # of the exception and every other assertion in this file untouched
    # -- and leaves `pub_key_derivation_tweaks`, which does not wrap this
    # loop, telling its caller about a serialization it never asked for
    for q in (1, 2, 7):
        key = bytes_from_prv_key_int(q)
        offset = (ec.n - q).to_bytes(32, byteorder="big", signed=False)
        with pytest.raises(ValueError):
            _pub_key_tweak_chain(key).tweak_add(offset)
        with monkeypatch.context() as no_c:
            no_bindings_bip32(no_c)
            with pytest.raises(
                BTClibValueError, match="the sum is the point at infinity"
            ):
                _pub_key_tweak_chain(key).tweak_add(offset)

    # and the private sum, whose delegated arm is the primitive itself
    for q, t in itertools.product((1, 2, 7, ec.n // 2, ec.n - 1), tweaks):
        key = q.to_bytes(32, byteorder="big", signed=False)
        offset = t.to_bytes(32, byteorder="big", signed=False)
        child = (q + t) % ec.n
        if child:
            assert libsecp256k1_keys.prvkey_tweak_add(key, offset) == child.to_bytes(
                32, byteorder="big", signed=False
            )
        else:
            with pytest.raises(ValueError):
                libsecp256k1_keys.prvkey_tweak_add(key, offset)


@needs_bindings
def test_the_chain_contract_no_derivation_here_asks_for() -> None:
    """`compressed`, and what a call that raised leaves the chain holding.

    Two halves of `tweak_add` that neither derivation reaches: both pass
    `compressed=True` as a literal, and the only refusal a path can
    provoke is the sum at infinity above. The union alias makes them a
    contract even so, mypy checking one call against both
    implementations, and a contract with no caller is a comment unless
    something asserts it.

    The flag by its answer and not by its type. `bytes_from_point`
    refuses a `compressed` that is not a bool, which is the check
    `bool_parameter_test` reaches, and a body that ignored the flag
    altogether would pass that one unchanged.

    The refusal by what the chain holds afterwards.
    `_PythonPubKeyTweakChain` serializes before it steps, so a call that
    raises leaves the point where the last call that answered left it --
    which is what the comment there says and what nothing said back. The
    two implementations part here and this one is the stricter: the
    bindings step first and serialize after, and do not refuse a non-bool
    at all, their serialization taking whatever it is truthy as. Not
    asserted of them, a dependency that grew the check being a change
    this suite should not go red for; asserted of the one whose ordering
    is a decision this file made.
    """
    key = bytes_from_prv_key_int(7)
    tweak = (3).to_bytes(32, byteorder="big", signed=False)

    compressed = _PythonPubKeyTweakChain(key).tweak_add(tweak)
    uncompressed = _PythonPubKeyTweakChain(key).tweak_add(tweak, compressed=False)
    assert uncompressed[0] == 0x04
    assert bytes_from_point(point_from_octets(uncompressed)) == compressed
    assert (
        libsecp256k1_keys.PubkeyTweakChain(key).tweak_add(tweak, compressed=False)
        == uncompressed
    )

    chain = _PythonPubKeyTweakChain(key)
    with pytest.raises(BTClibTypeError, match="invalid compressed type"):
        chain.tweak_add(tweak, compressed="yes")  # type: ignore[arg-type]
    assert chain.tweak_add(tweak) == compressed


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_invalid_child_prv_key(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse the two invalid private children, on a dictated hmac.

    On both arms: the zero child is the sum libsecp256k1 refuses and the
    comparison the Python arm makes, so one refusal has two spellings and
    they have to raise the same error.
    """
    if not bindings:
        no_bindings_bip32(monkeypatch)

    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xkey = BIP32KeyData.b58decode(rootxprv)
    prv_key_int = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)

    # parse256(IL) >= n: no valid scalar to offset the parent key by
    err_msg = "invalid child index 0: the hmac left half is not a valid scalar"
    _force_hmac(monkeypatch, ec.n, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxprv, "m/0")

    # ki = 0: the one offset that cancels the parent key out
    err_msg = "invalid child index 0: the child private key is zero"
    _force_hmac(monkeypatch, ec.n - prv_key_int, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxprv, "m/0")


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_invalid_child_pub_key(bindings: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse the two invalid public children, on a dictated hmac.

    On both arms, as the private children above: the sum at infinity is
    the one libsecp256k1 has no public key for, and the one the Python
    arm recognizes by its zero y.
    """
    if not bindings:
        no_bindings_bip32(monkeypatch)

    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    rootxpub = xpub_from_xprv(rootxprv)
    xkey = BIP32KeyData.b58decode(rootxprv)
    prv_key_int = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)

    err_msg = "invalid child index 0: the hmac left half is not a valid scalar"
    _force_hmac(monkeypatch, ec.n, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxpub, "m/0")

    # offset * G is the parent point negated, so their sum is infinity
    err_msg = "invalid child index 0: the child public key is the point at infinity"
    _force_hmac(monkeypatch, ec.n - prv_key_int, xkey.chain_code)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(rootxpub, "m/0")


XKEY = "xprv9s21ZrQH143K2ZP8tyNiUtgoezZosUkw9hhir2JFzDhcUWKz8qFYk3cxdgSFoCMzt8E2Ubi1nXw71TLhwgCfzqFHfM5Snv4zboSebePRmLS"


def test_assert_valid_does_not_rewrite_the_key_data() -> None:
    """A read is a read: assert_valid must not coerce fields in place.

    Writing back bytes(version), bytes(parent_fingerprint),
    bytes(chain_code), bytes(key), int(index) and int(depth) from a
    method serialize() and b58encode() call lets nominally read-only
    operations rewrite the object. Coercion belongs in __init__, where
    b58decode and a json object go through it.
    """
    xkey_data = BIP32KeyData.b58decode(XKEY)
    # a bytearray is bytes-like, so it serializes and compares equal: what
    # it is not is bytes, and assert_valid must not silently make it so.
    #
    # Every read of the field goes through an object-typed local before
    # being asserted on: "isinstance(bytes, bytearray)" narrows to Never,
    # the two having disjoint bases, and mypy then takes the rest of the
    # function for unreachable and checks none of it -- warn_unreachable
    # being off, in silence. Measured: with the assertion written directly
    # on the attribute, a reveal_type below it prints nothing at all
    #
    # object.__setattr__ and not replace_unchecked: that one builds the
    # instance through __init__, where bytes_from_octets copies the
    # buffer, so what it installs is bytes and there is nothing left for
    # a rewrite to be visible in
    object.__setattr__(xkey_data, "chain_code", bytearray(xkey_data.chain_code))
    chain_code: object = xkey_data.chain_code
    assert isinstance(chain_code, bytearray)

    xkey_data.assert_valid()
    after_assert_valid: object = xkey_data.chain_code
    assert isinstance(after_assert_valid, bytearray)


def test_assert_valid_does_not_rewrite_on_a_read() -> None:
    """Keep b58encode and serialize from coercing fields in place."""
    xkey_data = BIP32KeyData.b58decode(XKEY)
    object.__setattr__(xkey_data, "chain_code", bytearray(xkey_data.chain_code))

    xkey_data.b58encode()
    after_b58encode: object = xkey_data.chain_code
    assert isinstance(after_b58encode, bytearray)

    xkey_data.serialize()
    after_serialize: object = xkey_data.chain_code
    assert isinstance(after_serialize, bytearray)


def test_a_bytearray_chain_code_is_copied_into_the_key_data() -> None:
    """The caller keeps its buffer, and the key keeps its octets.

    `bytes_from_octets` copies what `__init__` is given, so a caller
    writing to the bytearray it built a key from does not rewrite the
    key: without the copy the field aliased that buffer, and the xprv
    this serializes to changed under a caller who never touched the key
    (issue #1255).
    """
    chain_code = bytearray(b"\x11" * 32)
    xkey_data = BIP32KeyData(
        version="0488ade4",
        depth=0,
        parent_fingerprint="00000000",
        index=0,
        chain_code=chain_code,
        key="00" + "22" * 32,
    )
    xprv = xkey_data.b58encode()
    chain_code[0] = 0xFF
    assert xkey_data.b58encode() == xprv


def test_assert_valid_reports_a_float_field_instead_of_coercing_it() -> None:
    """Reported, not repaired behind the caller's back.

    Dropping the check outright instead would let the float reach
    to_bytes and leave the library through an AttributeError.
    """
    xkey_data = BIP32KeyData.b58decode(XKEY)
    object.__setattr__(xkey_data, "index", float(xkey_data.index))
    with pytest.raises(BTClibTypeError, match="invalid index type: float"):
        xkey_data.assert_valid()
    index: object = xkey_data.index
    assert isinstance(index, float)

    xkey_data = BIP32KeyData.b58decode(XKEY)
    object.__setattr__(xkey_data, "depth", float(xkey_data.depth))
    with pytest.raises(BTClibTypeError, match="invalid depth type: float"):
        xkey_data.assert_valid()


def test_the_coercion_still_happens_in_init() -> None:
    """from_dict is the reason it exists: json has no integer type."""
    xkey_data = BIP32KeyData.b58decode(XKEY)
    coerced = BIP32KeyData(
        version=xkey_data.version,
        depth=0.0,  # type: ignore[arg-type]
        parent_fingerprint=xkey_data.parent_fingerprint,
        index=0.0,  # type: ignore[arg-type]
        chain_code=xkey_data.chain_code,
        key=xkey_data.key,
    )
    assert isinstance(coerced.depth, int)
    assert isinstance(coerced.index, int)
    assert coerced.b58encode() == XKEY
    assert BIP32KeyData.b58decode(coerced.b58encode()) == coerced


def test_is_root_is_all_three_fields_and_not_just_one() -> None:
    """No caller of `is_root` exercises it, so pin the property itself.

    `_assert_valid_depth_and_index` ties depth zero to index zero and to
    a zero parent fingerprint, so a *valid* object never isolates the
    index or the fingerprint term: it is depth alone a valid non-root key
    can vary. The other two need `check_validity=False`, the same
    combination `_assert_valid_depth_and_index` itself would refuse.
    """
    root = BIP32KeyData.b58decode(XKEY)
    assert root.is_root

    non_root_depth = BIP32KeyData(
        version=root.version,
        depth=1,
        parent_fingerprint=root.parent_fingerprint,
        index=0,
        chain_code=root.chain_code,
        key=root.key,
    )
    assert not non_root_depth.is_root

    non_root_index = BIP32KeyData(
        version=root.version,
        depth=0,
        parent_fingerprint=root.parent_fingerprint,
        index=1,
        chain_code=root.chain_code,
        key=root.key,
        check_validity=False,
    )
    assert not non_root_index.is_root

    non_root_fingerprint = BIP32KeyData(
        version=root.version,
        depth=0,
        parent_fingerprint=b"\x01\x02\x03\x04",
        index=0,
        chain_code=root.chain_code,
        key=root.key,
        check_validity=False,
    )
    assert not non_root_fingerprint.is_root

    # negative, not only positive: `depth == 0`/`index == 0` weakened to
    # `<= 0` would call this one root too, index and parent fingerprint
    # both being the root's own
    negative_depth = BIP32KeyData(
        version=root.version,
        depth=-1,
        parent_fingerprint=root.parent_fingerprint,
        index=0,
        chain_code=root.chain_code,
        key=root.key,
        check_validity=False,
    )
    assert not negative_depth.is_root

    negative_index = BIP32KeyData(
        version=root.version,
        depth=0,
        parent_fingerprint=root.parent_fingerprint,
        index=-1,
        chain_code=root.chain_code,
        key=root.key,
        check_validity=False,
    )
    assert not negative_index.is_root


def test_is_hardened_is_not_narrowed_to_the_boundary_alone() -> None:
    """An index strictly above the offset is hardened too, not just it.

    `self.index >= _HARDENED_OFFSET` weakened to `==` would call every
    non-root path in the test vectors hardened all the same, since every
    one of them lands exactly on the offset (`0h`, `44h`); nothing there
    ever derives past it.
    """
    root = BIP32KeyData.b58decode(XKEY)
    above_offset = BIP32KeyData(
        version=root.version,
        depth=1,
        parent_fingerprint=b"\x01\x02\x03\x04",
        index=0x80000000 + 1,
        chain_code=root.chain_code,
        key=root.key,
        check_validity=False,
    )
    assert above_offset.is_hardened


def test_hardened_public_derivation_is_refused_above_the_offset_too() -> None:
    """A hardened index above the offset is refused, not just the exact one.

    `any(index >= _HARDENED_OFFSET ...)` weakened to `==` in
    `__pub_key_path_derivation` would refuse only the exact boundary
    `derive(xpub, 0x80000000)` already covers, letting an ordinary
    hardened index above it reach a private-only derivation instead.
    """
    xpub = xpub_from_xprv(XKEY)
    err_msg = "invalid hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(xpub, 0x80000000 + 1)


def test_assert_valid_depth_and_index_accepts_its_own_boundaries() -> None:
    """Depth 255 and index 0xffffffff are the top of their ranges, not past it.

    `0 <= x <= bound` weakened on either side, or a bound replaced with a
    neighbor, would refuse exactly the value every other vector stops one
    short of.
    """
    root = BIP32KeyData.b58decode(XKEY)
    top = BIP32KeyData(
        version=root.version,
        depth=255,
        parent_fingerprint=b"\x01\x02\x03\x04",
        index=0xFFFFFFFF,
        chain_code=root.chain_code,
        key=root.key,
    )
    assert top.depth == 255
    assert top.index == 0xFFFFFFFF


def test_assert_valid_key_refuses_a_scalar_above_n_too() -> None:
    """`0 < q < n` chained: weakening the right `<` to `!=` misses q > n.

    Both existing invalid-key vectors put q at 0 and at n exactly, so
    `q != n` alone would already refuse either one; only a scalar
    strictly above n tells `q < n` apart from it.
    """
    xkey_data = replace_unchecked(
        BIP32KeyData.b58decode(XKEY),
        key=b"\x00" + (ec.n + 1).to_bytes(32, byteorder="big", signed=False),
    )
    with pytest.raises(BTClibValueError, match="invalid private key not in 1..n-1"):
        xkey_data.assert_valid()


def test_invalid_key_prefix_messages_show_exactly_one_byte() -> None:
    """The hex in each prefix-refusal message is one byte, not a slice past it.

    `key[:1].hex()` widened to `key[:2]` still contains the same text as
    a leading substring, so only an exact match on the whole message --
    not `pytest.raises(match=...)`'s search -- tells the two spellings
    apart.
    """
    root = BIP32KeyData.b58decode(XKEY)

    bad_prv = replace_unchecked(
        BIP32KeyData.b58decode(XKEY), key=b"\x05" + root.key[1:]
    )
    with pytest.raises(BTClibValueError) as excinfo:
        bad_prv.assert_valid()
    assert str(excinfo.value) == "invalid private key prefix: 0x05"

    xpub = BIP32KeyData.b58decode(xpub_from_xprv(XKEY))
    bad_pub = replace_unchecked(
        BIP32KeyData.b58decode(xpub_from_xprv(XKEY)), key=b"\x05" + xpub.key[1:]
    )
    with pytest.raises(BTClibValueError) as excinfo:
        bad_pub.assert_valid()
    assert str(excinfo.value) == "invalid public key prefix not in (0x02, 0x03): 0x05"

    # a valid xpub, not the malformed key above: `xpub_from_xprv`
    # validates what it is given before handing it to `_xpub_from_xprv`,
    # so a 0x05 prefix is refused as an invalid public key rather than as
    # a public one, and the message below is reached by the key that
    # really provokes it
    with pytest.raises(BTClibValueError) as excinfo:
        xpub_from_xprv(xpub)
    assert str(excinfo.value) == f"not a private key: prefix 0x{xpub.key[:1].hex()}"

    child_xpub_data = BIP32KeyData.b58decode(xpub_from_xprv(XKEY))
    prefix = f"0x{child_xpub_data.key[:1].hex()}"
    with pytest.raises(BTClibValueError) as excinfo:
        crack_prv_key_var(xpub_from_xprv(XKEY), xpub_from_xprv(XKEY))
    assert (
        str(excinfo.value)
        == f"extended child key is not a private key: prefix {prefix}"
    )


def test_pub_key_derivation_tweaks_are_32_bytes_each() -> None:
    """`offset.to_bytes(32, ...)` widened to 33 would leak a byte per tweak.

    Every existing assertion on `pub_key_derivation_tweaks` compares the
    accumulated point, which a leading zero byte would not move: nothing
    checks the tweaks' own length.
    """
    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xpub = BIP32KeyData.b58decode(xpub_from_xprv(rootxprv))
    tweaks = pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1/2")
    assert all(len(tweak) == 32 for tweak in tweaks)


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_a_path_of_no_steps_still_looks_at_the_public_key(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """[] is the right answer for an empty path, and not for a non-point.

    `if indexes:` around the whole body made the empty path the one
    spelling of this call that validated nothing: 33 bytes that are no
    public key -- a prefix of 0x00, an x above p, x = 0 -- all came back
    as `[]`, the answer a caller reads as "derivation succeeded, nothing
    to apply".

    Both arms build the chain, so both are asked: the four keys below are
    refused by `PubkeyTweakChain`'s parse where the bindings serve, and by
    `point_from_octets` where they do not.
    """
    if not bindings:
        no_bindings_bip32(monkeypatch)

    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xpub = BIP32KeyData.b58decode(xpub_from_xprv(rootxprv))

    assert pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m") == []

    for not_a_point in (
        b"\x02" + b"\xff" * 32,  # x above the field prime
        b"\x02" + b"\x00" * 32,  # x = 0
        b"\x05" + b"\x01" * 32,  # no such prefix
        b"\x00" + b"\x01" * 32,  # the xprv prefix, not a public key
    ):
        for der_path in ("m", "m/1/2"):
            with pytest.raises(BTClibValueError, match="invalid public key: "):
                pub_key_derivation_tweaks(not_a_point, xpub.chain_code, der_path)


def test_derive_with_a_forced_version() -> None:
    """A forced version must be the same kind, private or public, as the key.

    `_force_version` is otherwise unexercised by any test: `version in
    XPRV_VERSIONS_ALL` negated, `fversion not in allowed_versions`
    negated, and `bytes_from_octets(forced_version, 4)` widened to 5 or
    narrowed to 3 all survive without a single call anywhere passing
    forced_version.
    """
    forced_prv = NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv
    forced = derive(XKEY, "m/0h", forced_prv)
    assert BIP32KeyData.b58decode(forced).version == forced_prv

    err_msg = "invalid version forced on the extended key"
    forced_pub = NETWORKS["mainnet"].slip132_p2wpkh_p2sh_pub
    with pytest.raises(BTClibValueError, match=err_msg):
        derive(XKEY, "m/0h", forced_pub)


def test_b58decode_strips_a_string_and_not_bytes() -> None:
    """A string is whitespace-stripped before decoding.

    `isinstance(address, str)` negated would strip bytes instead of
    strings and leave a padded string for base58.decode to choke on --
    nothing downstream surfaces the swap without checking the string
    path directly.
    """
    xkey_data = BIP32KeyData.b58decode(f"  {XKEY}  ")
    assert xkey_data == BIP32KeyData.b58decode(XKEY)


def test_check_validity_defaults_to_true() -> None:
    """`__init__`, serialize, parse and b58encode all default to True.

    A zero depth with a non-zero parent fingerprint serializes fine
    structurally -- one byte and four, whatever they hold -- and is
    refused only by assert_valid's cross-field check, the one
    check_validity=False defers on every one of these four call sites.
    """
    root = BIP32KeyData.b58decode(XKEY)
    invalid = BIP32KeyData(
        version=root.version,
        depth=0,
        parent_fingerprint=b"\x01\x02\x03\x04",
        index=0,
        chain_code=root.chain_code,
        key=root.key,
        check_validity=False,
    )
    err_msg = "zero depth with non-zero parent fingerprint: "

    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyData(
            version=invalid.version,
            depth=invalid.depth,
            parent_fingerprint=invalid.parent_fingerprint,
            index=invalid.index,
            chain_code=invalid.chain_code,
            key=invalid.key,
        )

    with pytest.raises(BTClibValueError, match=err_msg):
        invalid.serialize()
    as_bytes = invalid.serialize(check_validity=False)

    with pytest.raises(BTClibValueError, match=err_msg):
        invalid.b58encode()
    assert invalid.b58encode(check_validity=False)

    with pytest.raises(BTClibValueError, match=err_msg):
        BIP32KeyData.parse(as_bytes)
    assert BIP32KeyData.parse(as_bytes, check_validity=False) == invalid


@pytest.mark.parametrize(
    "bindings",
    [
        pytest.param(True, marks=needs_bindings, id="bindings"),
        pytest.param(False, id="python"),
    ],
)
def test_the_tweaks_of_a_public_derivation_are_the_derivation(
    bindings: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scalars a path adds up to, against the key the path derives.

    What they are for is a key that cannot be derived from -- a BIP327
    MuSig2 aggregate key has no private key, so BIP328 derivation reaches
    the signers as tweaks (BIP373, `btclib.psbt.musig2`) -- and what says
    they are right is that applying them by hand lands on the key `derive`
    answers for the same path.

    On both arms, the tweaks being the hmac's left halves and so the same
    scalars either way: what differs is the chain walking the key from one
    to the next, which is where the two could part.
    """
    if not bindings:
        no_bindings_bip32(monkeypatch)

    rootxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    xpub = BIP32KeyData.b58decode(xpub_from_xprv(rootxprv))

    tweaks = pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1/2")
    derived = BIP32KeyData.b58decode(derive(xpub_from_xprv(rootxprv), "m/1/2"))
    point = point_from_octets(xpub.key, ec)
    for tweak in tweaks:
        point = ec.add_var(point, mult(int.from_bytes(tweak, "big"), ec.G, ec))
    assert bytes_from_point(point, ec) == derived.key

    # a hardened index needs the private key, and the refusal comes before
    # any step of the path is walked
    err_msg = "invalid hardened derivation from public key"
    with pytest.raises(BTClibValueError, match=err_msg):
        pub_key_derivation_tweaks(xpub.key, xpub.chain_code, "m/1h")


# BIP328's own test vectors: a MuSig2 aggregate public key, the synthetic
# xpub it becomes, and the participant keys it aggregates. The keys are
# *not* sorted here -- BIP328 aggregates the list as written, where BIP390
# sorts it first, so the three vectors say which of the two rules is whose
BIP328_VECTORS = [
    (
        "0354240c76b8f2999143301a99c7f721ee57eee0bce401df3afeaa9ae218c70f23",
        "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwXEKGEouzXE6QLLRxjatMcLLzJ5LV5Nib1BN7vJg6yp45yHHRbm",
        [
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        ],
    ),
    (
        "0290539eede565f5d054f32cc0c220126889ed1e5d193baf15aef344fe59d4610c",
        "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwVk5TFJk8Tw5WAdV3DhrGfbFA216sE9BsQQiSFTdudkETnKdg8k",
        [
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        ],
    ),
    (
        "022479f134cdb266141dab1a023cbba30a870f8995b95a91fc8464e56a7d41f8ea",
        "xpub661MyMwAqRbcFt6tk3uaczE1y6EvM1TqXvawXcYmFEWijEM4PDBnuCXwwUvaZYpysLX4wN59tjwU5pBuDjNrPEJbfxjLwn7ruzbXTcUTHkZ",
        [
            "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
            "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        ],
    ),
]


@pytest.mark.parametrize(
    "aggregate_pub_key, synthetic_xpub, participants",
    [
        pytest.param(aggregate, xpub, keys, id=vector_id(index, aggregate))
        for index, (aggregate, xpub, keys) in enumerate(BIP328_VECTORS)
    ],
)
def test_bip328_synthetic_xpub(
    aggregate_pub_key: str, synthetic_xpub: str, participants: list[str]
) -> None:
    """Reproduce BIP328's vectors: an aggregate key made derivable.

    The construction is the whole of the specification -- depth zero, child
    number zero, and `BIP328_CHAIN_CODE` where an aggregate key has no
    chain code of its own -- and the xpub it produces is what a
    ``musig()`` descriptor derives from and what BIP373 lets a psbt leave
    out, the fingerprint of that xpub being enough to recognize it.
    """
    aggregate = bytes.fromhex(aggregate_pub_key)
    assert bytes_from_point(key_agg(participants).Q, ec) == aggregate

    xkey = BIP32KeyData(
        version=NETWORKS["mainnet"].bip32_pub,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        index=0,
        chain_code=BIP328_CHAIN_CODE,
        key=aggregate,
    )
    assert xkey.b58encode() == synthetic_xpub
    # and a child of it is a child of the group: what the tweaks above
    # reach, which is the arithmetic a signer does instead of deriving
    assert derive(synthetic_xpub, "m/0") == derive(xkey, "m/0")


def test_cracking_refuses_a_child_its_own_assert_valid_refuses() -> None:
    """Both arguments through `_key_data_from_bip32_key` (issue 693).

    This function exists to demonstrate a known BIP32 weakness, so an
    answer it gives for a child the library itself refuses is a wrong
    lesson: it subtracted the offset from a key set to the zero scalar and
    returned an xprv. The parent is affected too, its `key[0]` prefix
    the only field looked at before the answer is built.
    """
    root = rootxprv_from_seed("0102030405060708090a0b0c0d0e0f10")
    parent_xpub = xpub_from_xprv(root)
    child_xprv = derive(root, "m/0")
    assert crack_prv_key_var(parent_xpub, child_xprv) == root

    bad_child = replace_unchecked(
        BIP32KeyData.b58decode(child_xprv),
        key=b"\x00" * 33,  # the zero scalar
    )
    err_msg = "invalid private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        bad_child.assert_valid()
    with pytest.raises(BTClibValueError, match=err_msg):
        crack_prv_key_var(parent_xpub, bad_child)


def test_the_object_spellings_answer_what_the_text_ones_answer() -> None:
    """Each underscore spelling is the function above it (issue 886).

    Each answers the `BIP32KeyData` its text twin encodes, so `b58encode`
    of one is the other -- which is the whole of the claim, the text
    spellings being these functions with an encoding on top. Asserted at
    every hop of a path a caller actually walks, seed to account to
    address, because the point of them is that a caller stops encoding and
    decoding between the hops.

    The arguments are the text twins' too: an object spelling takes a
    `BIP32Key`, so the key it derives from may be a `BIP32KeyData` or the
    Base58Check text of one, and the two name one key.
    """
    seed = "0102030405060708090a0b0c0d0e0f101112131415161718"
    root = rootxprv_from_seed_(seed)
    assert isinstance(root, BIP32KeyData)
    assert root.b58encode() == rootxprv_from_seed(seed)

    account = derive_(root, "m/44h/0h/0h")
    assert account.b58encode() == derive(root.b58encode(), "m/44h/0h/0h")
    # the same key, whichever spelling of it is handed in
    assert derive_(root.b58encode(), "m/44h/0h/0h") == account

    xpub = xpub_from_xprv_(account)
    assert xpub.b58encode() == xpub_from_xprv(account.b58encode())

    address_key = derive_from_account_(xpub, 0, 7)
    assert address_key.b58encode() == derive_from_account(xpub.b58encode(), 0, 7)
    # and it is the key the path spells out, which is what makes the
    # account-level function a shorthand rather than a second derivation
    assert address_key == derive_(xpub, "m/0/7")

    # the version can be forced, as in `derive`
    yprv = derive_(root, "m/44h", NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv)
    assert yprv.b58encode() == derive(
        root, "m/44h", NETWORKS["mainnet"].slip132_p2wpkh_p2sh_prv
    )


def test_the_object_spellings_validate_what_they_are_handed() -> None:
    """A public function validates its inputs, underscore or not (issue 886).

    The underscore says the caller holds the key rather than its text, and
    nothing else: what the four refuse is what the text spellings refuse,
    an invalid key on the way in and an invalid one on the way out. The
    output check is the one `b58encode` used to make inside `derive`, which
    is why it is `assert_valid` and not the encoding.
    """
    root = rootxprv_from_seed_("0102030405060708090a0b0c0d0e0f10")

    # a seed too short is refused as it is by the text spelling
    with pytest.raises(BTClibValueError, match="too few bits for seed"):
        rootxprv_from_seed_("0102030405060708")

    # a key handed in as an object is validated too: frozen keeps a
    # validated one valid, and this one never was
    corrupt = replace_unchecked(root, key=b"\x00" * 33)
    err_msg = "invalid private key not in 1..n-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_(corrupt, "m/0")
    with pytest.raises(BTClibValueError, match=err_msg):
        xpub_from_xprv_(corrupt)
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account_(corrupt, 0, 0)

    # an xpub cannot answer a hardened child, whichever spelling asks
    xpub = xpub_from_xprv_(root)
    with pytest.raises(BTClibValueError, match="invalid hardened derivation"):
        derive_(xpub, "m/0h")


def test_derive_from_account_range_is_the_same_keys_walked_once() -> None:
    """A range answers what the single-address spelling answers, index by index.

    The branch level is walked once here and once per address there, so
    the two are one answer or the saving is a bug: asserted over a
    contiguous run, over a run with a gap in it -- what a scan resuming
    past one looks like -- and over the empty one, which is no addresses
    and not an error.
    """
    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    mxpub = xpub_from_xprv(derive(rootxprv_from_seed(seed), "m / 44 h / 0 h"))

    for branch in (0, 1):
        for indexes in (range(5), [0], [3, 0, 17], [], (2, 2)):
            assert derive_from_account_range_(mxpub, branch, indexes) == [
                derive_from_account_(mxpub, branch, i) for i in indexes
            ]
            assert derive_from_account_range(mxpub, branch, indexes) == [
                derive_from_account(mxpub, branch, i) for i in indexes
            ]


def test_derive_from_account_range_refuses_before_it_walks() -> None:
    """One bad index refuses the whole range, and in the same words.

    Half a list would leave the caller holding the addresses before the
    bad index and no answer for the rest, so every index is read before
    any of them is derived -- which is also why a bad one at the end
    raises rather than being reached after a thousand derivations.
    """
    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    mxpub = xpub_from_xprv(derive(rootxprv_from_seed(seed), "m / 44 h / 0 h"))

    err_msg = "invalid private derivation at branch level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account_range_(mxpub, 0x80000000, range(3))

    err_msg = "invalid branch number: 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account_range_(mxpub, 2, range(3))

    err_msg = "invalid private derivation at address index level"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account_range_(mxpub, 0, [0, 0x80000000], max_index=0xFFFFFFFF)

    err_msg = "invalid address index: 65536"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account_range_(mxpub, 0, [0, 1, 0xFFFF + 1])

    err_msg = "unhardened account/master key"
    with pytest.raises(BTClibValueError, match=err_msg):
        derive_from_account_range_(xpub_from_xprv(rootxprv_from_seed(seed)), 0, [0])


def test_fingerprint_is_the_children_parent_fingerprint() -> None:
    """A key's fingerprint is what its own children carry as a parent.

    Which is the whole of what BIP32 wants the four octets for, and the
    one assertion that catches them being taken of the wrong key:
    `derive` writes the parent's fingerprint into the child and
    `fingerprint` computes it from the parent, so the two agree only if
    both read the same compressed public key.

    Both spellings of the parent, because the fingerprint is the public
    key's and a pair answering two would identify one key twice. What
    makes them agree is `_xpub_from_xprv`, shared rather than repeated
    here (issue #1188).
    """
    seed = "bfc4cbaad0ff131aa97fa30a48d09ae7df914bcc083af1e07793cd0a7c61a03f"
    seed += "65d622848209ad3366a419f4718a80ec9037df107d8d12c19b83202de00a40ad"
    xprv = rootxprv_from_seed(seed)

    child = BIP32KeyData.b58decode(derive(xprv, 0x80000000))

    assert fingerprint(xprv) == child.parent_fingerprint
    assert fingerprint(xpub_from_xprv(xprv)) == child.parent_fingerprint
