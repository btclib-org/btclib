# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP32 hierarchical deterministic wallet functions.

https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

A deterministic wallet derives every key pair from a single root, the
one element requiring backup; BIP32 makes the derivation a tree, so a
branch of keys can be shared without the rest, and public derivation
computes child public keys with no private key at hand.

A BIP32 extended key is 78 bytes:

- [  : 4] version
- [ 4: 5] depth in the derivation path
- [ 5: 9] parent fingerprint
- [ 9:13] index
- [13:45] chain code
- [45:78] compressed pub_key or [0x00][prv_key]
"""

from __future__ import annotations

import functools
import hmac
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from btclib import base58
from btclib._libsecp256k1 import keys as libsecp256k1_keys
from btclib.alias import BinaryData, Octets, String
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
)
from btclib.curves import (
    bytes_from_point,
    bytes_from_prv_key_int,
    mult,
    point_from_octets,
    secp256k1,
)
from btclib.curves.curve import _is_x_coordinate_var, _libsecp256k1_serves
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import (
    NETWORKS,
    XPRV_VERSIONS_ALL,
    XPUB_VERSIONS_ALL,
    xpubversion_from_xprvversion,
)
from btclib.utils import (
    assert_no_trailing,
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_json_number,
    is_integer,
)

__all__ = [
    "BIP328_CHAIN_CODE",
    "BIP32Key",
    "BIP32KeyData",
    "crack_prv_key_var",
    "derive",
    "derive_",
    "derive_from_account",
    "derive_from_account_",
    "derive_from_account_range",
    "derive_from_account_range_",
    "fingerprint",
    "pub_key_derivation_tweaks",
    "rootxprv_from_seed",
    "rootxprv_from_seed_",
    "xpub_from_xprv",
    "xpub_from_xprv_",
]

# secp256k1 is written out at each use rather than aliased to a module
# global "ec": BIP32 is defined for secp256k1 and for nothing else, so
# the alias was not configuration, and rebinding btclib.bip32.bip32.ec
# changed key validation for every caller in the process


_KEY_SIZE = [("version", 4), ("parent_fingerprint", 4), ("chain_code", 32), ("key", 33)]
_REQUIRED_LENGTH = 78


@functools.lru_cache(maxsize=2048)
def _cached_base58_decode(address: String) -> bytes:
    """Return `base58.decode(address)`, memoized on the xprv/xpub string.

    `derive` decodes its `xkey` argument fresh on every call, and a
    caller deriving many indices or paths from one account key -- what
    `derive_from_account` does once per address -- pays for decoding
    that same root again each time. `maxsize` is bounded rather than
    `None` for the reason `pedersen.second_generator`'s cache states:
    `address` is caller-supplied, and an unbounded cache on it would be
    a memory leak (issue #287).

    2048 rather than the module's usual bare default (128) is measured
    on two workloads: btclib's own suite, and a caller that also calls
    `b58decode` directly once per derived key, on top of what `derive`
    already does (checksig#643, the heavier of the two). Hit rate at
    128, 512, 1024 and 2048 respectively: 22.2%, 24.3%, 27.5% and 28.8%
    for the first; 52.8%, 55.6%, 56.1% and 72.9% for the second -- most
    of the second workload's climb from 1024 to 2048, the first
    already flat by then.

    Past 2048 the second workload keeps climbing -- at 8192 it is still
    full and evicting -- but so does what stays resident: `address` may
    be an xprv, and every entry is a decoded key kept alive past its
    caller's own reference to it. 2048 is where the first workload has
    already flattened and the second has just cleared its own knee,
    rather than chasing a ratio neither workload's own shape asks for.

    Bytes, not the `BIP32KeyData` `b58decode` builds from them: frozen
    does not stop `object.__setattr__`, which
    `tests/bip32/bip32_test.py::test_assert_valid2` uses on purpose to
    corrupt independent instances decoded from the same string, so
    `b58decode` still has to construct a fresh one on every call. Bytes
    are the one result here nobody can mutate by accident.
    """
    return base58.decode(address)


def _assert_valid_depth_and_index(
    depth: int, index: int, parent_fingerprint: bytes
) -> None:
    """Raise an exception if depth, index and fingerprint disagree.

    The three are one check and not three: depth zero is the root, and a
    root has no parent, so it is the depth that decides what the index
    and the fingerprint of the parent are allowed to be.
    """
    if not 0 <= index <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid index: {index}")

    if not 0 <= depth <= 255:
        raise BTClibValueError(f"invalid depth: {depth}")

    if depth == 0:
        if parent_fingerprint != b"\x00" * 4:
            err_msg = "zero depth with non-zero parent fingerprint: "
            err_msg += f"0x{parent_fingerprint.hex()}"
            raise BTClibValueError(err_msg)
        if index != 0:
            raise BTClibValueError(f"zero depth with non-zero index: {index}")


def _assert_valid_key(version: bytes, key: bytes) -> None:
    """Raise an exception if the key is not valid for its version.

    The version is what says whether the 33 bytes are a private or a
    public key, so an unknown version leaves nothing to check them
    against and is the error itself.
    """
    if version in XPRV_VERSIONS_ALL:
        if key[0] != 0:
            raise BTClibValueError(f"invalid private key prefix: 0x{key[:1].hex()}")
        q = int.from_bytes(key[1:], byteorder="big", signed=False)
        if not 0 < q < secp256k1.n:
            # never echo the scalar: it is (attempted) key material
            raise BTClibValueError("invalid private key not in 1..n-1")
    elif version in XPUB_VERSIONS_ALL:
        if key[0] not in {2, 3}:
            err_msg = "invalid public key prefix not in (0x02, 0x03): "
            err_msg += f"0x{key[:1].hex()}"
            raise BTClibValueError(err_msg)
        # existence and nothing else, the y having been computed and
        # dropped: this is the caller _is_x_coordinate_var's docstring
        # describes, and the square root it exists not to pay was paid
        # once per extended key, so by every level of every derivation
        # path (issue 615). A predicate has no exception to chain, so
        # the message below is the whole of the error where it used to
        # be raised from curve_group's "invalid x-coordinate"
        x = int.from_bytes(key[1:], byteorder="big", signed=False)
        if not _is_x_coordinate_var(x, secp256k1):
            raise BTClibValueError(f"invalid public key: 0x{key.hex()}")
    else:
        raise BTClibValueError(f"unknown extended key version: 0x{version.hex()}")


@dataclass(frozen=True, init=False)
class BIP32KeyData:
    """A BIP32 extended key, decoded into its six fields.

    What one xprv/xpub string holds: version, depth, parent
    fingerprint, index, chain code and the 33-byte key, private keys
    carrying their 0x00 prefix. The wire form is the 78-byte serialize
    and parse; b58encode and b58decode add the customary Base58Check
    spelling. repr masks the key material of a private one.

    Frozen, so that a public function handed one can trust it rather
    than revalidate it: `check_validity=False` says "not checked yet",
    and a mutable field would let that stay true forever, one attribute
    write after the check that never came (issue 727). `_BIP32KeyData`
    below is where derivation still needs to mutate one field at a
    time -- a sibling struct now, and not a subclass, frozen and
    non-frozen dataclasses refusing to mix in one inheritance chain.
    """

    version: bytes
    depth: int
    parent_fingerprint: bytes
    # index is an int, not bytes, to avoid any byteorder ambiguity
    index: int
    chain_code: bytes
    key: bytes

    @property
    def is_private(self) -> bool:
        """Answer whether the key is private, by its 0x00 prefix."""
        return self.key[0] == 0

    def __repr__(self) -> str:
        # never echo private key material: mask key and chain_code
        # (key[:1], not is_private, so that repr cannot raise on an
        # invalid instance with an empty key)
        private = self.key[:1] == b"\x00"
        chain_code = "***" if private else self.chain_code.hex()
        key = "***" if private else self.key.hex()
        return (
            f"{type(self).__name__}("
            f"version={self.version.hex()}, "
            f"depth={self.depth}, "
            f"parent_fingerprint={self.parent_fingerprint.hex()}, "
            f"index={self.index}, "
            f"chain_code={chain_code}, "
            f"key={key})"
        )

    @property
    def is_hardened(self) -> bool:
        """Answer whether the index is in the hardened range."""
        return self.index >= _HARDENED_OFFSET

    @property
    def is_root(self) -> bool:
        """Answer whether this is a master key: no depth, index, parent."""
        return (
            self.depth == 0
            and self.index == 0
            and self.parent_fingerprint == b"\x00" * 4
        )

    def __init__(
        self,
        version: Octets,
        depth: int,
        parent_fingerprint: Octets,
        index: int,
        chain_code: Octets,
        key: Octets,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "version", bytes_from_octets(version))
        # a coercion, where the annotation already says int, for the same
        # reason bytes_from_octets is called on the four Octets fields:
        # from_dict feeds this constructor a json object, where a whole
        # number may arrive as a float. Coercing in assert_valid instead
        # would rewrite the object it is asked to inspect -- and it is
        # called by serialize() and to_dict(), so reading a key would
        # mutate it. A bool is refused rather than coerced: `true` out of
        # json is a schema error, not depth one
        object.__setattr__(self, "depth", int_from_json_number(depth, "depth"))
        object.__setattr__(
            self, "parent_fingerprint", bytes_from_octets(parent_fingerprint)
        )
        object.__setattr__(self, "index", int_from_json_number(index, "index"))
        object.__setattr__(self, "chain_code", bytes_from_octets(chain_code))
        object.__setattr__(self, "key", bytes_from_octets(key))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse what no valid extended key can hold.

        Field types and sizes, a depth consistent with index and
        parent fingerprint, a known version, and a key that parses --
        as a scalar in 1..n-1 or as a point of the curve, whichever
        the version demands.
        """
        for key, size in _KEY_SIZE:
            # bytes() is the type check, not a coercion: it raises
            # TypeError for a field rebound to a str, which would otherwise
            # pass the length test below and fail later on .hex(). The
            # result is never assigned back: validating must not rewrite
            # the object
            value = bytes(getattr(self, key))
            if len(value) != size:
                err_msg = f"invalid {key} length: "
                err_msg += f"{len(value)} bytes"
                err_msg += f" instead of {size}"
                raise BTClibValueError(err_msg)

        # the same type check for the two int fields. Not a coercion,
        # which would repair the mistake by rewriting the object being
        # inspected; not dropped either, which would let a float reach
        # to_bytes and leave through an AttributeError
        for key in ("depth", "index"):
            value_ = getattr(self, key)
            if not is_integer(value_):
                err_msg = f"invalid {key} type: {type(value_).__name__}"
                raise BTClibTypeError(err_msg)

        # after the two loops and not before: these read the fields as
        # the bytes and the ints the loops have just established them to
        # be, and .hex() on a str field would raise AttributeError here
        _assert_valid_depth_and_index(self.depth, self.index, self.parent_fingerprint)
        _assert_valid_key(self.version, self.key)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the 78-byte serialization, BIP32's."""
        if check_validity:
            self.assert_valid()

        return b"".join(
            [
                self.version,
                self.depth.to_bytes(1, byteorder="big", signed=False),
                self.parent_fingerprint,
                self.index.to_bytes(4, byteorder="big", signed=False),
                self.chain_code,
                self.key,
            ]
        )

    def b58encode(self, *, check_validity: bool = True) -> str:
        """Return the Base58Check text, the xprv/xpub spelling."""
        data_binary = self.serialize(check_validity=check_validity)
        return base58.encode(data_binary).decode("ascii")

    @classmethod
    def parse(
        cls: type[BIP32KeyData], xkey_bin: BinaryData, *, check_validity: bool = True
    ) -> BIP32KeyData:
        """Return a BIP32KeyData by parsing 78 bytes from binary data."""
        stream = bytesio_from_binarydata(xkey_bin)
        key_bin = stream.read(_REQUIRED_LENGTH)

        # whatever check_validity says: seventy-eight bytes are what make
        # the slices below mean anything, where a semantic check is an
        # opinion about the key they carry. btclib/utils.py states the rule
        if len(key_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(key_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise BTClibValueError(err_msg)
        assert_no_trailing(xkey_bin, stream, "extended key")

        return cls(
            version=key_bin[:4],
            depth=key_bin[4],
            parent_fingerprint=key_bin[5:9],
            index=int.from_bytes(key_bin[9:13], byteorder="big", signed=False),
            chain_code=key_bin[13:45],
            # the constant the read and the length check above are written
            # in, rather than a second spelling of it: the offsets are this
            # field's own, the total is the format's
            key=key_bin[45:_REQUIRED_LENGTH],
            check_validity=check_validity,
        )

    @classmethod
    def b58decode(
        cls: type[BIP32KeyData], address: String, *, check_validity: bool = True
    ) -> BIP32KeyData:
        """Build a BIP32KeyData from its xprv/xpub Base58Check text.

        The type is asked here rather than left to `base58.decode`, which
        does ask it: the cache in front of that call keys on the argument,
        so an unhashable one -- a list, a bytearray, the mutable buffers
        `String` does not cover -- left as a TypeError about hashing
        instead of the refusal decoding would have given.
        """
        assert_type(address, (str, bytes), "base58 string")

        if isinstance(address, str):
            address = address.strip()

        xkey_bin = _cached_base58_decode(address)
        return cls.parse(xkey_bin, check_validity=check_validity)


def _rootxprv_from_seed(seed: Octets, version: Octets) -> BIP32KeyData:
    """Return BIP32 root master extended private key from seed."""
    seed = bytes_from_octets(seed)
    bit_length = len(seed) * 8
    # the bit count is diagnostic enough: never echo the seed itself
    if bit_length < 128:
        raise BTClibValueError(f"too few bits for seed: {bit_length}")
    if bit_length > 512:
        raise BTClibValueError(f"too many bits for seed: {bit_length}")
    hmac_ = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    k = b"\x00" + hmac_[:32]
    v = bytes_from_octets(version, 4)

    return BIP32KeyData(
        version=v,
        depth=0,
        parent_fingerprint=b"\x00" * 4,
        index=0,
        chain_code=hmac_[32:],
        key=k,
    )


def rootxprv_from_seed_(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> BIP32KeyData:
    """Return the BIP32 root master extended private key of a seed.

    `rootxprv_from_seed` below is this with the Base58Check encoding on
    top, and the trailing underscore says which of the two this is: as in
    `ecc.dsa`, it marks the spelling for a caller holding the prepared
    form -- there a message already hashed, here the extended key itself
    rather than its xprv text.

    Which is what the four object spellings of this module are for. A
    caller deriving a child public key from a seed had btclib build
    Base58Check text and read it back at every hop, three encodings and
    three decodings of a spelling that never left the module: seed to
    `m/0h/1` and neutered is 69.41 us over distinct seeds against 32.42 for
    the same three calls over `BIP32KeyData`, and 57.14 against 32.59 where
    one seed repeats and `_cached_base58_decode` answers (issue 886). The
    text is what `rootxprv_from_seed` is for, and nothing here stops
    answering it.
    """
    return _rootxprv_from_seed(seed, version)


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> str:
    """Return BIP32 root master extended private key from seed."""
    return rootxprv_from_seed_(seed, version).b58encode()


BIP32Key = BIP32KeyData | String


def _key_data_from_bip32_key(xkey: BIP32Key) -> BIP32KeyData:
    """Return the key as a valid BIP32KeyData, however it was spelled.

    What a public function taking a `BIP32Key` owes the private ones it
    calls: a string is decoded, and either spelling is validated, once
    and here. The private functions below then validate nothing, which
    is what the leading underscore says of them -- so a caller reaching
    past one of these wrappers owes its callee the same guarantee this
    provides.

    The key is validated as it stands, before `_derive` changes its
    depth: the depth-zero rule is a statement about the index and the
    parent fingerprint of *this* key, and at the final depth of a path
    it no longer says anything.
    """
    if isinstance(xkey, BIP32KeyData):
        xkey.assert_valid()
        return xkey
    return BIP32KeyData.b58decode(xkey)


def _xpub_from_xprv(xprv: BIP32KeyData) -> BIP32KeyData:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign
    transactions).
    """
    if xprv.key[0] != 0:
        # the offending key is public here, but never echo a
        # serialized xkey: the prefix already says what is wrong
        err_msg = f"not a private key: prefix 0x{xprv.key[:1].hex()}"
        raise BTClibValueError(err_msg)

    q = int.from_bytes(xprv.key[1:], byteorder="big", signed=False)

    return BIP32KeyData(
        version=xpubversion_from_xprvversion(xprv.version),
        depth=xprv.depth,
        parent_fingerprint=xprv.parent_fingerprint,
        index=xprv.index,
        chain_code=xprv.chain_code,
        key=bytes_from_prv_key_int(q),
        check_validity=False,
    )


def xpub_from_xprv_(xprv: BIP32Key) -> BIP32KeyData:
    """Neutered Derivation (ND), answering the extended key itself.

    `xpub_from_xprv` below is this with the Base58Check encoding on top;
    the trailing underscore is `rootxprv_from_seed_`'s, and says the same
    thing.
    """
    xkey = _xpub_from_xprv(_key_data_from_bip32_key(xprv))
    # the output check the text spelling got from `b58encode`, which is
    # what `serialize` inside it does: `_xpub_from_xprv` builds with
    # `check_validity=False`, so this is the one validation of the key
    # answered here -- and it is the whole of what the encoding was
    # validating, 0.64 us of its 6.73
    xkey.assert_valid()
    return xkey


def xpub_from_xprv(xprv: BIP32Key) -> str:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign
    transactions).
    """
    # check_validity=False: `xpub_from_xprv_` has just made that check on
    # the key it answered
    return xpub_from_xprv_(xprv).b58encode(check_validity=False)


def fingerprint(xkey: BIP32Key) -> bytes:
    """Return the four octets BIP32 identifies an extended key by.

    The first four of the HASH160 of the compressed public key, which is
    what BIP32 defines the fingerprint as and what a `BIP32KeyOrigin`
    names its master with.

    Here and not in a converter, because it is bip32's own idea: nothing
    outside this module's formats has a fingerprint (issue #1188). Every
    reader of the four octets is this module's or sits above it --
    `derive` below writes a parent's into each child it makes,
    `crack_prv_key_var` reads one back to tell whether a parent and a
    child are that pair, and `psbt`'s origins carry one to name a
    master.

    An xprv answers with its xpub's, the fingerprint being the public
    key's: a pair that gave two would identify one key twice. The
    neutering is `_xpub_from_xprv`'s, so the two spellings share the
    derivation rather than agreeing by coincidence.
    """
    xkey_data = _key_data_from_bip32_key(xkey)
    if xkey_data.is_private:
        xkey_data = _xpub_from_xprv(xkey_data)
    return hash160(xkey_data.key)[:4]


# repr=False: a generated __repr__ would print key and prv_key_int, the
# private scalar and the key material BIP32KeyData's own masking repr
# exists to hide -- this struct has no repr of its own to mask with, so
# it takes the default's silence instead
@dataclass(repr=False)
class _BIP32KeyData:
    """The mutable working copy the derivation loop rewrites in place.

    Not a `BIP32KeyData`, and deliberately: that class is frozen so a
    public function can trust one it is handed (issue 727), and
    `dataclasses` refuses a mutable dataclass inheriting from a frozen
    one. `__prv_key_derivation`, `__pub_key_derivation` and the two
    path-walkers below mutate `chain_code`, `key`, `prv_key_int` and
    `parent_fingerprint` field by field across up to 255 levels of a
    path, for the measured performance reasons their own comments give;
    `_derive` builds one, mutates it, and hands a real `BIP32KeyData`
    back built from its final fields -- one allocation for the whole
    path, not one per level. Never validates and never coerces: every
    field always comes from a `BIP32KeyData` already valid or from this
    same loop, so there is nothing here for `check_validity` to gate.

    `prv_key_int` is the one intermediate result multi-level derivation
    reuses: do not rely on it elsewhere. The public counterpart a
    private key needs is not cached beside it -- `__prv_key_path_derivation`
    computes it once, for the fingerprint, and hands it to the step that
    would recompute it; a point cached here would instead be built for
    every key, including the public ones that never look at it.
    """

    version: bytes
    depth: int
    parent_fingerprint: bytes
    index: int
    chain_code: bytes
    key: bytes
    prv_key_int: int  # non-zero for private key only

    @property
    def is_private(self) -> bool:
        """Answer whether the key is private, by its 0x00 prefix."""
        return self.key[0] == 0


# the group order as the 32 octets a scalar is written in: big-endian
# bytes of one width compare as the numbers they spell, so the range
# check BIP32 makes of the hmac's left half is made where the hash left
# it, and neither the check nor the tweak that follows reads an integer
# out of it
_N_BYTES = secp256k1.n.to_bytes(secp256k1.n_size, byteorder="big")


def _invalid_child(index: int, reason: str) -> BTClibValueError:
    """Return the error for a child BIP32 declares invalid.

    BIP32 has three of these -- parse256(IL) >= n, a zero private child,
    a public child at infinity -- and tells the caller to "proceed with
    the next value for i". Raising says so rather than deriving that
    next index silently: this code is asked for one index, and returning
    the key of another is a substitution nothing downstream could
    detect. Bitcoin Core answers the same way, CKDpriv returning false
    and leaving the choice to whoever picked the path.

    At odds of about 2^-127 none of the three is reachable, so what this
    buys is a defined answer rather than a key no other wallet derives.
    """
    err_msg = f"invalid child index {index}: {reason}"
    err_msg += "; BIP32 mandates deriving the next index instead"
    return BTClibValueError(err_msg)


def __prv_key_derivation(xkey: _BIP32KeyData, index: int, pub_key: bytes) -> None:
    xb = (
        xkey.key
        if index >= _HARDENED_OFFSET
        else pub_key or bytes_from_prv_key_int(xkey.prv_key_int)
    )
    xb += index.to_bytes(4, byteorder="big", signed=False)
    hmac_ = hmac.new(xkey.chain_code, xb, "sha512").digest()
    offset = hmac_[:32]
    if offset >= _N_BYTES:
        raise _invalid_child(index, "the hmac left half is not a valid scalar")

    # the sum of two scalars, one of them the parent private key:
    # secp256k1_ec_seckey_tweak_add computes it in constant time, where
    # Python's own `(a + b) % n` is variable in time with the operands
    # and leaves an unzeroized copy of each intermediate behind. The key
    # goes in as the 32 bytes it is stored as rather than as
    # xkey.prv_key_int, so that no arithmetic on the secret happens
    # here; it costs 0.55 us against 0.03, on a derivation whose hmac
    # and public key are some 15 us of their own.
    #
    # The dispatch is not on the curve, BIP32 being defined for secp256k1
    # alone: it is on whether the bindings are there to serve it, which is
    # the one question `_libsecp256k1_serves` answers that another curve
    # would not have asked. What the Python arm below is for is a caller
    # without them, and SECURITY.md says of it what it says of every
    # Python path: the arithmetic is on integers and is not constant-time
    if _libsecp256k1_serves(secp256k1, None):
        try:
            key = libsecp256k1_keys.prvkey_tweak_add(xkey.key[1:], offset)
        except ValueError as e:
            # past the range check above, the one sum libsecp256k1 refuses
            # is the zero BIP32 refuses too
            raise _invalid_child(index, "the child private key is zero") from e
        prv_key_int = int.from_bytes(key, byteorder="big", signed=False)
    else:
        # ki = parse256(IL) + kpar (mod n), which is BIP32's own equation
        prv_key_int = (
            xkey.prv_key_int + int.from_bytes(offset, byteorder="big", signed=False)
        ) % secp256k1.n
        if prv_key_int == 0:
            raise _invalid_child(index, "the child private key is zero")
        key = prv_key_int.to_bytes(32, byteorder="big", signed=False)

    # xkey is mutated only past the checks, so a rejected index leaves
    # it the key it was rather than half a derivation
    xkey.chain_code = hmac_[32:]
    xkey.prv_key_int = prv_key_int
    xkey.key = b"\x00" + key


def _pub_key_offset(chain_code: bytes, key: bytes, index: int) -> tuple[bytes, bytes]:
    """Return what an unhardened index adds, and the child chain code.

    The scalar alone, without the point it is added to: BIP32 derives a
    public child as P + IL*G, so this is the whole of the arithmetic that
    a caller which is not deriving a key of its own needs --
    `pub_key_derivation_tweaks` below, and through it the MuSig2
    aggregate keys of BIP328, which have no private key to derive with.

    The 32 octets of the hmac's left half, not the integer they spell:
    what reads them is `keys.pubkey_tweak_add`, which takes octets, and
    what `pub_key_derivation_tweaks` answers is octets too, so an integer
    here would be read out of the hash and written straight back.
    """
    xb = key + index.to_bytes(4, byteorder="big", signed=False)
    hmac_ = hmac.new(chain_code, xb, "sha512").digest()
    offset = hmac_[:32]
    if offset >= _N_BYTES:
        raise _invalid_child(index, "the hmac left half is not a valid scalar")
    return offset, hmac_[32:]


class _PythonPubKeyTweakChain:
    """What `keys.PubkeyTweakChain` is, in the arithmetic of this library.

    The other half of `_pub_key_offset` above: that answers the scalar a
    step adds, this adds it to the point. A path is a chain because each
    step's child is the next step's parent, so the point is held from one
    step to the next rather than parsed again out of the octets the step
    before it has just written -- which is what the bindings' class holds
    it for, and is worth more here: `point_from_octets` on a compressed
    key is a modular square root, 84.7 us where their own parse is 2.9,
    so a path of any length pays one instead of one per level.

    `curves.curve` has the same arithmetic twice over -- `_tweak_add_var`
    ends in `ec.add_var(P, mult(t, ec.G, ec))`, and `_TweakChain` is a
    point with many tweaks of it and the bindings' chain where they serve
    -- and this is not written here for want of noticing. Three things
    differ, and each is the whole of a step: `_TweakChain`'s tweaks are
    absolute, measured from the point it was built on, where BIP32's are
    successive; `_tweak_add_var` pays a `require_on_curve` per step, on a
    point this one has just computed itself; and a refused tweak drops
    `_TweakChain` to the one-shot pair and it answers the next one, where
    BIP32 has to end the path instead.

    The contract is theirs, so that `_pub_key_tweak_chain` below can
    answer either and its callers need not know which: `tweak_add`
    answers the serialized child key and raises `ValueError` for the sum
    at infinity -- which libsecp256k1 has no public key for and BIP32
    refuses too, `_invalid_child` being what the callers turn it into --
    and the constructor raises it for octets that are no point.

    Theirs for every argument a caller here passes, and `compressed` is
    where the two would part if one did not: `bytes_from_point` refuses a
    value that is not a bool and their serialization takes it for the
    flag it is truthy as. This one is the stricter, and stricter is the
    side to be on -- but it is what makes the order below matter, so it
    is written here rather than left to be rediscovered from a raise the
    other implementation does not make. Both callers pass the literal,
    `compressed` is typed `bool`, and the union alias is what has mypy
    hold them to it.

    A refused step ends the chain, which is that contract too: "pubkey
    will be set to an invalid value if this function returns 0" is what
    libsecp256k1 says of `secp256k1_ec_pubkey_tweak_add`, and that pubkey
    is what their chain holds. So there is nothing to step from
    afterwards and neither implementation defines what a further step
    answers; both callers here raise instead of asking again, a refused
    index ending the whole derivation.

    Python throughout, and it has to be: with libsecp256k1 in reach their
    class is the better answer, so a chain that mixed the two would be
    the one shape never worth building. It cannot mix as written --
    `mult` and the lift inside `point_from_octets` gate on
    `_libsecp256k1_serves(secp256k1, None)`, which is the call that chose
    this implementation, and cannot answer it differently -- and
    `test_the_python_arm_reaches_no_bindings` checks that rather than
    trusting it, a dispatch made finer-grained one day being what would
    end it silently.
    """

    def __init__(self, key: bytes) -> None:
        self._point = point_from_octets(key, secp256k1)

    def tweak_add(self, tweak: bytes, compressed: bool = True) -> bytes:
        """Return the key of point + tweak*G, and step the chain to it."""
        # Ki = point(parse256(IL)) + Kpar, which is BIP32's own equation
        point = secp256k1.add_var(
            self._point, mult(int.from_bytes(tweak, byteorder="big", signed=False))
        )
        if not point[1]:
            # y == 0 is how an affine point spells infinity here, its x
            # being arbitrary -- INF is (5, 0), and `curve_group`'s
            # add_aff_var says why: the group has one point more than a
            # pair of field elements can name, so no formula reaches that
            # spelling and the one real point with y == 0, a two-torsion
            # point, has no affine form at all. Comparing with INF would
            # test the arbitrary x as well
            raise BTClibValueError("the sum is the point at infinity")

        # serialized before the step is taken, as __prv_key_derivation
        # mutates only past its own checks: `compressed` is read by
        # bytes_from_point, which refuses a value that is not a bool, and
        # a chain left stepped by a call that raised would answer the
        # next tweak from a point its caller never received
        sec = bytes_from_point(point, secp256k1, compressed)
        self._point = point
        return sec


# the two implementations of one chain: what a caller of the function
# below holds, and neither of them a state the other has to allow for.
#
# Under TYPE_CHECKING, because the union is the annotation of two
# signatures and of nothing else: `from __future__ import annotations`
# leaves an annotation a string, while a union built at module level is
# an object, and building this one would ask the bindings for a class
# where they may not be installed. Nothing calls `get_type_hints` on
# either signature, which is what would want the name back at runtime
if TYPE_CHECKING:
    _PubKeyTweakChain = libsecp256k1_keys.PubkeyTweakChain | _PythonPubKeyTweakChain


def _pub_key_tweak_chain(key: bytes) -> _PubKeyTweakChain:
    """Return the chain a public derivation path is walked with.

    The dispatch, made once for a whole path rather than at every step of
    it: BIP32 is defined for secp256k1 alone, so what is asked here is
    not which curve this is but whether the bindings are there to serve
    it, which is the one question `_libsecp256k1_serves` answers that
    another curve would not have asked.
    """
    return (
        libsecp256k1_keys.PubkeyTweakChain(key)
        if _libsecp256k1_serves(secp256k1, None)
        else _PythonPubKeyTweakChain(key)
    )


# BIP328's chain code, which is the sha256 of "MuSig2MuSig2MuSig2": an
# aggregate key has no chain code of its own, so a synthetic xpub is the
# key plus this constant, and every implementation deriving from an
# aggregate key has to use the same one or derive other children. It sits
# beside the tweaks below because it is the other half of one fact: the
# derivation BIP328 defines is this chain code walked by that function,
# and both `psbt.musig2` and a `musig()` descriptor key expression need it
BIP328_CHAIN_CODE = bytes.fromhex(
    "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
)


def pub_key_derivation_tweaks(
    pub_key: Octets, chain_code: Octets, der_path: DerPath
) -> list[bytes]:
    """Return the 32-byte tweak each step of a public derivation adds.

    A public child is the parent point plus IL*G, so a whole path is a
    list of scalars that can be applied wherever the point itself is not
    available to derive from. That is what a BIP327 MuSig2 aggregate key
    needs: the group has no private key, so BIP328 derivation reaches the
    signers as plain tweaks of the aggregate key, and BIP373 carries a
    psbt signed under a key derived that way.

    Hardened indexes are refused before any step is walked, as
    __pub_key_path_derivation refuses them: they need a private key that
    by construction does not exist.
    """
    key = bytes_from_octets(pub_key, secp256k1.p_size + 1)
    code = bytes_from_octets(chain_code, 32)
    indexes = indexes_from_der_path(der_path)
    if any(index >= _HARDENED_OFFSET for index in indexes):
        raise BTClibValueError("invalid hardened derivation from public key")

    # one parse for the whole path rather than one per index: each step
    # still needs its own serialized key, to hash into the next tweak,
    # but not a fresh parse of the bytes the step before it just
    # serialized -- the chain holds the point in between.
    # Outside the loop and not inside an `if indexes:`, so that a path of
    # no steps is the one spelling of this call that still looks at the
    # key it was handed: [] is the right answer for it, and the right
    # answer for 33 bytes that are not a point is no answer
    try:
        chain = _pub_key_tweak_chain(key)
    except ValueError as e:
        raise BTClibValueError(f"invalid public key: {key.hex()}") from e

    tweaks: list[bytes] = []
    for index in indexes:
        offset, code = _pub_key_offset(code, key, index)
        tweaks.append(offset)
        key = chain.tweak_add(offset, compressed=True)
    return tweaks


def __pub_key_derivation(
    xkey: _BIP32KeyData, index: int, chain: _PubKeyTweakChain
) -> None:
    offset, chain_code = _pub_key_offset(xkey.chain_code, xkey.key, index)

    # the parent point plus the generator times the offset: one step is
    # 11.6 us where secp256k1_ec_pubkey_tweak_add computes it and 175.2
    # where `add_var(P, mult(t))` does, which is what a caller without
    # the bindings pays here -- the dispatch being off altogether on that
    # arm, so the multiplication is Python as well. xkey holds the key
    # serialized throughout on the delegated one: no point of btclib's
    # own is ever built, ffi.new's raw C struct staying inside the
    # bindings.
    # Compressed on the way out, which is the spelling an extended key
    # holds: asking for the uncompressed form to read a y out of it costs
    # a second serialize and the parity arithmetic that follows, for a
    # coordinate nothing here goes on to use. `chain` is __pub_key_path_
    # derivation's, held across every index of the path so that only the
    # first of them pays for parsing xkey.key rather than every one --
    # and which of the two it holds is its own business
    try:
        sec = chain.tweak_add(offset, compressed=True)
    except ValueError as e:
        # past the range check above, the one sum the chain refuses is
        # the point at infinity BIP32 refuses too
        raise _invalid_child(
            index, "the child public key is the point at infinity"
        ) from e

    xkey.chain_code = chain_code
    xkey.key = sec


def __prv_key_path_derivation(xkey: _BIP32KeyData, indexes: list[int]) -> None:
    """Derive xkey down the whole path, privately.

    The last index is derived apart from the others because the
    fingerprint a child carries is its parent's: it is taken from the
    key as it stands one derivation short of the end. The public key
    computed for it is then handed to that last derivation, which for an
    unhardened index would otherwise compute it a second time.
    """
    for index in indexes[:-1]:
        __prv_key_derivation(xkey, index, b"")
    pub_key = bytes_from_prv_key_int(xkey.prv_key_int)
    xkey.parent_fingerprint = hash160(pub_key)[:4]
    __prv_key_derivation(xkey, indexes[-1], pub_key)


def __pub_key_path_derivation(xkey: _BIP32KeyData, indexes: list[int]) -> None:
    """Derive xkey down the whole path, publicly.

    A hardened index needs the private key, so the whole path is refused
    before any of it is walked: half a derivation would leave the caller
    holding a key at neither end of the path.
    """
    if any(index >= _HARDENED_OFFSET for index in indexes):
        raise BTClibValueError("invalid hardened derivation from public key")
    chain = _pub_key_tweak_chain(xkey.key)
    for index in indexes[:-1]:
        __pub_key_derivation(xkey, index, chain)
    xkey.parent_fingerprint = hash160(xkey.key)[:4]
    __pub_key_derivation(xkey, indexes[-1], chain)


def _force_version(version: bytes, forced_version: Octets) -> bytes:
    """Return the forced version, which must be of the key's own kind.

    xprv to yprv is the same key spelled for another script type, while
    xprv to ypub would claim the key is public with the bytes still
    private -- neutering is _xpub_from_xprv and not a relabelling.
    """
    allowed_versions = (
        XPRV_VERSIONS_ALL if version in XPRV_VERSIONS_ALL else XPUB_VERSIONS_ALL
    )
    fversion = bytes_from_octets(forced_version, 4)
    if fversion not in allowed_versions:
        err_msg = "invalid version forced on the extended key"
        err_msg += f"{hex_string(fversion)}"
        raise BTClibValueError(err_msg)
    return fversion


def _derive(
    xkey: BIP32KeyData, der_path: DerPath, forced_version: Octets | None
) -> BIP32KeyData:
    indexes = indexes_from_der_path(der_path)

    final_depth = xkey.depth + len(indexes)
    if final_depth > 255:
        err_msg = f"final depth greater than 255: {final_depth}"
        raise BTClibValueError(err_msg)

    # the mutable working copy the loop below rewrites field by field:
    # the six fields come from a key the caller has validated, and the
    # one that changes here -- the depth -- is bounded on the line above
    working = _BIP32KeyData(
        version=xkey.version,
        depth=final_depth,
        parent_fingerprint=xkey.parent_fingerprint,
        index=xkey.index,
        chain_code=xkey.chain_code,
        key=xkey.key,
        prv_key_int=(
            int.from_bytes(xkey.key[1:], "big", signed=False) if xkey.is_private else 0
        ),
    )

    if forced_version:
        working.version = _force_version(working.version, forced_version)

    if indexes:
        if working.is_private:
            __prv_key_path_derivation(working, indexes)
        else:
            __pub_key_path_derivation(working, indexes)

        working.index = indexes[-1]

    # `check_validity=False`: validating here would also ask the
    # depth-zero rule about the depth this just walked to, where it no
    # longer means anything; the one validation the wrapper is entitled
    # to is its own, on what this hands back
    return BIP32KeyData(
        version=working.version,
        depth=working.depth,
        parent_fingerprint=working.parent_fingerprint,
        index=working.index,
        chain_code=working.chain_code,
        key=working.key,
        check_validity=False,
    )


def derive_(
    xkey: BIP32Key, der_path: DerPath, forced_version: Octets | None = None
) -> BIP32KeyData:
    """Derive a BIP32 key across a path, answering the extended key itself.

    `derive` below is this with the Base58Check encoding on top; the
    trailing underscore is `rootxprv_from_seed_`'s, and says the same
    thing. It is the one of the four object spellings the measurement of
    issue 886 is about: a caller deriving from a key it holds pays neither
    the decoding of the argument nor the encoding of the answer, where the
    xprv text it would have built is a string the next call decodes again.

    The path and the version are `derive`'s, and so is what they accept.
    """
    derived = _derive(_key_data_from_bip32_key(xkey), der_path, forced_version)
    # the output check the wrapper is entitled to, and the only validation
    # of the derived key. `b58encode` used to be where it happened, its
    # `serialize` being the half of it that validates: this is that half,
    # 0.64 us of the 6.73 the encoding costs
    derived.assert_valid()
    return derived


def derive(
    xkey: BIP32Key, der_path: DerPath, forced_version: Octets | None = None
) -> str:
    """Derive a BIP32 key across a path spanning multiple depth levels.

    Valid DerPath examples:

    - string like "m/44h/0'/1H/0/10"
    - iterable integer indexes
    - one single integer index
    - bytes in multiples of the 4-bytes index

    DerPath is case/blank/extra-slash insensitive
    (e.g. "M /44h / 0' /1H // 0/ 10 / ").
    """
    # check_validity=False: `derive_` has just made that check on the key
    # it answered
    return derive_(xkey, der_path, forced_version).b58encode(check_validity=False)


def _assert_valid_branch(
    mxkey: BIP32KeyData, branch: int, branches_0_1_only: bool, max_index: int
) -> None:
    if not mxkey.is_hardened:
        raise BTClibValueError("unhardened account/master key")

    if branch >= _HARDENED_OFFSET:
        raise BTClibValueError("invalid private derivation at branch level")
    if branch > max_index:
        err_msg = f"invalid branch number: {branch} is higher than {max_index}."
        raise BTClibValueError(err_msg)
    if branches_0_1_only and branch not in {0, 1}:
        raise BTClibValueError(f"invalid branch number: {branch} not in (0, 1)")


def _assert_valid_address_index(address_index: int, max_index: int) -> None:
    if address_index >= _HARDENED_OFFSET:
        raise BTClibValueError("invalid private derivation at address index level")
    if address_index > max_index:
        err_msg = f"invalid address index: {address_index} is higher than {max_index}."
        raise BTClibValueError(err_msg)


def _derive_from_account(
    mxkey: BIP32KeyData,
    branch: int,
    address_index: int,
    branches_0_1_only: bool,
    max_index: int,
) -> BIP32KeyData:
    _assert_valid_branch(mxkey, branch, branches_0_1_only, max_index)
    _assert_valid_address_index(address_index, max_index)

    return _derive(mxkey, f"m/{branch}/{address_index}", None)


def derive_from_account_(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> BIP32KeyData:
    """Derive at the given branch and index, answering the extended key.

    `derive_from_account` below is this with the Base58Check encoding on
    top; the trailing underscore is `rootxprv_from_seed_`'s, and says the
    same thing. Which is the spelling a wallet wants: `key_wallet` and
    `script_wallet` derive one of these per address, and an address is
    built from the key rather than from its text.
    """
    derived = _derive_from_account(
        _key_data_from_bip32_key(mxkey),
        branch,
        address_index,
        branches_0_1_only,
        max_index,
    )
    # the output check, as in `derive_` above and for its reason
    derived.assert_valid()
    return derived


def derive_from_account_range_(
    mxkey: BIP32Key,
    branch: int,
    address_indexes: Sequence[int],
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> list[BIP32KeyData]:
    """Derive many addresses of one branch, walking to it once.

    `derive_from_account_` above answers one, and a wallet asks for many:
    a gap-limit scan, a ranged descriptor, an account being enumerated.
    Asked one at a time, each of those walks `m/branch/index` from the
    account key, so the branch level -- which every sibling shares -- is
    derived again for every one of them, hmac and tweak and all. Here it
    is derived once and each index is one level on top of it: 20.17 us an
    address against 37.08, measured over a thousand.

    Which is the larger half of what issue 918 asked about, and not the
    half it named. The parse of the account key is one per *path* and not
    one per level -- `_PubKeyTweakChain` holds the point across the levels
    of a walk, so the branch key is never parsed from octets -- so what a
    range saves there is 2.34 us of an address that is 37, six percent
    and not worth an entry point. The level is worth one.

    A sequence rather than a first and a count, so that a scan resuming
    at a gap, or a descriptor's own list, is the argument itself. One
    address is a loss -- 42.1 us against 37.2, the branch walked and
    nothing to amortize it over -- and two already pay, 62.3 against
    73.8, so a caller with exactly one still wants
    `derive_from_account_`.

    Every index is refused by the rules `derive_from_account_` refuses
    it by, before any of them is walked: a list half derived would leave
    the caller holding the addresses before the bad index and no answer
    for the rest. The branch is refused whatever the list, an empty one
    included -- a branch that is no branch is a bad call and not a
    question nobody asked -- and is *walked* only where there is an
    index to put on it.
    """
    account = _key_data_from_bip32_key(mxkey)
    _assert_valid_branch(account, branch, branches_0_1_only, max_index)
    for address_index in address_indexes:
        _assert_valid_address_index(address_index, max_index)

    # no index is no addresses, and the branch it would have been reached
    # through is a level nobody asked for: the validation above still
    # runs, a branch that is no branch being a bad call whatever the list
    if not address_indexes:
        return []

    # check_validity=False: the branch key is not the answer and is not
    # handed back, and the depth-zero rule would be asked of a depth this
    # has just walked to -- as `_derive` says of its own return
    branch_key = _derive(account, f"m/{branch}", None)
    derived = [_derive(branch_key, f"m/{index}", None) for index in address_indexes]
    # the output check, once per key, as the single-address spelling makes
    # it on the one key it answers
    for key in derived:
        key.assert_valid()
    return derived


def derive_from_account_range(
    mxkey: BIP32Key,
    branch: int,
    address_indexes: Sequence[int],
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> list[str]:
    """Derive many addresses of one branch, as Base58Check text."""
    # check_validity=False: `derive_from_account_range_` has just checked
    return [
        key.b58encode(check_validity=False)
        for key in derive_from_account_range_(
            mxkey, branch, address_indexes, branches_0_1_only, max_index
        )
    ]


def derive_from_account(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> str:
    """Derive a key with public derivation at the given branch and index.

    It also ensures that the master key is hardened, that the branch is
    a standard receive or change, and that the index is not arbitrarily
    high.
    """
    # check_validity=False: `derive_from_account_` has just made that check
    return derive_from_account_(
        mxkey, branch, address_index, branches_0_1_only, max_index
    ).b58encode(check_validity=False)


def crack_prv_key_var(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> str:
    """Return the parent xprv from a parent xpub and a non-hardened child.

    The known break BIP32 warns about: a non-hardened child's private
    key minus the derivation offset -- computable from the xpub -- is
    the parent's, so leaking one child xprv beside the account xpub
    leaks the account. A hardened child is refused, its offset not
    being computable.
    """
    # both arguments through the one place a BIP32Key becomes a validated
    # BIP32KeyData: this function exists to demonstrate a known BIP32
    # weakness, so an answer it gives for a child its own assert_valid
    # refuses is a wrong lesson. Frozen, so aliased rather than copied --
    # there is nothing in it for a copy to protect any more
    p = _key_data_from_bip32_key(parent_xpub)

    if p.key[0] not in {2, 3}:
        raise BTClibValueError(_err_msg("parent", "not a public", p))
    c = _key_data_from_bip32_key(child_xprv)

    if c.key[0] != 0:
        raise BTClibValueError(_err_msg("child", "not a private", c))
    # check depth
    if c.depth != p.depth + 1:
        raise BTClibValueError("not a parent's child: wrong depths")

    # check fingerprint
    if c.parent_fingerprint != hash160(p.key)[:4]:
        raise BTClibValueError("not a parent's child: wrong parent fingerprint")

    if c.is_hardened:
        raise BTClibValueError("hardened child derivation")

    hmac_ = hmac.new(
        p.chain_code,
        p.key + c.index.to_bytes(4, byteorder="big", signed=False),
        "sha512",
    ).digest()
    child_q = int.from_bytes(c.key[1:], byteorder="big", signed=False)
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    parent_q = (child_q - offset) % secp256k1.n

    parent = BIP32KeyData(
        version=c.version,
        depth=p.depth,
        parent_fingerprint=p.parent_fingerprint,
        index=p.index,
        chain_code=p.chain_code,
        key=b"\x00" + parent_q.to_bytes(32, byteorder="big", signed=False),
        check_validity=False,
    )
    return parent.b58encode()


def _err_msg(
    child_or_parent: str, not_a_private_or_public: str, key: BIP32KeyData
) -> str:
    # the "not a public" branch is reached with an xprv:
    # never echo a serialized xkey, the prefix says what is wrong
    return (
        f"extended {child_or_parent} key is {not_a_private_or_public} key: "
        f"prefix 0x{key.key[:1].hex()}"
    )
