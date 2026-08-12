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

import copy
import hmac
from dataclasses import dataclass

from btclib_libsecp256k1 import keys as libsecp256k1_keys

from btclib import base58
from btclib.alias import BinaryData, Octets, String
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    DerPath,
    indexes_from_der_path,
)
from btclib.curves import (
    bytes_from_prv_key_int,
    secp256k1,
)
from btclib.curves.curve import _is_x_coordinate
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.network import NETWORKS, XPRV_VERSIONS_ALL, XPUB_VERSIONS_ALL
from btclib.utils import (
    assert_no_trailing,
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
    "crack_prv_key",
    "derive",
    "derive_from_account",
    "pub_key_derivation_tweaks",
    "rootxprv_from_seed",
    "xpub_from_xprv",
]

# secp256k1 is written out at each use rather than aliased to a module
# global "ec": BIP32 is defined for secp256k1 and for nothing else, so
# the alias was not configuration, and rebinding btclib.bip32.bip32.ec
# changed key validation for every caller in the process


_KEY_SIZE = [("version", 4), ("parent_fingerprint", 4), ("chain_code", 32), ("key", 33)]
_REQUIRED_LENGTH = 78


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
        # dropped: this is the caller _is_x_coordinate's docstring
        # describes, and the square root it exists not to pay was paid
        # once per extended key, so by every level of every derivation
        # path (issue 615). A predicate has no exception to chain, so
        # the message below is the whole of the error where it used to
        # be raised from curve_group's "invalid x-coordinate"
        x = int.from_bytes(key[1:], byteorder="big", signed=False)
        if not _is_x_coordinate(x, secp256k1):
            raise BTClibValueError(f"invalid public key: 0x{key.hex()}")
    else:
        raise BTClibValueError(f"unknown extended key version: 0x{version.hex()}")


@dataclass
class BIP32KeyData:
    """A BIP32 extended key, decoded into its six fields.

    What one xprv/xpub string holds: version, depth, parent
    fingerprint, index, chain code and the 33-byte key, private keys
    carrying their 0x00 prefix. The wire form is the 78-byte serialize
    and parse; b58encode and b58decode add the customary Base58Check
    spelling. repr masks the key material of a private one.
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
        self.version = bytes_from_octets(version)
        # a coercion, where the annotation already says int, for the same
        # reason bytes_from_octets is called on the four Octets fields:
        # from_dict feeds this constructor a json object, where a whole
        # number may arrive as a float. Coercing in assert_valid instead
        # would rewrite the object it is asked to inspect -- and it is
        # called by serialize() and to_dict(), so reading a key would
        # mutate it. A bool is refused rather than coerced: `true` out of
        # json is a schema error, not depth one
        self.depth = int_from_json_number(depth, "depth")
        self.parent_fingerprint = bytes_from_octets(parent_fingerprint)
        self.index = int_from_json_number(index, "index")
        self.chain_code = bytes_from_octets(chain_code)
        self.key = bytes_from_octets(key)

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
        """Build a BIP32KeyData from its xprv/xpub Base58Check text."""
        if isinstance(address, str):
            address = address.strip()

        xkey_bin = base58.decode(address)
        return cls.parse(xkey_bin, check_validity=check_validity)


def _rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> BIP32KeyData:
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


def rootxprv_from_seed(
    seed: Octets, version: Octets = NETWORKS["mainnet"].bip32_prv
) -> str:
    """Return BIP32 root master extended private key from seed."""
    xkey = _rootxprv_from_seed(seed, version)
    return xkey.b58encode()


BIP32Key = BIP32KeyData | String


def _xpub_from_xprv(xprv: BIP32Key) -> BIP32KeyData:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign
    transactions).
    """
    if isinstance(xprv, BIP32KeyData):
        xkey = copy.copy(xprv)
    else:
        xkey = BIP32KeyData.b58decode(xprv)

    if xkey.key[0] != 0:
        # the offending key is public here, but never echo a
        # serialized xkey: the prefix already says what is wrong
        err_msg = f"not a private key: prefix 0x{xkey.key[:1].hex()}"
        raise BTClibValueError(err_msg)

    i = XPRV_VERSIONS_ALL.index(xkey.version)
    xkey.version = XPUB_VERSIONS_ALL[i]

    q = int.from_bytes(xkey.key[1:], byteorder="big", signed=False)
    xkey.key = bytes_from_prv_key_int(q)

    return xkey


def xpub_from_xprv(xprv: BIP32Key) -> str:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign
    transactions).
    """
    xkey = _xpub_from_xprv(xprv)
    return xkey.b58encode()


# repr=False: a generated __repr__ would print prv_key_int, the very
# scalar the inherited masking __repr__ exists to hide
@dataclass(repr=False)
class _BIP32KeyData(BIP32KeyData):
    # the one intermediate result multi-level derivation reuses: do not
    # rely on it elsewhere. The public counterpart a private key needs is
    # not cached beside it -- __prv_key_path_derivation computes it once,
    # for the fingerprint, and hands it to the step that would recompute
    # it; a point cached here would instead be built for every key,
    # including the public ones that never look at it

    prv_key_int: int  # non-zero for private key only

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
        super().__init__(
            version,
            depth,
            parent_fingerprint,
            index,
            chain_code,
            key,
            check_validity=False,
        )

        self.prv_key_int = (
            int.from_bytes(self.key[1:], "big", signed=False) if self.is_private else 0
        )

        if check_validity:
            self.assert_valid()


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
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    if offset >= secp256k1.n:
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
    # BIP32 is defined for secp256k1 and for nothing else, so this is
    # not gated on the curve as the rest of the library's dispatches
    # are: there is no other curve for a fallback to serve
    try:
        key = libsecp256k1_keys.prvkey_tweak_add(xkey.key[1:], offset)
    except ValueError as e:
        # past the range check above, the one sum libsecp256k1 refuses
        # is the zero BIP32 refuses too
        raise _invalid_child(index, "the child private key is zero") from e

    # xkey is mutated only past the checks, so a rejected index leaves
    # it the key it was rather than half a derivation
    xkey.chain_code = hmac_[32:]
    xkey.prv_key_int = int.from_bytes(key, byteorder="big", signed=False)
    xkey.key = b"\x00" + key


def _pub_key_offset(chain_code: bytes, key: bytes, index: int) -> tuple[int, bytes]:
    """Return what an unhardened index adds, and the child chain code.

    The scalar alone, without the point it is added to: BIP32 derives a
    public child as P + IL*G, so this is the whole of the arithmetic that
    a caller which is not deriving a key of its own needs --
    `pub_key_derivation_tweaks` below, and through it the MuSig2
    aggregate keys of BIP328, which have no private key to derive with.
    """
    xb = key + index.to_bytes(4, byteorder="big", signed=False)
    hmac_ = hmac.new(chain_code, xb, "sha512").digest()
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    if offset >= secp256k1.n:
        raise _invalid_child(index, "the hmac left half is not a valid scalar")
    return offset, hmac_[32:]


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

    tweaks: list[bytes] = []
    for index in indexes:
        offset, code = _pub_key_offset(code, key, index)
        tweaks.append(offset.to_bytes(32, byteorder="big"))
        # the child key, which the next index hashes: the point is not
        # needed here and libsecp256k1 adds the tweak to the serialized
        # key, as __pub_key_derivation does one function below
        key = libsecp256k1_keys.pubkey_tweak_add(key, offset, compressed=True)
    return tweaks


def __pub_key_derivation(xkey: _BIP32KeyData, index: int) -> None:
    offset, chain_code = _pub_key_offset(xkey.chain_code, xkey.key, index)

    # the parent point plus the generator times the offset, which is
    # what secp256k1_ec_pubkey_tweak_add computes: 12.4 us against the
    # 33.4 of mult(offset) followed by a Python point addition, and the
    # key stays serialized throughout -- the parent's 33 bytes go in and
    # the child's come out, with no point built on either side.
    # Compressed on the way out, which is the spelling an extended key
    # holds: asking for the uncompressed form to read a y out of it costs
    # a second serialize and the parity arithmetic that follows, for a
    # coordinate nothing here goes on to use.
    #
    # Not gated on the curve, BIP32 being defined for secp256k1 alone
    try:
        sec = libsecp256k1_keys.pubkey_tweak_add(xkey.key, offset, compressed=True)
    except ValueError as e:
        # past the range check above, the one sum libsecp256k1 refuses
        # is the point at infinity BIP32 refuses too
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
    for index in indexes[:-1]:
        __pub_key_derivation(xkey, index)
    xkey.parent_fingerprint = hash160(xkey.key)[:4]
    __pub_key_derivation(xkey, indexes[-1])


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
    xkey: BIP32Key, der_path: DerPath, forced_version: Octets | None = None
) -> BIP32KeyData:
    if not isinstance(xkey, BIP32KeyData):
        xkey = BIP32KeyData.b58decode(xkey)

    indexes = indexes_from_der_path(der_path)

    final_depth = xkey.depth + len(indexes)
    if final_depth > 255:
        err_msg = f"final depth greater than 255: {final_depth}"
        raise BTClibValueError(err_msg)

    xkey = _BIP32KeyData(
        version=xkey.version,
        depth=final_depth,
        parent_fingerprint=xkey.parent_fingerprint,
        index=xkey.index,
        chain_code=xkey.chain_code,
        key=xkey.key,
    )

    if forced_version:
        xkey.version = _force_version(xkey.version, forced_version)

    if indexes:
        if xkey.is_private:
            __prv_key_path_derivation(xkey, indexes)
        else:
            __pub_key_path_derivation(xkey, indexes)

        xkey.index = indexes[-1]

    return xkey


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
    xkey = _derive(xkey, der_path, forced_version)
    return xkey.b58encode()


def _derive_from_account(
    mxkey: BIP32Key,
    branch: int,
    address_index: int,
    branches_0_1_only: bool = True,
    max_index: int = 0xFFFF,
) -> BIP32KeyData:
    if not isinstance(mxkey, BIP32KeyData):
        mxkey = BIP32KeyData.b58decode(mxkey)

    if not mxkey.is_hardened:
        raise BTClibValueError("unhardened account/master key")

    if branch >= _HARDENED_OFFSET:
        raise BTClibValueError("invalid private derivation at branch level")
    if branch > max_index:
        err_msg = f"invalid branch number: {branch} is higher than {max_index}."
        raise BTClibValueError(err_msg)
    if branches_0_1_only and branch not in {0, 1}:
        raise BTClibValueError(f"invalid branch number: {branch} not in (0, 1)")

    if address_index >= _HARDENED_OFFSET:
        raise BTClibValueError("invalid private derivation at address index level")
    if address_index > max_index:
        err_msg = f"invalid address index: {address_index} is higher than {max_index}."
        raise BTClibValueError(err_msg)

    return _derive(mxkey, f"m/{branch}/{address_index}")


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
    return _derive_from_account(
        mxkey, branch, address_index, branches_0_1_only, max_index
    ).b58encode()


def crack_prv_key(parent_xpub: BIP32Key, child_xprv: BIP32Key) -> str:
    """Return the parent xprv from a parent xpub and a non-hardened child.

    The known break BIP32 warns about: a non-hardened child's private
    key minus the derivation offset -- computable from the xpub -- is
    the parent's, so leaking one child xprv beside the account xpub
    leaks the account. A hardened child is refused, its offset not
    being computable.
    """
    if isinstance(parent_xpub, BIP32KeyData):
        p = copy.copy(parent_xpub)
    else:
        p = BIP32KeyData.b58decode(parent_xpub)

    if p.key[0] not in {2, 3}:
        raise BTClibValueError(_err_msg("parent", "not a public", p))
    if isinstance(child_xprv, BIP32KeyData):
        c = child_xprv
    else:
        c = BIP32KeyData.b58decode(child_xprv)

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

    p.version = c.version

    hmac_ = hmac.new(
        p.chain_code,
        p.key + c.index.to_bytes(4, byteorder="big", signed=False),
        "sha512",
    ).digest()
    child_q = int.from_bytes(c.key[1:], byteorder="big", signed=False)
    offset = int.from_bytes(hmac_[:32], byteorder="big", signed=False)
    parent_q = (child_q - offset) % secp256k1.n
    p.key = b"\x00" + parent_q.to_bytes(32, byteorder="big", signed=False)

    return p.b58encode()


def _err_msg(
    child_or_parent: str, not_a_private_or_public: str, key: BIP32KeyData
) -> str:
    # the "not a public" branch is reached with an xprv:
    # never echo a serialized xkey, the prefix says what is wrong
    return (
        f"extended {child_or_parent} key is {not_a_private_or_public} key: "
        f"prefix 0x{key.key[:1].hex()}"
    )
