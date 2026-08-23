# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The canonical form of a bitcoin key, parsed once and carried.

**What this is for.** A public key has several spellings -- SEC octets, a
hex string of them, a point, an xpub -- and a private key has as many.
Every converter in this library takes all of them and answers a tuple, so
the canonical form is what comes *out* of a conversion and never what
goes *in*: a caller that has one has to spell it back for the next call,
which parses it again. That round trip is what `bip32.derive_` and
`to_pub_key._sec_from_pub_key` work around locally -- issues 886 and
887. Issue 896 is the same round trip where `script.taproot` reads an
internal key, and there it is this module that answers it.

`PubKeyData` and `PrvKeyData` are that cut: the spellings stay at the
boundary, the parse happens once, and what travels afterwards is an
object that knows which half it is.

**Why the SEC octets are the field and the point is derived.** The two
conversions do not cost the same. Serializing a point is a byte
concatenation; parsing a compressed one is a modular square root, whose
cost `curves.sec_point.point_from_octets` records beside the two arms
that pay it. A write is cheaper than a lift and a lift than a
derivation. The first of those two gaps is widest exactly where it
matters, at the compressed form that bitcoin uses.

So the cheap direction is paid on the way in, the dear one on first use
and kept, and `PrvKeyData.pub` is where laziness buys most. The CHANGELOG
entry for this module carries the measurements and the command that took
them: one fact in one place, and this is not the place.

That is not only a cache. **`point` is also the proof**: a length and a
prefix are what the constructor checks, and whether those octets are a
point of the curve is the question `point` answers. It is the contract
`to_pub_key._sec_from_pub_key` already states -- "the guarantee is the
caller's to complete" -- made explicit and paid once, rather than left to
each caller and paid again at every one.

**Why one type and not two.** A `PubKeySecData` beside a `PubKeyPointData`
would hand the caller a choice that is a cache decision rather than a
meaning, which is the burden this module exists to remove; any function
taking either would take a union again; and the same key in the two types
could not compare equal without performing the very conversion the split
was meant to avoid.

**Why frozen, and why not `slots=True`.** Frozen for the reason
`BIP32KeyData` is (issue 727): a public function handed one may trust it
instead of revalidating, and a mutable field would let
`check_validity=False` stay unchecked forever. Not slotted, because
`functools.cached_property` stores into the instance `__dict__` and a
slotted dataclass has none -- it raises `TypeError: No '__dict__'
attribute`. Equality and hashing read the declared fields alone, so what
a lazy property has computed never changes either, and two objects for
one key compare equal whichever of them has been asked for a point.

The compressed and uncompressed spellings of one key are **not** equal
here, and that is right rather than an oversight: they hash to different
addresses.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Any

from typing_extensions import override

from btclib.alias import Octets, Point
from btclib.curves import Curve, bytes_from_prv_key_int, point_from_octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import network_from_name
from btclib.utils import assert_type, bytes_from_octets, is_integer

__all__ = [
    "PrvKeyData",
    "PubKeyData",
]

# the two SEC forms, and the prefix each one takes. 0x04 is the
# uncompressed marker; 0x02 and 0x03 name the parity of y. A hybrid key --
# 0x06 or 0x07, both coordinates *and* a parity byte -- is SEC1 and is not
# among them: `sec_point.point_from_octets` does parse one when its
# `hybrid` argument asks for it, the script engine being the caller that
# has to accept what was mined, and it defaults to `hybrid=False` because
# nothing in bitcoin produces one. This type takes that default, so a
# hybrid key is refused here rather than carried as a canonical form
_COMPRESSED_PREFIXES = (0x02, 0x03)
_UNCOMPRESSED_PREFIX = 0x04


def _normalized(network: Any) -> Any:
    """Return a network name in the one spelling two of them share.

    `network_from_name` accepts " MainNet " for "mainnet" -- the
    tolerance issue #216 decided to keep, and `network`'s
    `_validated_network_name` is where that rule is stated. Without the
    same coercion here the two spellings build objects that are not equal
    and do not hash alike, and the claim above that equality reads the
    declared fields would be true of the fields and false of the key.

    A normalization and not a check, which is why it refuses nothing:
    `check_validity=False` means the validity checks do not run, so that
    a test can build the invalid object it means to exercise, and a
    coercion that raised would take that away. Whether the name is a
    network at all -- and whether it is a string -- stays
    `assert_valid`'s question.

    `sec` is asymmetric here, and only the refusal is inherited:
    `bytes_from_octets` refuses a wrong type whatever `check_validity`
    says, and it belongs to `utils` rather than to this module. The
    coercion beside it is this module's own, and the constructor says
    what it is for.
    """
    return network.strip().lower() if isinstance(network, str) else network


@dataclass(frozen=True, init=False)
class PubKeyData:
    """A public key as its SEC octets, on a named network.

    The octets are the field because serializing a point is cheap and
    parsing one is not; `point` is the lift, paid on first use and kept.
    The module docstring carries the reasoning and the CHANGELOG entry
    the measurements.
    """

    sec: bytes
    network: str

    def __init__(
        self,
        sec: Octets,
        network: str = "mainnet",
        *,
        check_validity: bool = True,
    ) -> None:
        # `bytes()` around it: `bytes_from_octets` returns a bytearray or
        # a memoryview as it came, deliberately, and `utils` says why --
        # `assert_valid` is a read and must not rewrite the field it
        # reads. Here the field is built rather than read, and it is
        # declared `bytes`: without the coercion a key made from a
        # bytearray is unhashable, where the docstring above promises that
        # equality and hashing read the declared fields, and one made from
        # a memoryview carries octets no concatenation accepts --
        # `script.taproot` joins a merkle root to the x it reads off
        # `sec` before hashing the pair under a tag.
        # `bytes(b)` on bytes is `b` itself, so the spelling every caller
        # of this library uses copies nothing
        object.__setattr__(self, "sec", bytes(bytes_from_octets(sec)))
        object.__setattr__(self, "network", _normalized(network))

        if check_validity:
            self.assert_valid()

    @property
    def is_compressed(self) -> bool:
        """Answer whether the key is in the compressed SEC form.

        `is_` and not `compressed`, which is what `PrvKeyData` calls the
        same idea: there it is a field, a kind the caller states and a
        WIF carries, and here it is a question about octets already in
        hand. CONTRIBUTING.md's vocabulary is what makes the two names
        differ, and the difference is the point.
        """
        return len(self.sec) == self.curve.p_size + 1

    @property
    def curve(self) -> Curve:
        """Return the curve of the network the key is on."""
        return network_from_name(self.network).curve

    @cached_property
    def point(self) -> Point:
        """Return the curve point the octets encode, lifting it once.

        The lift is the proof: `assert_valid` reads a length and a
        prefix, and whether what they frame is a point of the curve is
        what this answers. A key nobody asks this of has never been
        proved one -- deliberately, that being the trade
        `to_pub_key._sec_from_pub_key` already makes for the callers
        that hand the octets straight to a call which parses them
        anyway.
        """
        return point_from_octets(self.sec, self.curve)

    def assert_valid(self) -> None:
        """Refuse octets no SEC public key has, and an unknown network.

        A length and a prefix, and not a point: see `point`, which is
        where the curve is asked. That `sec` is bytes at all is not asked
        here, `bytes_from_octets` having refused anything else in the
        constructor whatever `check_validity` said; `network` is asked,
        `_normalized` being a coercion that refuses nothing.
        """
        assert_type(self.network, str, "network")
        # refuses a name no network has, which is what this is called for
        ec = network_from_name(self.network).curve
        if len(self.sec) == ec.p_size + 1:
            if self.sec[0] not in _COMPRESSED_PREFIXES:
                raise BTClibValueError(
                    f"invalid compressed SEC prefix: {self.sec[0]:#04x}"
                )
        elif len(self.sec) == 2 * ec.p_size + 1:
            if self.sec[0] != _UNCOMPRESSED_PREFIX:
                raise BTClibValueError(
                    f"invalid uncompressed SEC prefix: {self.sec[0]:#04x}"
                )
        else:
            # never echo the octets: a caller that reached here with
            # private material spelled them as a public key by mistake,
            # and the size is the whole of what is wrong
            raise BTClibValueError(f"invalid SEC key size: {len(self.sec)}")


@dataclass(frozen=True, init=False)
class PrvKeyData:
    """A private key as its scalar, on a named network, compressed or not.

    `compressed` is not decoration: it is what a WIF carries and what
    decides the SEC form of `pub`, so without it the public key this
    derives would not be one key but two.

    `pub` is the derivation, and it is the most expensive conversion in
    this module -- a scalar multiplication, dearer than lifting a
    compressed point -- so it is where laziness pays most.
    """

    q: int
    network: str
    compressed: bool

    def __init__(
        self,
        q: int,
        network: str = "mainnet",
        compressed: bool = True,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "q", q)
        object.__setattr__(self, "network", _normalized(network))
        object.__setattr__(self, "compressed", compressed)

        if check_validity:
            self.assert_valid()

    @override
    def __repr__(self) -> str:
        # never echo private key material, as BIP32KeyData's repr does not
        masked = f"{type(self).__name__}(q=..., network={self.network!r}"
        return f"{masked}, compressed={self.compressed!r})"

    @property
    def curve(self) -> Curve:
        """Return the curve of the network the key is on."""
        return network_from_name(self.network).curve

    @cached_property
    def pub(self) -> PubKeyData:
        """Return the public key this one derives, multiplying once.

        `check_validity=False`, and it is the one call in this module
        entitled to it. What makes the skip safe is not that
        `assert_valid` ran -- on an object built with
        `check_validity=False` it never did -- but that the two lines
        above ask everything it would: `self.curve` resolves the network
        name through `network_from_name`, which refuses one no network
        has, and `bytes_from_prv_key_int` asserts `compressed` is a bool
        and answers the SEC form by construction. Asking again is what
        CONTRIBUTING.md's "checking them a second time buys nothing"
        names, and it would be this module's own argument run backwards.
        """
        sec = bytes_from_prv_key_int(self.q, self.curve, self.compressed)
        return PubKeyData(sec, self.network, check_validity=False)

    def assert_valid(self) -> None:
        """Refuse a scalar outside 1..n-1, and an unknown network."""
        assert_type(self.network, str, "network")
        # `is_integer` and not `assert_type(self.q, int, "q")`: a bool is
        # an int to `isinstance`, and here the two mean different things
        # -- `compressed` is a kind and `q` is a number -- so True
        # reaching the scalar is a caller's mistake and not the key one.
        # That policy is one decision for the whole library, which
        # `utils.is_integer` states and `integer_policy_test.py` keeps
        if not is_integer(self.q):
            raise BTClibTypeError("not a private key scalar")
        assert_type(self.compressed, bool, "compressed")
        ec = network_from_name(self.network).curve
        if not 0 < self.q < ec.n:
            # never echo the scalar: it is the secret itself
            raise BTClibValueError("private key not in 1..n-1")
