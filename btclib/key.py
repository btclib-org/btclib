# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The canonical form of a bitcoin key, parsed once and carried.

**What this is for.** A public key has several spellings -- SEC octets, a
hex string of them, a point, an xpub -- and a private key has as many.
Every converter in this library takes all of them and answers a tuple, so
the canonical form is what comes *out* of a conversion and never what
goes *in*: a caller that has one has to spell it back for the next call,
which parses it again. That round trip is what
`bip32.derive_`, `to_pub_key._sec_from_pub_key` and
`taproot._output_pubkey_and_internal_key` each work around locally --
issues 886, 887 and 896, three patches over one cut.

`PubKeyData` and `PrvKeyData` are that cut: the spellings stay at the
boundary, the parse happens once, and what travels afterwards is an
object that knows which half it is.

**Why the SEC octets are the field and the point is derived.** The two
conversions do not cost the same. Serializing a point is a byte
concatenation; parsing a compressed one is a square root in the field.
Measured on secp256k1 over twenty thousand rounds of one key, a
compressed point costs 3.35 us to parse against the 0.99 of writing it
-- 3.4x -- where an uncompressed one costs 1.33 against 1.04, both
coordinates being there to read rather than lifted. Deriving a public
key from a private one is dearer than either, at 8.00 us.

So the cheap direction is paid on the way in, the expensive one on first
use and kept, and `PrvKeyData.pub` is where laziness buys most.

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
# bitcoin: Core has never relayed one, and `curves.sec_point` refuses it,
# so this refuses it too rather than parse what the layer below will not
_COMPRESSED_PREFIXES = (2, 3)
_UNCOMPRESSED_PREFIX = 4


@dataclass(frozen=True)
class PubKeyData:
    """A public key as its SEC octets, on a named network.

    The octets are the field because serializing a point is cheap and
    parsing one is not; `point` is the lift, paid on first use and kept.
    The module docstring carries the measurement and the reasoning.
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
        object.__setattr__(self, "sec", bytes_from_octets(sec))
        object.__setattr__(self, "network", network)

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
        where the curve is asked. That `sec` is bytes at all is not
        asked here: `bytes_from_octets` is what the constructor runs it
        through, whatever `check_validity` says, so a second check would
        re-ask a question already answered one layer down.
        """
        assert_type(self.network, str, "network")
        # refuses a name no network has, which is what this is called for
        ec = network_from_name(self.network).curve
        prefix = self.sec[0] if self.sec else None
        if len(self.sec) == ec.p_size + 1:
            if prefix not in _COMPRESSED_PREFIXES:
                raise BTClibValueError(f"invalid compressed SEC prefix: {prefix}")
        elif len(self.sec) == 2 * ec.p_size + 1:
            if prefix != _UNCOMPRESSED_PREFIX:
                raise BTClibValueError(f"invalid uncompressed SEC prefix: {prefix}")
        else:
            # never echo the octets: a caller that reached here with
            # private material spelled them as a public key by mistake,
            # and the size is the whole of what is wrong
            raise BTClibValueError(f"invalid SEC key size: {len(self.sec)}")


@dataclass(frozen=True)
class PrvKeyData:
    """A private key as its scalar, on a named network, compressed or not.

    `compressed` is not decoration: it is what a WIF carries and what
    decides the SEC form of `pub`, so without it the public key this
    derives would not be one key but two.

    `pub` is the derivation, and it is the most expensive conversion in
    this module -- a scalar multiplication, some two and a half times
    what lifting a compressed point costs -- so it is where laziness
    pays most.
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
        object.__setattr__(self, "network", network)
        object.__setattr__(self, "compressed", compressed)

        if check_validity:
            self.assert_valid()

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
        """Return the public key this one derives, multiplying once."""
        sec = bytes_from_prv_key_int(self.q, self.curve, self.compressed)
        return PubKeyData(sec, self.network)

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
