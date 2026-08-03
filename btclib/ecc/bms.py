#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Bitcoin message signing (BMS).

Bitcoin uses a P2PKH address-based scheme for message signature: such
a signature does prove the control of the private key corresponding to
the address and, consequently, of the associated bitcoins (if any).
Message signature adopts a custom compact 65-bytes (fixed size)
serialization format (i.e. not the ASN.1 DER format used for
transactions, which would results in 71-bytes average signature).

One should never sign a vague statement that could be reused
out of the context it was intended for. Always include at least:

- name (nickname, customer id, e-mail, etc.)
- date and time
- who the message is intended for (name, business name, e-mail, etc.)
- specific purpose of the message

To mitigate the risk of signing a possibly deceiving message,
for any given message a *magic* "Bitcoin Signed Message:\\n" prefix is
added, then the hash of the resulting message is signed.

This BMS scheme relies on ECDSA,
i.e. it works with private/public key pairs, not addresses:
the address is only used to identify a key pair.
At signing time, a wallet infrastructure is required to access
the private key corresponding to a given address;
alternatively, the private key must be provided explicitly.

To verify the ECDSA signature the public key is not needed
because (EC)DSA allows public key recovery:
public keys that correctly verify the signature
can be implied from the signature itself.
In the case of the Bitcoin secp256k1 curve,
two public keys are recovered
(up to four with non-zero but negligible probability);
at verification time the address must match
that public key in the recovery set
marked as the right one at signature time.

The (r, s) DSA signature is serialized as
[1-byte recovery flag][32-bytes r][32-bytes s],
in a compact 65-bytes (fixed-size) encoding.

The serialized signature is then base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash).
The equal sign '=' is used as encoding end marker.

The recovery flag is used
at verification time to discriminate among recovered
public keys (and among address types in the case
of scheme extension beyond P2PKH).
Explicitly, the recovery flag value is:

    key_id + (4 if compressed else 0) + 27

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address
- compressed indicates if the address is the hash of the compressed
  public key representation
- 27 identify a P2PKH address, which is the only kind of address
  supported by Bitcoin Core;
  when the recovery flag is in the [31, 34] range of compressed
  addresses, Electrum also check for P2WPKH-P2SH and P2WPKH
  (SegWit always uses compressed public keys);
  BIP137 (Trezor) uses, instead, 35 and 39 instead of 27
  for P2WPKH-P2SH and P2WPKH (respectively)

+----------+---------+-----------------------------------------------------+
| rec flag |  key id | address type                                        |
+==========+=========+=====================================================+
|    27    |    0    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    28    |    1    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    29    |    2    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    30    |    3    | P2PKH uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    31    |    0    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    32    |    1    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    33    |    2    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    34    |    3    | P2PKH compressed (also Electrum P2WPKH-P2SH/P2WPKH) |
+----------+---------+-----------------------------------------------------+
|    35    |    0    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    36    |    1    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    37    |    2    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    38    |    3    | BIP137 (Trezor) P2WPKH-P2SH                         |
+----------+---------+-----------------------------------------------------+
|    39    |    0    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+
|    40    |    1    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+
|    41    |    2    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+
|    42    |    3    | BIP137 (Trezor) P2WPKH                              |
+----------+---------+-----------------------------------------------------+

This implementation endorses the Electrum approach: a signature
generated with a compressed WIF (i.e. without explicit address or
with a compressed P2PKH address) is valid also for the
P2WPKH-P2SH and P2WPKH addresses derived from the same WIF.

Nonetheless, it is possible to obtain the BIP137 behaviour if
at signing time the compressed WIF is supplemented with
a P2WPKH-P2SH or P2WPKH address:
in this case the signature will be valid only for that same
address.

The message is signed and verified byte-for-byte as provided:
btclib does not strip whitespace, because the signature must commit
to the exact bytes it names. Bitcoin Core behaves the same
everywhere, its Sign/Verify Message gui dialog included, and so does
the Electrum CLI; the Electrum gui instead deliberately strips
leading and trailing blanks from the message
(https://github.com/spesmilo/electrum/issues/4327), so on a
whitespace-padded message it disagrees with all of the above: a
signature it produces commits to the stripped text, and a signature
over the exact bytes never verifies there. Two mutually exclusive
pull requests put both resolutions in front of Electrum:
https://github.com/spesmilo/electrum/pull/10787 (strip in the one
gui path that misses it, qml signing) and
https://github.com/spesmilo/electrum/pull/10788 (never strip,
matching Core and btclib).

https://github.com/bitcoin/bitcoin/pull/524

https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
"""

from __future__ import annotations

import base64
import contextlib
import secrets
from dataclasses import dataclass
from hashlib import sha256

from btclib_libsecp256k1 import recovery as libsecp256k1_recovery

from btclib.alias import BinaryData, Octets, String
from btclib.b32 import has_segwit_prefix, p2wpkh, witness_from_address
from btclib.b58 import h160_from_address, p2pkh, p2wpkh_p2sh, wif_from_prv_key
from btclib.curves import bytes_from_point, bytes_from_prv_key_int, mult, secp256k1
from btclib.curves.curve import _libsecp256k1_applicable
from btclib.ecc import dsa
from btclib.ecc.dsa import _libsecp256k1_recover_sec_
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import hash160, magic_message, reduce_to_hlen
from btclib.network import NETWORKS
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.utils import bytesio_from_binarydata

_REQUIRED_LENGTH = 65


@dataclass(frozen=True, init=False)
class Sig:
    # 1 byte
    rf: int
    dsa_sig: dsa.Sig

    # written out rather than an InitVar[bool] field and a __post_init__:
    # see the comment on dsa.Sig.__init__
    def __init__(
        self, rf: int, dsa_sig: dsa.Sig, *, check_validity: bool = True
    ) -> None:
        object.__setattr__(self, "rf", rf)
        object.__setattr__(self, "dsa_sig", dsa_sig)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        if self.rf < 27 or self.rf > 42:
            raise BTClibValueError(f"invalid recovery flag: {self.rf}")
        self.dsa_sig.assert_valid()
        if self.dsa_sig.ec != secp256k1:
            raise BTClibValueError(f"invalid curve: {self.dsa_sig.ec.name}")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        # [1-byte recovery flag][32-bytes r][32-bytes s]
        n_size = self.dsa_sig.ec.n_size
        return b"".join(
            [
                self.rf.to_bytes(1, byteorder="big", signed=False),
                self.dsa_sig.r.to_bytes(n_size, byteorder="big", signed=False),
                self.dsa_sig.s.to_bytes(n_size, byteorder="big", signed=False),
            ]
        )

    def b64encode(self, *, check_validity: bool = True) -> str:
        """Return the BMS address-based signature as base64-encoding.

        First off, the signature is serialized in the [1-byte
        rf][32-bytes r][32-bytes s] compact format, then it is
        base64-encoded.
        """
        data_binary = self.serialize(check_validity=check_validity)
        return base64.b64encode(data_binary).decode("ascii")

    @classmethod
    def parse(cls: type[Sig], data: BinaryData, *, check_validity: bool = True) -> Sig:
        stream = bytesio_from_binarydata(data)
        sig_bin = stream.read(_REQUIRED_LENGTH)

        # the length is checked whatever check_validity says: it is not
        # an opinion about the signature, it is what makes the slices
        # below mean anything. Skipped, a short buffer would still yield
        # a Sig, r and s coming from truncated slices -- every input
        # sharing a prefix mapping to the same signature
        if len(sig_bin) != _REQUIRED_LENGTH:
            err_msg = f"invalid decoded length: {len(sig_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGTH}"
            raise BTClibValueError(err_msg)

        rf = sig_bin[0]
        ec = secp256k1
        n_size = ec.n_size
        r = int.from_bytes(sig_bin[1 : 1 + n_size], "big", signed=False)
        s = int.from_bytes(sig_bin[1 + n_size : 1 + 2 * n_size], "big", signed=False)
        dsa_sig = dsa.Sig(r, s, ec, check_validity=False)

        return cls(rf, dsa_sig, check_validity=check_validity)

    @classmethod
    def b64decode(cls: type[Sig], data: String, *, check_validity: bool = True) -> Sig:
        """Return the verified components of the provided BMS signature.

        The address-based BMS signature can be represented as (rf, r, s)
        tuple or as base64-encoding of the compact format [1-byte
        rf][32-bytes r][32-bytes s].
        """
        # b64decode discards whatever is not in the base64 alphabet,
        # which would make a signature reachable from unboundedly many
        # strings. validate=True rejects that junk, but it is not enough
        # on its own: what it makes of padding depends on the
        # interpreter, and not in one direction -- 3.11 takes the excess
        # pad of "AAAA===" that 3.10 and 3.14 refuse, while 3.14 refuses
        # the pad after a complete group in "QUJD=" that both of them
        # take -- and every version discards the bits a non-final group
        # leaves over. What settles it everywhere is requiring the
        # canonical encoding, the one b64encode gives back.
        # Stripping covers bytes as well as str: the whitespace around a
        # copied and pasted signature is the one laxity worth tolerating
        data = data.strip()
        try:
            data_bin = data.encode("ascii") if isinstance(data, str) else data
            data_decoded = base64.b64decode(data_bin, validate=True)
        except ValueError as e:  # binascii.Error and UnicodeEncodeError
            raise BTClibValueError(f"invalid base64 encoding: {e}") from e
        if base64.b64encode(data_decoded) != data_bin:
            raise BTClibValueError("invalid base64 encoding: not canonical")
        return cls.parse(data_decoded, check_validity=check_validity)


def gen_keys(
    prv_key: PrvKey | None = None,
    network: str | None = None,
    compressed: bool | None = None,
) -> tuple[str, str]:
    """Return a private/public key pair.

    The private key is a WIF, the public key is a base58 P2PKH address.
    """
    if prv_key is None:
        if network is None:
            network = "mainnet"
        ec = NETWORKS[network].curve
        # q in the range [1, ec.n-1]
        prv_key = 1 + secrets.randbelow(ec.n - 1)

    wif = wif_from_prv_key(prv_key, network, compressed)
    return wif, p2pkh(wif)


def _search_key_id(magic_msg: bytes, dsa_sig: dsa.Sig, q: int) -> int:
    """Return the key_id that recovers the public key of q.

    The candidate that is this key, named by the key_id that recovers it.
    key_id is in [0, 3], and the first two bits in rf are reserved for it.

    This is the question a recoverable signature answers as it signs, so
    `sign` asks it only where the bindings are not the signer.
    """
    # one candidate at a time, stopping at the match, rather than
    # dsa.recover_pub_keys(magic_msg, dsa_sig).index(Q) -- every candidate
    # and then a search. Two things this buys: on secp256k1 the list is
    # key_ids 0 and 1, since a signer's own key has j = 0, so key_ids 2
    # and 3 would be computed only to be dropped -- each a Python
    # _double_mult when r + ec.n - ec.p happens to be on the curve, about
    # half the time; measured over 40 random (key, msg) pairs, 18.7 ms
    # against 9.0 ms here, a factor of 2. And .index names the key_id only
    # while no earlier candidate has dropped out of that list, which is
    # exactly what the j = 1 case does: r + ec.n < ec.p with r not a
    # coordinate on the curve leaves [key_id 2, key_id 3] and an index of
    # 0 or 1
    #
    # a mod_inv per candidate is the price of comparing affine points, and
    # the match could be made in Jacobian coordinates instead (issue 183);
    # measured, it is not worth reaching into dsa's private layer for, the
    # two inversions of an aff_from_jac being 37 us against the 5900 us of
    # the recovery that produced the point
    Q = mult(q)
    for key_id in range(2 * (secp256k1.cofactor + 1)):
        # a candidate can fail either half of SEC 1 v.2 step 1.6, which
        # means "not this one" and not "no key": see dsa._recover_pub_keys_
        with contextlib.suppress(BTClibValueError, BTClibRuntimeError):
            if dsa.recover_pub_key(key_id, magic_msg, dsa_sig) == Q:
                return key_id

    # unreachable: dsa_sig was just signed with q, so some key_id does
    # recover the public key of q
    err_msg = "no key_id recovers the public key"  # pragma: no cover
    raise BTClibRuntimeError(err_msg)  # pragma: no cover


def sign(msg: Octets, prv_key: PrvKey, addr: String | None = None) -> Sig:
    """Generate address-based compact signature for the provided message."""
    magic_msg = magic_message(msg)
    q, network, compressed = prv_keyinfo_from_prv_key(prv_key)

    # signing and naming the key_id are one call, not two: recoverable
    # signing is the shape libsecp256k1 offers precisely because the recid
    # falls out of the signature -- it is the parity of the nonce's point
    # and whether its x-coordinate exceeded the group order, both of which
    # the signer had in hand -- so `_search_key_id` does not get faster,
    # it goes away. 102 us against 4360, the mean over 40 random keys, and
    # the search was all of it: 2977 us where the signer's key is key_id 0
    # and one recovery finds it, 5492 where it is key_id 1 and the first
    # candidate is computed only to be discarded. 76 of the 102 that
    # remain are the Sig validation below
    if _libsecp256k1_applicable(secp256k1):
        sig_bytes, key_id = libsecp256k1_recovery.sign(reduce_to_hlen(magic_msg), q)
        n_size = secp256k1.n_size
        r = int.from_bytes(sig_bytes[:n_size], byteorder="big", signed=False)
        s = int.from_bytes(sig_bytes[n_size:], byteorder="big", signed=False)
        # check_validity=False, and the Sig returned below does validate:
        # asserting r congruent to an x-coordinate is a modular square
        # root, 76 us of the 102, and paying it twice over the one
        # signature is most of what is left to save here
        dsa_sig = dsa.Sig(r, s, secp256k1, check_validity=False)
    else:
        dsa_sig = dsa.sign(magic_msg, q)
        key_id = _search_key_id(magic_msg, dsa_sig, q)

    # bytes_from_prv_key_int, not bytes_from_point(mult(q)): the address
    # wants the octets, and on secp256k1 they come out of the bindings'
    # own serialization without a point in between (issue #127)
    pub_key = bytes_from_prv_key_int(q, compressed=compressed)

    if isinstance(addr, str):
        addr = addr.strip()
    elif isinstance(addr, bytes):
        addr = addr.decode("ascii")

    # finally, calculate the recovery flag
    if addr is None or addr == p2pkh(pub_key, network, compressed):
        rf = key_id + 27
        # third bit in rf is reserved for the 'compressed' boolean
        rf += 4 if compressed else 0
    # BIP137, and only for a compressed key: both spellings are segwit,
    # which has no uncompressed form, so an uncompressed key can own a
    # p2pkh address and nothing else. Without the guard the two calls
    # below would be reached with an uncompressed pub_key and raise out
    # of p2wpkh_p2sh -- "not a private or compressed public key for
    # mainnet", which names neither what was passed (a private key, for
    # mainnet) nor what failed (the address is not this key's)
    elif compressed and addr == p2wpkh_p2sh(pub_key, network):
        rf = key_id + 35
    elif compressed and addr == p2wpkh(pub_key, network):
        rf = key_id + 39
    else:
        raise BTClibValueError("mismatch between private key and address")

    return Sig(rf, dsa_sig)


def _assert_p2wpkh(addr: String, rf: int, pub_key: bytes) -> None:
    """Raise an exception unless the p2wpkh address is this key's.

    The recovery flag has to be one that names a native segwit address,
    which is two ranges and not one: 39..42, the spelling BIP137
    assigns to p2wpkh, and 31..34, the compressed p2pkh spelling, which
    is accepted because Electrum signs a native address with it.
    """
    wit_ver, h160, _ = witness_from_address(addr)
    if wit_ver != 0 or len(h160) != 20:
        raise BTClibValueError(f"not a p2wpkh address: {addr!r}")
    if not (30 < rf < 35 or rf > 38):
        raise BTClibValueError(f"invalid p2wpkh address recovery flag: {rf}")
    if hash160(pub_key) != h160:
        raise BTClibValueError(f"invalid p2wpkh address: {addr!r}")


def _assert_p2pkh(addr: String, rf: int, pub_key: bytes, h160: bytes) -> None:
    """Raise an exception unless the p2pkh address is this key's.

    27..34, i.e. everything below the first segwit spelling: p2pkh is
    the only address type an uncompressed key can own, so it is the only
    one whose flags include the uncompressed 27..30.
    """
    if rf > 34:
        raise BTClibValueError(f"invalid p2pkh address recovery flag: {rf}")
    if hash160(pub_key) != h160:
        raise BTClibValueError(f"invalid p2pkh address: {addr!r}")


def _assert_p2wpkh_p2sh(addr: String, rf: int, pub_key: bytes, h160: bytes) -> None:
    """Raise an exception unless the p2wpkh-p2sh address is this key's.

    31..38: the 35..38 BIP137 assigns to the wrapped spelling, and again
    the compressed p2pkh 31..34 that Electrum signs it with. Segwit
    either way, so an uncompressed key cannot own one.
    """
    if not 30 < rf < 39:
        raise BTClibValueError(f"invalid p2wpkh-p2sh address recovery flag: {rf}")
    script_pk = b"\x00\x14" + hash160(pub_key)
    if hash160(script_pk) != h160:
        raise BTClibValueError(f"invalid p2wpkh-p2sh address: {addr!r}")


def assert_as_valid(
    msg: Octets, addr: String, sig: Sig | String, lower_s: bool = True
) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False
    if isinstance(sig, Sig):
        sig.assert_valid()
    else:
        sig = Sig.b64decode(sig)

    # first two bits in rf are reserved for key_id
    #    key_id = 00;     key_id = 01;     key_id = 10;     key_id = 11
    # 27-27 = 000000;  28-27 = 000001;  29-27 = 000010;  30-27 = 000011
    # 31-27 = 000100;  32-27 = 000101;  33-27 = 000110;  34-27 = 000111
    # 35-27 = 001000;  36-27 = 001001;  37-27 = 001010;  38-27 = 001011
    # 39-27 = 001100;  40-27 = 001101;  41-27 = 001110;  42-27 = 001111
    key_id = sig.rf - 27 & 0b11
    magic_msg = magic_message(msg)
    compressed = sig.rf > 30
    # signature is valid only if the provided address is matched, and an
    # address is a hash of the sec octets: no point is built here, the
    # bindings answering the octets themselves -- which is the mod_inv of
    # an affine conversion not paid either. `verify` is 97 us against 2782,
    # the mean over 40 random keys, of which 76 are the r-congruence square
    # root of the Sig validation above and some 20 the recovery itself
    if _libsecp256k1_applicable(secp256k1):
        pub_key = _libsecp256k1_recover_sec_(
            key_id, reduce_to_hlen(magic_msg), sig.dsa_sig, lower_s, compressed
        )
    else:
        Q = dsa.recover_pub_key(key_id, magic_msg, sig.dsa_sig, lower_s, sha256)
        pub_key = bytes_from_point(Q, compressed=compressed)

    # the address says which of the three checks applies, and each of them
    # carries the recovery-flag range that belongs to its type: the flag
    # is what the signer said the address was, so a flag outside the range
    # is a signature for a different address type
    if has_segwit_prefix(addr):
        _assert_p2wpkh(addr, sig.rf, pub_key)
        return

    script_type, h160, _ = h160_from_address(addr)

    if script_type == "p2pkh":
        _assert_p2pkh(addr, sig.rf, pub_key, h160)
        return

    # must be P2WPKH-P2SH
    _assert_p2wpkh_p2sh(addr, sig.rf, pub_key, h160)


def verify(msg: Octets, addr: String, sig: Sig | String, lower_s: bool = True) -> bool:
    """Verify address-based compact signature for the provided message."""
    # ValueError and BTClibRuntimeError, not Exception: an input that is not
    # a valid signature is False, and so is a verification that failed, but
    # a TypeError is neither -- an hf passed as sha256() instead of sha256
    # is a caller error: raise, rather than report an invalid signature.
    # BTClibRuntimeError by name and not RuntimeError, because
    # RecursionError is one and is not an answer about a signature
    try:
        assert_as_valid(msg, addr, sig, lower_s)
    except (ValueError, BTClibRuntimeError):
        return False

    return True
