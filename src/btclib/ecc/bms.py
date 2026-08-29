# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin message signing (BMS): address-based signatures over text.

A BMS signature proves control of the private key behind an address.
The scheme is ECDSA under an envelope: the message is prefixed by the
magic "Bitcoin Signed Message:\\n" string -- so that a signed message
can never double as a transaction signature -- and the hash of the
envelope is what is signed. The serialization is the compact 65-byte
[1-byte recovery flag][32-byte r][32-byte s], customarily exchanged
as base64 text, not the DER of transaction signatures.

A vague statement can be replayed out of the context it was signed
for, so a message worth signing names its signer, its date, its
addressee, and its purpose.

The scheme works on key pairs, the address only identifying one: the
signer needs the private key behind the address, from a wallet or
supplied directly. The verifier needs no public key at all, ECDSA
allowing recovery: the candidate keys are implied by the signature,
and the recovery flag says which candidate -- and which address type
-- the signer meant. Explicitly, the recovery flag value is:

    key_id + (4 if compressed else 0) + 27

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address
- compressed indicates if the address is the hash of the compressed
  public key representation
- 27 identifies a p2pkh address, which is the only kind of address
  supported by Bitcoin Core;
  when the recovery flag is in the [31, 34] range of compressed
  addresses, Electrum also checks for p2wpkh-p2sh and p2wpkh
  (segwit always uses compressed public keys);
  BIP137 (Trezor) uses, instead, 35 and 39 instead of 27
  for p2wpkh-p2sh and p2wpkh (respectively)

+----------+---------+-----------------------------------------------------+
| rec flag |  key id | address type                                        |
+==========+=========+=====================================================+
|    27    |    0    | p2pkh uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    28    |    1    | p2pkh uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    29    |    2    | p2pkh uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    30    |    3    | p2pkh uncompressed                                  |
+----------+---------+-----------------------------------------------------+
|    31    |    0    | p2pkh compressed (also Electrum p2wpkh-p2sh/p2wpkh) |
+----------+---------+-----------------------------------------------------+
|    32    |    1    | p2pkh compressed (also Electrum p2wpkh-p2sh/p2wpkh) |
+----------+---------+-----------------------------------------------------+
|    33    |    2    | p2pkh compressed (also Electrum p2wpkh-p2sh/p2wpkh) |
+----------+---------+-----------------------------------------------------+
|    34    |    3    | p2pkh compressed (also Electrum p2wpkh-p2sh/p2wpkh) |
+----------+---------+-----------------------------------------------------+
|    35    |    0    | BIP137 (Trezor) p2wpkh-p2sh                         |
+----------+---------+-----------------------------------------------------+
|    36    |    1    | BIP137 (Trezor) p2wpkh-p2sh                         |
+----------+---------+-----------------------------------------------------+
|    37    |    2    | BIP137 (Trezor) p2wpkh-p2sh                         |
+----------+---------+-----------------------------------------------------+
|    38    |    3    | BIP137 (Trezor) p2wpkh-p2sh                         |
+----------+---------+-----------------------------------------------------+
|    39    |    0    | BIP137 (Trezor) p2wpkh                              |
+----------+---------+-----------------------------------------------------+
|    40    |    1    | BIP137 (Trezor) p2wpkh                              |
+----------+---------+-----------------------------------------------------+
|    41    |    2    | BIP137 (Trezor) p2wpkh                              |
+----------+---------+-----------------------------------------------------+
|    42    |    3    | BIP137 (Trezor) p2wpkh                              |
+----------+---------+-----------------------------------------------------+

This implementation endorses the Electrum approach: a signature
generated with a compressed WIF (i.e. without explicit address or
with a compressed p2pkh address) is valid also for the
p2wpkh-p2sh and p2wpkh addresses derived from the same WIF.

The BIP137 behaviour is available all the same: a compressed WIF
supplemented at signing time with a p2wpkh-p2sh or p2wpkh address
yields a signature valid for that address alone.

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
"""  # noqa: D301
# the "\n" a few paragraphs up is two characters, backslash and n, naming
# the magic string's own escape notation rather than embedding a newline
# in this one: an r prefix would double that backslash instead

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from hashlib import sha256

from btclib.alias import BinaryData, Octets, String
from btclib.b32 import is_segwit_prefixed, p2wpkh, witness_from_address
from btclib.b58 import h160_from_address, p2pkh, p2wpkh_p2sh, wif_from_prv_key
from btclib.curves import bytes_from_point, bytes_from_prv_key_int, secp256k1
from btclib.curves.curve import _libsecp256k1_serves
from btclib.ecc import dsa
from btclib.ecc.dsa import _libsecp256k1_recover_sec_
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import hash160, magic_message, reduce_to_hlen
from btclib.network import network_from_name
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.utils import assert_no_trailing, bytesio_from_binarydata, str_from_string

__all__ = [
    "Sig",
    "assert_as_valid",
    "gen_keys",
    "sign",
    "verify",
]

_REQUIRED_LENGTH = 65


@dataclass(frozen=True, init=False)
class Sig:
    """A Bitcoin Message Signature: recovery flag and ECDSA signature.

    The flag, 27 to 42, carries the recovery key id and the address
    type the signer claims; the signature is an ordinary dsa.Sig on
    secp256k1. The wire form is the 65-byte compact serialization,
    customarily exchanged as base64 (b64encode/b64decode).
    """

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
        """Refuse a flag outside 27..42, a curve that is not secp256k1."""
        if self.rf < 27 or self.rf > 42:
            raise BTClibValueError(f"invalid recovery flag: {self.rf}")
        self.dsa_sig.assert_valid()
        if self.dsa_sig.ec != secp256k1:
            raise BTClibValueError(f"invalid curve: {self.dsa_sig.ec.name}")

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the 65-byte compact form: flag, then r, then s."""
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
        """Build a Sig from the 65-byte compact serialization."""
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
        assert_no_trailing(data, stream, "signature")

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
        # the coercion before the strip, which is str's and bytes': what
        # is neither reached it untouched, so `bms.verify` handed a type
        # of its own choosing left as an AttributeError about a missing
        # method (issue #814). Stripping then covers what came as bytes
        # as well as what came as text: the whitespace around a copied
        # and pasted signature is the one laxity worth tolerating
        text = str_from_string(data, "base64 signature").strip()
        try:
            data_bin = text.encode("ascii")
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

    The private key is a WIF, the public key is a base58 p2pkh address.
    """
    if prv_key is None:
        if network is None:
            network = "mainnet"
        ec = network_from_name(network).curve
        # q in the range [1, ec.n-1]
        prv_key = 1 + secrets.randbelow(ec.n - 1)

    wif = wif_from_prv_key(prv_key, network, compressed)
    return wif, p2pkh(wif)


def sign(msg: Octets, prv_key: PrvKey, addr: String | None = None) -> Sig:
    """Generate address-based compact signature for the provided message."""
    magic_msg = magic_message(msg)
    q, network, compressed = prv_keyinfo_from_prv_key(prv_key)

    # signing and naming the key_id are one call, not two, and this module
    # has no dispatch of its own for it: `dsa.sign_recoverable` answers the
    # key_id whichever implementation signs, the recid libsecp256k1
    # reports being the very thing the Python signer computes anyway --
    # the parity of the nonce's point and how far its x-coordinate runs
    # past the group order. Not a search over the four candidates, one
    # recovery each until one is the signer's own key: that recomputes
    # what the signer already knows, on either path (issue 285)
    dsa_sig, key_id = dsa.sign_recoverable(magic_msg, q)

    # bytes_from_prv_key_int, not bytes_from_point(mult(q)): the address
    # wants the octets, and on secp256k1 they come out of the bindings'
    # own serialization without a point in between (issue #127)
    pub_key = bytes_from_prv_key_int(q, compressed=compressed)

    if addr is not None:
        addr = str_from_string(addr, "address").strip()

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


def assert_as_valid(msg: Octets, addr: String, sig: Sig | String) -> None:
    """Refuse a signature that does not open to the address.

    The public key is recovered from the signature under the magic
    message envelope, then rendered as the address type the recovery
    flag claims; anything short of a match is an error, verify being
    the boolean answer.
    """
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
    # bindings answering the octets themselves -- which is the mod_inv_var of
    # an affine conversion not paid either. Delegated, `verify` costs a
    # small fraction of what the Python path does, the mean over 40
    # random keys, of which the recovery itself is most and the
    # r-congruence check of the Sig validation above a little
    if _libsecp256k1_serves(secp256k1, None):
        pub_key = _libsecp256k1_recover_sec_(
            key_id, reduce_to_hlen(magic_msg), sig.dsa_sig, compressed, lower_s=False
        )
    else:
        Q = dsa.recover_pub_key(key_id, magic_msg, sig.dsa_sig, sha256)
        pub_key = bytes_from_point(Q, compressed=compressed)

    # the address says which of the three checks applies, and each of them
    # carries the recovery-flag range that belongs to its type: the flag
    # is what the signer said the address was, so a flag outside the range
    # is a signature for a different address type
    if is_segwit_prefixed(addr):
        _assert_p2wpkh(addr, sig.rf, pub_key)
        return

    script_type, h160, _ = h160_from_address(addr)

    if script_type == "p2pkh":
        _assert_p2pkh(addr, sig.rf, pub_key, h160)
        return

    # must be p2wpkh-p2sh
    _assert_p2wpkh_p2sh(addr, sig.rf, pub_key, h160)


def verify(msg: Octets, addr: String, sig: Sig | String) -> bool:
    """Verify address-based compact signature for the provided message."""
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states: what is not a valid signature
    # is False, and a caller's own mistake is refused before this rather
    # than excluded from the except
    try:
        assert_as_valid(msg, addr, sig)
    except (ValueError, BTClibRuntimeError):
        return False

    return True
