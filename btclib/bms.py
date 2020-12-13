#!/usr/bin/env python3

# Copyright (C) 2019-2020 The btclib developers
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

https://github.com/bitcoin/bitcoin/pull/524

https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
"""

import base64
import secrets
from dataclasses import InitVar, dataclass
from hashlib import sha256
from typing import Optional, Tuple, Type, TypeVar, Union

from dataclasses_json import DataClassJsonMixin

from . import dsa
from .alias import BinaryData, String
from .base58_address import h160_from_base58_address, p2pkh, p2wpkh_p2sh
from .base58_wif import wif_from_prv_key
from .bech32_address import p2wpkh, witness_from_bech32_address
from .curve import mult, secp256k1
from .exceptions import BTClibValueError
from .network import NETWORKS
from .sec_point import bytes_from_point
from .to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from .utils import bytesio_from_binarydata, hash160

_REQUIRED_LENGHT = 65

_Sig = TypeVar("_Sig", bound="Sig")


@dataclass(frozen=True)
class Sig(DataClassJsonMixin):
    # 1 byte
    rf: int = 0
    dsa_sig: dsa.Sig = dsa.Sig(ec=secp256k1, check_validity=False)
    check_validity: InitVar[bool] = True

    def __post_init__(self, check_validity: bool) -> None:
        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        if self.rf < 27 or self.rf > 42:
            raise BTClibValueError(f"invalid recovery flag: {self.rf}")
        self.dsa_sig.assert_valid()
        if self.dsa_sig.ec != secp256k1:
            raise BTClibValueError(f"invalid curve: {self.dsa_sig.ec.name}")

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        # [1-byte recovery flag][32-bytes r][32-bytes s]
        out = self.rf.to_bytes(1, byteorder="big", signed=False)
        nsize = self.dsa_sig.ec.nsize
        out += self.dsa_sig.r.to_bytes(nsize, byteorder="big", signed=False)
        out += self.dsa_sig.s.to_bytes(nsize, byteorder="big", signed=False)
        return out

    def b64encode(self, check_validity: bool = True) -> str:
        """Return the BMS address-based signature as base64-encoding.

        First off, the signature is serialized in the
        [1-byte rf][32-bytes r][32-bytes s] compact format,
        then it is base64-encoded.
        """
        data_binary = self.serialize(check_validity)
        return base64.b64encode(data_binary).decode("ascii")

    @classmethod
    def deserialize(
        cls: Type[_Sig], data: BinaryData, check_validity: bool = True
    ) -> _Sig:

        stream = bytesio_from_binarydata(data)
        sig_bin = stream.read(_REQUIRED_LENGHT)

        if check_validity and len(sig_bin) != _REQUIRED_LENGHT:
            err_msg = f"invalid decoded length: {len(sig_bin)}"
            err_msg += f" instead of {_REQUIRED_LENGHT}"
            raise BTClibValueError(err_msg)

        rf = sig_bin[0]
        ec = secp256k1
        nsize = ec.nsize
        r = int.from_bytes(sig_bin[1 : 1 + nsize], "big", signed=False)
        s = int.from_bytes(sig_bin[1 + nsize : 1 + 2 * nsize], "big", signed=False)
        dsa_sig = dsa.Sig(r, s, ec, check_validity=False)

        return cls(rf, dsa_sig, check_validity)

    @classmethod
    def b64decode(cls: Type[_Sig], data: String, check_validity: bool = True) -> _Sig:
        """Return the verified components of the provided BMS signature.

        The address-based BMS signature can be represented
        as (rf, r, s) tuple or as base64-encoding of the compact format
        [1-byte rf][32-bytes r][32-bytes s].
        """

        if isinstance(data, str):
            data = data.strip()

        data_decoded = base64.b64decode(data)
        return cls.deserialize(data_decoded, check_validity)


def gen_keys(
    prv_key: PrvKey = None,
    network: Optional[str] = None,
    compressed: Optional[bool] = None,
) -> Tuple[str, str]:
    """Return a private/public key pair.

    The private key is a WIF, the public key is a base58 P2PKH address.
    """

    if prv_key is None:
        if network is None:
            network = "mainnet"
        ec = NETWORKS[network].curve
        # q in the range [1, ec.n-1]
        q = 1 + secrets.randbelow(ec.n - 1)
        wif = wif_from_prv_key(q, network, compressed)
    else:
        wif = wif_from_prv_key(prv_key, network, compressed)

    address = p2pkh(wif)

    return wif, address


def _magic_message(msg: String) -> bytes:

    # Electrum does strip leading and trailing spaces;
    # Bitcoin Core does not
    if isinstance(msg, str):
        msg = msg.encode()

    t = (
        b"\x18Bitcoin Signed Message:\n"
        + len(msg).to_bytes(1, byteorder="big", signed=False)
        + msg
    )
    return sha256(t).digest()


def sign(msg: String, prv_key: PrvKey, addr: Optional[String] = None) -> Sig:
    """Generate address-based compact signature for the provided message."""

    if isinstance(addr, str):
        addr = addr.strip()

    if isinstance(addr, bytes):
        addr = addr.decode("ascii")

    # first sign the message
    magic_msg = _magic_message(msg)
    q, network, compressed = prv_keyinfo_from_prv_key(prv_key)
    dsa_sig = dsa.sign(magic_msg, q)

    # now calculate the key_id
    # TODO do the match in Jacobian coordinates avoiding mod_inv
    pub_keys = dsa.recover_pub_keys(magic_msg, dsa_sig)
    Q = mult(q)
    # key_id is in [0, 3]
    # first two bits in rf are reserved for it
    key_id = pub_keys.index(Q)
    pub_key = bytes_from_point(Q, compressed=compressed)

    # finally, calculate the recovery flag
    if addr is None or addr == p2pkh(pub_key, network, compressed):
        rf = key_id + 27
        # third bit in rf is reserved for the 'compressed' boolean
        rf += 4 if compressed else 0
    # BIP137
    elif addr == p2wpkh_p2sh(pub_key, network):
        rf = key_id + 35
    elif addr == p2wpkh(pub_key, network):
        rf = key_id + 39
    else:
        raise BTClibValueError("mismatch between private key and address")

    return Sig(rf, dsa_sig)


def assert_as_valid(msg: String, addr: String, sig: Union[Sig, String]) -> None:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    if not isinstance(sig, Sig):
        sig = Sig.b64decode(sig)
    else:
        sig.assert_valid()  # 1

    magic_msg = _magic_message(msg)
    c = dsa.challenge(magic_msg, secp256k1, sha256)
    # first two bits in rf are reserved for key_id
    #    key_id = 00;     key_id = 01;     key_id = 10;     key_id = 11
    # 27-27 = 000000;  28-27 = 000001;  29-27 = 000010;  30-27 = 000011
    # 31-27 = 000100;  32-27 = 000101;  33-27 = 000110;  34-27 = 000111
    # 35-27 = 001000;  36-27 = 001001;  37-27 = 001010;  38-27 = 001011
    # 39-27 = 001100;  40-27 = 001101;  41-27 = 001110;  42-27 = 001111
    key_id = sig.rf - 27 & 0b11

    recovered_pub_key = dsa.__recover_pub_key(
        key_id, c, sig.dsa_sig.r, sig.dsa_sig.s, sig.dsa_sig.ec
    )
    Q = secp256k1._aff_from_jac(recovered_pub_key)

    try:
        _, h160, _, is_script_hash = h160_from_base58_address(addr)
        is_b58 = True
    except BTClibValueError:
        _, h160, _, is_script_hash = witness_from_bech32_address(addr)
        is_b58 = False

    compressed = sig.rf >= 31
    # signature is valid only if the provided address is matched
    pub_key = bytes_from_point(Q, compressed=compressed)
    if is_b58:
        if is_script_hash and 30 < sig.rf < 39:  # P2WPKH-P2SH
            script_pk = b"\x00\x14" + hash160(pub_key)
            if hash160(script_pk) != h160:
                raise BTClibValueError(f"wrong p2wpkh-p2sh address: {addr!r}")
        elif sig.rf < 35:  # P2PKH
            if hash160(pub_key) != h160:
                raise BTClibValueError(f"wrong p2pkh address: {addr!r}")
        else:
            err_msg = f"invalid recovery flag: {sig.rf} (base58 address {addr!r})"
            raise BTClibValueError(err_msg)
    else:
        if sig.rf > 38 or 30 < sig.rf < 35:  # P2WPKH
            if hash160(pub_key) != h160:
                raise BTClibValueError(f"wrong p2wpkh address: {addr!r}")
        else:
            err_msg = f"invalid recovery flag: {sig.rf} (bech32 address {addr!r})"
            raise BTClibValueError(err_msg)


def verify(msg: String, addr: String, sig: Union[Sig, String]) -> bool:
    """Verify address-based compact signature for the provided message."""

    # all kind of Exceptions are catched because
    # verify must always return a bool
    try:
        assert_as_valid(msg, addr, sig)
    except Exception:  # pylint: disable=broad-except
        return False
    else:
        return True
