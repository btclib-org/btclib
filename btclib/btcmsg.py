#!/usr/bin/env python3

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Bitcoin address-based compact signature for messages.

Bitcoin uses an address-based scheme for message signature:
such a signature does prove the control of the private key corresponding to
the address and, consequently, of the associated bitcoins (if any).
Message signature adopts a custom compact 65-bytes serialization format
(i.e. not the ASN.1 DER format used for transactions,
which would results in 71-bytes average signature).

One should never sign a vague statement that could be reused
out of the context it was intended for. Always include at least:

- name (nickname, customer id, e-mail, etc.)
- date and time
- who the message is intended for (name, business name, e-mail, etc.)
- specific purpose of the message

To mitigate the risk of signing a possibly deceiving message,
for any given message a *magic* "Bitcoin Signed Message" prefix is added,
then the hash of the resulting message is ECDSA signed.

As it is the case for all digital signature schemes,
this scheme works with private/public key pairs, not addresses:
the address is only used to uniquely identify a private/public key pair.
At signing time, a wallet infrastructure is required to access the
private key corresponding to a given address;
alternatively, the private key must be provided explicitly.

To verify the signature the public key is not needed
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
where the first byte is the recovery flag used
at verification time to discriminate among recovered
public keys (and address types).
Explicitly, the recovery flag value is:

    key_id + (4 if compressed else 0) + 27

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address;
- compressed indicates if the address is the hash of the compressed
  public key representation
- 27 identify a P2PKH address, which is the only kind of address
  supported by Bitcoin Core;
  when the recovery flag is in the [31, 34] range of compressed addresses,
  Electrum also check for P2WPKH-P2SH and P2WPKH
  (SegWit always uses compressed public keys);
  BIP137 (Trezor) uses, instead, 35 and 39 instead of 27
  for P2WPKH-P2SH and P2WPKH (respectively).

+---------+--------+---------------------------------------------------------+
| recflag | key_id | address type                                            |
+=========+========+=========================================================+
|    27   |    0   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    28   |    1   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    29   |    2   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    30   |    3   | P2PKH uncompressed                                      |
+---------+--------+---------------------------------------------------------+
|    31   |    0   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    32   |    1   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    33   |    2   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    34   |    3   | P2PKH compressed (also P2WPKH-P2SH/P2WPKH for Electrum) |
+---------+--------+---------------------------------------------------------+
|    35   |    0   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    36   |    1   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    37   |    2   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    38   |    3   | BIP137 (Trezor) P2WPKH-P2SH                             |
+---------+--------+---------------------------------------------------------+
|    39   |    0   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+
|    40   |    1   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+
|    41   |    2   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+
|    42   |    3   | BIP137 (Trezor) P2WPKH                                  |
+---------+--------+---------------------------------------------------------+

Finally, the signature is base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash).
The equal sign '=' is used as end marker of the encoded message.

https://bitcoin.stackexchange.com/questions/10759/how-does-the-signature-verification-feature-in-bitcoin-qt-work-without-a-public

https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

https://bitcoin.stackexchange.com/questions/34135/what-is-the-strmessagemagic-good-for

https://bitcoin.stackexchange.com/questions/36838/why-does-the-standard-bitcoin-message-signature-include-a-message-prefix

https://bitcoin.stackexchange.com/questions/68844/explicit-message-length-in-bitcoin-signed-message

https://github.com/bitcoinjs/bitcoinjs-lib/blob/1079bf95c1095f7fb018f6e4757277d83b7b9d07/src/message.js#L13

https://bitcointalk.org/index.php?topic=6428

https://bitcointalk.org/index.php?topic=6430

https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106?newreg=670c5855241d4340af0cbbc960fd2dc3

https://github.com/bitcoin/bitcoin/pull/524

https://www.reddit.com/r/Bitcoin/comments/bgcgs2/can_bitcoin_core_0171_sign_message_from_segwit/

https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki

https://github.com/brianddk/bips/blob/legacysignverify/bip-0xyz.mediawiki

"""

from base64 import b64decode, b64encode
from hashlib import sha256
from typing import Optional, Tuple, Union

from . import dsa
from .base58address import h160_from_b58address, p2pkh, p2wpkh_p2sh
from .bech32address import p2wpkh, witness_from_b32address
from .curvemult import mult
from .utils import Octets, String, hash160, octets_from_point
from .base58wif import prvkeytuple_from_wif

# (rf, r, s) or base64 compact serialization (bytes or hex-string)
Sig = Union[Tuple[int, int, int], Octets]


def _magic_hash(msg: String) -> bytes:

    # Electrum does strip leading and trailing spaces;
    # Bitcoin Core does not
    if isinstance(msg, str):
        msg = msg.encode()

    t = b'\x18Bitcoin Signed Message:\n' + len(msg).to_bytes(1, 'big') + msg
    return sha256(t).digest()


def serialize(rf: int, r: int, s: int) -> bytes:
    """Return the address-based compact signature as base64-encoding.

    The compact signature is [1-byte rf][32-bytes r][32-bytes s]
    """
    if rf < 27 or rf > 42:
        raise ValueError(f"Invalid recovery flag: {rf}")
    dsa._check_sig(r, s)
    sig = bytes([rf]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return b64encode(sig)


def deserialize(base64sig: Octets) -> Tuple[int, int, int]:
    """Return the elements of the address-based compact signature.

    The compact signature is [1-byte rf][32-bytes r][32-bytes s]
    """
    sig = b64decode(base64sig)
    if len(sig) != 65:
        raise ValueError(f"Wrong signature length: {len(sig)} instead of 65")
    rf = sig[0]
    if rf < 27 or rf > 42:
        raise ValueError(f"Invalid recovery flag: {rf}")
    r = int.from_bytes(sig[1:33], byteorder='big')
    s = int.from_bytes(sig[33:], byteorder='big')
    dsa._check_sig(r, s)
    return rf, r, s


def sign(msg: String, wif: String,
         addr: Optional[String] = None) -> Tuple[int, int, int]:
    """Generate address-based compact signature for the provided message."""

    if isinstance(addr, str):
        addr = addr.strip()
        addr = addr.encode('ascii')

    # first sign the message
    magic_msg = _magic_hash(msg)
    q, compressed, _ = prvkeytuple_from_wif(wif)
    r, s = dsa.sign(magic_msg, q)

    # now calculate the key_id
    pubkeys = dsa.pubkey_recovery(magic_msg, (r, s))
    Q = mult(q)
    key_id = pubkeys.index(Q)
    pubkey = octets_from_point(Q, compressed)

    # finally, calculate the recovery flag
    if addr is None or addr == p2pkh(pubkey):
        rf = key_id + 27
        rf += 4 if compressed else 0
    # BIP137
    elif addr == p2wpkh_p2sh(pubkey):
        rf = key_id + 35
    elif addr == p2wpkh(pubkey):
        rf = key_id + 39
    else:
        raise ValueError("Mismatch between private key and address")

    return rf, r, s


def verify(msg: String, addr: String, sig: Sig) -> bool:
    """Verify address-based compact signature for the provided message."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(msg, addr, sig)
    except Exception:
        return False


def _verify(msg: String, addr: String, sig: Sig) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False


    if isinstance(sig, tuple):
        rf, r, s = sig
        dsa._check_sig(r, s)
    else:
        # it is a base64 sig
        rf, r, s = deserialize(sig)


    magic_msg = _magic_hash(msg)
    Qs = dsa.pubkey_recovery(magic_msg, (r, s))
    # key_id can be retireved as least significant 2 bits of the recovery flag
    #    key_id = 00;     key_id = 01;     key_id = 10;     key_id = 11
    # 27-27 = 000000;  28-27 = 000001;  29-27 = 000010;  30-27 = 000011
    # 31-27 = 000100;  32-27 = 000101;  33-27 = 000110;  34-27 = 000111
    # 35-27 = 001000;  36-27 = 001001;  37-27 = 001010;  38-27 = 001011
    # 39-27 = 001100;  40-27 = 001101;  41-27 = 001110;  42-27 = 001111
    key_id = rf - 27 & 0b11
    Q = Qs[key_id]

    try:
        _, h160, _, is_script_hash = h160_from_b58address(addr)
        is_b58 = True
    except Exception:
        _, h160, _, is_script_hash = witness_from_b32address(addr)
        is_b58 = False

    # signature is valid only if the provided address is matched
    compressed = True
    if rf < 31:
        compressed = False
    pubkey = octets_from_point(Q, compressed)
    if is_b58:
        if is_script_hash and 30 < rf and rf < 39:  # P2WPKH-P2SH
            script_pubkey = b'\x00\x14' + hash160(pubkey)
            return hash160(script_pubkey) == h160
        elif rf < 35:                               # P2PKH
            return hash160(pubkey) == h160
        else:
            errmsg = f"Invalid recovery flag ({rf}) for base58 address ({addr!r})"
            raise ValueError(errmsg)
    else:
        if rf > 38 or (30 < rf and rf < 35):        # P2WPKH
            return hash160(pubkey) == h160
        else:
            errmsg = f"Invalid recovery flag ({rf}) for bech32 address ({addr!r})"
            raise ValueError(errmsg)
