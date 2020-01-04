#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Bitcoin address-based compact signature for messages.

Bitcoin wallets use an address-based scheme for message signature: this
signature proves the control of the private key corresponding to
the given address and, consequently, of the associated bitcoins (if any).
Message signature adopts a custom compact 65 bytes signature encoding,
not the DER encoding used for transactions,
which results in 71 bytes average signature.

As it is the case for all digital signature scheme, this scheme actually
works with keys, not addresses: the address is only used to uniquely
identify a private/public keypair.
At signing time a wallet infrastructure is required to access the
private key corresponding to the given address; alternatively
the private key must be provided explicitly.
The resulting signature goes along with its address:
public key recovery is used at verification time,
i.e. given a message, the public key that would have created that signature
is found and compared with the provided address.

For a given message, the ECDSA signature operates on the hash of the
*magic* "Bitcoin Signed Message" prefix concatenated to the actual
message; this prefix manipulation avoids the plain signature of a
possibly deceiving message.
The resulting (r, s) signature is serialized as
[1 byte][r][s], where the first byte is a recovery flag used
during signature verification to discriminate among recovered
public keys and address types.
Explicitly, the recovery flag value is:

    key_id + 27 + (4 if compressed else 0)

where:

- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address;
  it is stored in the least significant 2 bits of the recovery flag
- 27 identify a P2PKH address, which is the only kind of address
  supported by Bicoin Core;
  straightforward extensions to SegWit P2WPKH-P2SH and P2WPKH are obtained
  using 35 and 39 (respectively) instead of 27: this is the BIP137 (Trezor)
  specification (Electrum has a different incompatible specification);
- compressed indicates if the address is the hash of the compressed
  public key representation (SegWit is always compressed)

+-----------+--------+--------------------+
| rec. flag | key_id |    address type    |
+===========+========+====================+
|     27    |    0   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     28    |    1   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     29    |    2   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     30    |    3   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     31    |    0   | P2PKH compressed   |
+-----------+--------+--------------------+
|     32    |    1   | P2PKH compressed   |
+-----------+--------+--------------------+
|     33    |    2   | P2PKH compressed   |
+-----------+--------+--------------------+
|     34    |    3   | P2PKH compressed   |
+-----------+--------+--------------------+
|     35    |    0   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     36    |    1   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     37    |    2   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     38    |    3   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     39    |    0   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     40    |    1   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     41    |    2   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     42    |    3   | P2WPKH (bech32)    |
+-----------+--------+--------------------+

Finally, the serialized signature is base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash);
the equal sign '=' is used as end marker of the encoded message.

Warning: one should never sign a vague statement that could be reused
out of the context it was intended for.
Always include at least

- your name (nickname, customer id, email, etc.)
- date and time
- who the message is intended for (name, business name, email, etc.)
- specific purpose of the message

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

import base64
from hashlib import sha256 as hf
from typing import Tuple, Union, Optional

from . import segwitaddress
from . import base58
from .curve import mult
from .curves import secp256k1
from .address import _h160_from_address, _P2PKH_PREFIXES, _P2SH_PREFIXES
from .wif import prvkey_from_wif
from .dsa import sign, pubkey_recovery
from .utils import octets_from_point, h160

# TODO: support msg as bytes
# TODO: add small wallet (address <-> private key) infrastructure
# TODO:                           then also add sign(address, msg)
# TODO: decouple serialization from address-based signature
# TODO: add test vectors from P. Todd's library
# TODO: report Electrum bug
# TODO: generalize to other curves and hash functions
# TODO: test P2WPKH-P2SH and P2WPKH


def _magic_hash(msg: str) -> bytes:
    # Electrum does strip leading and trailing spaces;
    # bitcoin core does not
    # msg = msg.strip()
    m = hf()
    prefix = b'\x18Bitcoin Signed Message:\n'
    m.update(prefix)
    message = chr(len(msg)) + msg
    m.update(message.encode())
    return m.digest()


def msgsign(msg: str, wif: Union[str, bytes], 
            addr: Optional[Union[str, bytes]] = None) -> bytes:
    """Generate the message signature."""

    # first sign the message
    magic_msg = _magic_hash(msg)
    prvkey, compressedwif, _ = prvkey_from_wif(wif)
    sig = sign(secp256k1, hf, magic_msg, prvkey)

    # [r][s]
    bytes_sig = sig[0].to_bytes(32, 'big') + sig[1].to_bytes(32, 'big')

    # now calculate the recovery flag, aka recId
    pubkey = mult(secp256k1, prvkey)
    pubkeys = pubkey_recovery(secp256k1, hf, magic_msg, sig)
    rf = pubkeys.index(pubkey)

    if addr is None:
        # assume p2pkh address
        rf += 27
        rf += 4 if compressedwif else 0
        # [rf][r][s]
        return base64.b64encode(bytes([rf]) + bytes_sig)

    # the following is only for BIP137
    #
    # redundant at best for P2PKH, it can only throw in case of 
    # compression mismatch between wif and adress

    # 1 determine the type of address
    # 2 verify that it corresponds to the given private key
    # 3 compute rf according to BIP137
    try:
        prefix, hash160 = _h160_from_address(addr)
        is_p2wpkh = False
        is_p2wpkh_p2sh = False
        if prefix in _P2SH_PREFIXES:
            is_p2wpkh_p2sh = True
    except Exception:
        _, wv, wp = segwitaddress._decode(addr)
        if wv != 0:
            raise ValueError(f"Invalid witness version: {wv}")
        hash160 = bytes(wp)
        is_p2wpkh = True
        is_p2wpkh_p2sh = False

    pk = octets_from_point(secp256k1, pubkey, True)
    if is_p2wpkh_p2sh:
        # scriptPubkey is 0x0014{20-byte key-hash}
        scriptPubkey = b'\x00\x14' + h160(pk)
        if h160(scriptPubkey) == hash160:
            rf += 35  # p2wpkh-p2sh
        else:
            raise ValueError("Mismatch between p2wpkh_p2sh address and key pair")
    elif is_p2wpkh:
        if h160(pk) == hash160:
            rf += 39  # p2wpkh
        else:
            raise ValueError("Mismatch between p2wpkh address and key pair")
    else:
        if h160(pk) == hash160:
            if compressedwif:
                rf += 31  # p2pkh (compressed key)
            else:
                msg = "Pubkey mismatch: "
                msg += "uncompressed wif, compressed address"
                raise ValueError(msg)
        else:  # try with uncompressed key
            pk = octets_from_point(secp256k1, pubkey, False)
            if h160(pk) == hash160:
                if compressedwif:
                    msg = "Pubkey mismatch: "
                    msg += "compressed wif, uncompressed address"
                    raise ValueError(msg)
                else:
                    rf += 27  # p2pkh (uncompressed key)
            else:
                raise ValueError("Mismatch between p2pkh address and key pair")

    # [rf][r][s]
    return base64.b64encode(bytes([rf]) + bytes_sig)


def verify(msg: str, addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    """Verify message signature for a given P2PKH address."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(msg, addr, sig)
    except Exception:
        return False


def _verify(msg: str, addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # [rf][r][s]
    sig = base64.b64decode(sig)
    if len(sig) != 65:
        raise ValueError(f"Wrong encoding length: {len(sig)} instead of 65")

    # signature is valid only if the provided address is matched

    # first: calculate hash160 from address
    try:
        prefix, hash160 = _h160_from_address(addr)
        is_p2wpkh_p2sh = False
        if prefix in _P2SH_PREFIXES:
            is_p2wpkh_p2sh = True
    except Exception:
        _, wv, wp = segwitaddress._decode(addr)
        if wv != 0:
            raise ValueError(f"Invalid witness version: {wv}")
        hash160 = bytes(wp)
        is_p2wpkh_p2sh = False

    # second: recover pubkey from sig
    rf = sig[0]
    compressed = True
    if rf < 27:
        raise ValueError(f"Invalid recovery flag: {rf}")
    elif rf < 31:
        compressed = False
    elif rf > 42:
        raise ValueError(f"Invalid recovery flag: {rf}")

    r = int.from_bytes(sig[1:33], 'big')
    s = int.from_bytes(sig[33:], 'big')
    magic_msg = _magic_hash(msg)
    pubkeys = pubkey_recovery(secp256k1, hf, magic_msg, (r, s))
    i = rf + 1 & 3  # the right pubkey for both BIP137 and Electrum
    pubkey = pubkeys[i]
    pk = octets_from_point(secp256k1, pubkey, compressed)

    if is_p2wpkh_p2sh:
        # scriptPubkey is 0x0014{20-byte key-hash}
        scriptPubkey = b'\x00\x14' + h160(pk)
        return h160(scriptPubkey) == hash160
    
    return h160(pk) == hash160
