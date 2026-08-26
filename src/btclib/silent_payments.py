# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Silent payments, according to BIP352.

https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki

A silent payment address is published once and reused; every payment to
it lands on a *different* taproot output, so nothing on chain links two
payments to the same recipient. The recipient publishes two keys, a scan
key and a spend key, and the sender derives the output from an ECDH
shared secret between its own input keys and the scan key -- so the
output is one the sender can compute and only the recipient can spend,
with no interaction and nothing extra in the transaction.

**Where the shared secret comes from is the whole design.** It is not the
sender's ephemeral key, which would need a place in the transaction to
publish it; it is the sum of the private keys the sender is signing the
inputs with. The recipient recovers the same secret from the public keys
of those inputs, which the transaction already carries, so scanning is
one multiplication per transaction and the transaction is an ordinary
taproot spend.

The pieces, bottom-up:

- `pub_key_from_input` reads the public key of one input, and answers
  None for an input BIP352 does not count. Only p2pkh, p2wpkh,
  p2sh-p2wpkh and p2tr count: an input with conditional branches or
  several keys could be re-signed with a different set after the output
  was derived, which in a coinjoin is somebody else's malleability, and
  uncompressed keys are excluded as BIP143 already recommends.
- `prv_key_sum` and `pub_key_sum` are the two sides of the same sum, the
  taproot negation included: an x-only key has two private keys, and
  sender and recipient have to pick the same one.
- `input_hash` binds the sum to the transaction's smallest outpoint, so
  that the same input keys spent in two transactions derive two
  different outputs. `tweak_data` is that hash times the public sum,
  which is what a light-client server can publish per transaction
  (BIP352's Appendix A) and all a scanner needs.
- `shared_secret` is the multiplication both parties do, from either end.
- `output_keys` is the sender's whole operation, and `scan_outputs` the
  recipient's -- for a caller holding a light client's `tweak`, per
  BIP352's Appendix A; `scan_transaction_outputs` is the same recipient's
  operation for a caller holding the transaction itself, outpoints and
  input public keys, which is what lets it reach the bindings the way
  `output_keys` does.
- `label_tweak`, `labeled_address_from_keys` and `label_lookup` are the
  optional third piece: one published address per purpose, all sharing
  one scan key, at the cost of a subtraction per output while scanning.

**What is not here** is the transaction-level policy, which is a wallet's:
BIP352 says a transaction is worth scanning when it has a taproot output,
has an eligible input, and spends no output of segwit version above 1,
and that a sender must sign with a sighash flag that fixes the inputs --
`SIGHASH_ANYONECANPAY` breaks the protocol, the inputs being what the
secret is derived from. None of the three is a function here; the module
docstring is where they are stated, and `btclib.script.sig_hash` is where
the flags are.

secp256k1 and sha256 are not parameters, as in `btclib.ecc.musig2`:
BIP352 is defined for that pair, and the 33-byte compressed points, the
32-byte scalars and the three tags below are its serialization.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from btclib._libsecp256k1 import silentpayments as libsecp256k1_silentpayments
from btclib.alias import NetworkType, Octets, Point, String
from btclib.b32 import power_of_2_base_conversion
from btclib.bech32 import _BECH32_M_CONST, decode, encode
from btclib.curves import bytes_from_point, mult, point_from_octets, secp256k1
from btclib.curves.curve import (
    _libsecp256k1_serves,
    _sum_var,
    _tweak_add_var,
    _TweakChain,
)
from btclib.curves.sec_point import _mult_sec_var
from btclib.ecc.ssa import point_from_bip340pub_key
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160, tagged_hash
from btclib.network import network_type_from_network
from btclib.script.script_pub_key import is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh
from btclib.script.witness import Witness
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import PubKey, point_from_pub_key, pub_keyinfo_from_pub_key
from btclib.tx.out_point import OutPoint
from btclib.utils import bytes_from_octets, is_integer, is_octets, str_from_string

__all__ = [
    "K_MAX",
    "NUMS_H",
    "SilentPaymentOutput",
    "address_from_keys",
    "input_hash",
    "keys_from_address",
    "label_lookup",
    "label_tweak",
    "labeled_address_from_keys",
    "output_key",
    "output_keys",
    "prv_key_from_tweak",
    "prv_key_sum",
    "pub_key_from_input",
    "pub_key_sum",
    "scan_outputs",
    "scan_transaction_outputs",
    "shared_secret",
    "tweak_data",
]

# BIP352's tags, frozen by the specification: a different string is a
# different protocol, deriving different outputs from the same keys
_INPUTS_TAG = b"BIP0352/Inputs"
_LABEL_TAG = b"BIP0352/Label"
_SHARED_SECRET_TAG = b"BIP0352/SharedSecret"

# the human-readable parts BIP352 defines, one for mainnet and one for
# every test network: `Network.network_type` is exactly that distinction,
# so there is no per-network hrp to add to the network table
_MAINNET_HRP = "sp"
_TESTNET_HRP = "tsp"

# this document defines version 0, and reserves 31 for a change that
# breaks compatibility -- a v0 wallet must refuse a v31 address rather
# than read the part of it that it understands
_VERSION = 0
_RESERVED_VERSION = 31

# the two published keys, compressed
_PK_SIZE = 33
_PAYLOAD_SIZE = 2 * _PK_SIZE

# BIP173's checksum design gives a bech32m string of this length the
# error-detection it was designed for; BIP352 recommends the bound
# because a future version may lengthen the payload, so the 90 characters
# of a segwit address are not it and neither is the 117 a v0 address takes
_MAX_ADDRESS_SIZE = 1023

# the per-group recipient limit. Without it, a block of one transaction
# with 23255 outputs all aimed at one entity would cost that entity
# O(N^2) to scan -- minutes. K_MAX is the number of p2tr outputs a
# 100kvB transaction holds, so a standard transaction is always within it
K_MAX = 2323

# BIP341's NUMS point H, x-only: the internal key of a taproot output
# that deliberately has no key path. Such an input is skipped rather than
# counted, which is what lets an output nobody can key-spend be funded
# into a silent payment anyway
NUMS_H = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
)

# BIP341's annex prefix, which is popped off a witness stack before the
# control block is read
_ANNEX_PREFIX = 0x50


# what a label index is serialized as, and the whole of what bounds one:
# BIP352 hashes it as four bytes, most significant first, so there is no
# label above 2^32-1 and no negative one
_LABEL_SIZE = 4
_MAX_LABEL = 2**32 - 1


def _label_bytes(m: int) -> bytes:
    """Serialize a label index, most significant byte first."""
    # a bool is an int and would label 0 or 1 by accident, which is
    # `utils.is_integer`'s policy and matters here for the same reason: a
    # label read back out of json or a configuration file
    if not is_integer(m):
        raise BTClibTypeError(f"non-integer label: {m}")
    if not 0 <= m <= _MAX_LABEL:
        raise BTClibValueError(f"label not in 0..2^32-1: {m}")
    return m.to_bytes(_LABEL_SIZE, "big")


def _scalar(data: bytes, what: str) -> int:
    """Return a hash as the scalar it has to be, refusing what is not one.

    BIP352 says "fail" wherever a hash lands outside 1..n-1, and means it
    at three places: the input hash, a label and a shared-secret tweak.
    On secp256k1 either end is a hash preimage nobody has, and the
    failure is stated all the same because a protocol that continues past
    it derives an output no counterparty derives.
    """
    scalar = int.from_bytes(data, "big")
    if not 0 < scalar < secp256k1.n:
        raise BTClibValueError(f"invalid {what}: not in 1..n-1")
    return scalar


def _x_only(P: Point) -> bytes:
    """Return the 32-byte x-only serialization of a point.

    Through the compressed one, which is what refuses infinity: an x-only
    key is not a serialization of the whole group either, and a taproot
    output at infinity is not an output.
    """
    return bytes_from_point(P, secp256k1)[1:]


def _compressed_point(octets: Octets) -> Point | None:
    """Parse a compressed public key, answering None for anything else.

    BIP352 permits compressed and x-only keys and no other form, so a
    65-byte uncompressed key is an input that does not count rather than
    an error: `point_from_octets` takes the 0x04 form, and the size check
    in front of it is what keeps this to the 33-byte one.
    """
    try:
        return point_from_octets(bytes_from_octets(octets, _PK_SIZE), secp256k1)
    except (TypeError, ValueError):
        return None


def _hrp_from_network(network: str) -> str:
    """Return BIP352's hrp for a network: mainnet's, or every testnet's.

    Through `network_type_from_network` and not `NETWORKS[network]`: a
    name no network has is refused there, where indexing the table answers
    a bare `KeyError` -- which, being a `LookupError`, no `except
    BTClibValueError` written against this library would catch.
    """
    return (
        _MAINNET_HRP if network_type_from_network(network) == "main" else _TESTNET_HRP
    )


def address_from_keys(B_scan: PubKey, B_m: PubKey, network: str = "mainnet") -> str:
    """Return the bech32m silent payment address of a key pair.

    B_m is the spend key, or the spend key plus a label tweak:
    `labeled_address_from_keys` is the spelling that applies the tweak.
    """
    payload = bytes_from_point(point_from_pub_key(B_scan), secp256k1)
    payload += bytes_from_point(point_from_pub_key(B_m), secp256k1)
    data = [_VERSION, *power_of_2_base_conversion(payload, 8, 5)]
    # bech32m by the constant and not by the leading value: `encode`
    # reads the witness version of a segwit address off data[0] to choose
    # between bech32 and bech32m, and here data[0] is a silent payment
    # version -- 0, which would pick the bech32 constant and produce a
    # string no BIP352 implementation accepts
    return encode(_hrp_from_network(network), data, _BECH32_M_CONST).decode("ascii")


def keys_from_address(address: String) -> tuple[Point, Point, NetworkType]:
    """Return (B_scan, B_m, network type) from a silent payment address.

    The network type and not a network: BIP352 has one hrp for mainnet
    and one for every test network, so "tsp" says testnet, signet,
    testnet4 or regtest without saying which.

    A version above 0 is read as far as v0 defines it -- the first 66
    bytes of the payload, the rest discarded -- so that a v0 sender can
    pay a later address. v31 is refused instead, being the version BIP352
    reserves for a change that breaks exactly that.
    """
    # the coercion before the length, as in b32.witness_from_address:
    # `len` of what is neither text nor bytes is a TypeError about a
    # builtin, where the codec below would have named the argument
    addr = str_from_string(address, "address").strip().lower()
    if len(addr) > _MAX_ADDRESS_SIZE:
        err_msg = f"invalid address length: {len(addr)} > {_MAX_ADDRESS_SIZE}"
        raise BTClibValueError(err_msg)

    hrp, data = decode(addr, _BECH32_M_CONST)
    if hrp == _MAINNET_HRP:
        network_type: NetworkType = "main"
    elif hrp == _TESTNET_HRP:
        network_type = "test"
    else:
        raise BTClibValueError(f"invalid hrp: {hrp}")

    # `decode` was given the checksum constant, so it did not read a
    # version off the data part and did not require one to be there
    if not data:
        raise BTClibValueError("empty data in silent payment address")
    version = data[0]
    if version == _RESERVED_VERSION:
        raise BTClibValueError(f"reserved silent payment version: {version}")

    payload = bytes(power_of_2_base_conversion(data[1:], 5, 8, False))
    if version == _VERSION:
        if len(payload) != _PAYLOAD_SIZE:
            err_msg = f"invalid v0 payload length: {len(payload)}"
            err_msg += f" instead of {_PAYLOAD_SIZE} bytes"
            raise BTClibValueError(err_msg)
    elif len(payload) < _PAYLOAD_SIZE:
        err_msg = f"invalid v{version} payload length: {len(payload)}"
        err_msg += f" is less than the {_PAYLOAD_SIZE} bytes v0 reads"
        raise BTClibValueError(err_msg)

    B_scan = point_from_octets(payload[:_PK_SIZE], secp256k1)
    B_m = point_from_octets(payload[_PK_SIZE:_PAYLOAD_SIZE], secp256k1)
    return B_scan, B_m, network_type


def label_tweak(b_scan: PrvKey, m: int) -> int:
    """Return the scalar labelling an address with the integer m.

    The scan private key is what the tweak is derived from, so the
    recipient can recognize its own labels while scanning without holding
    the spend key: BIP352 exports the scan key on purpose, and a label
    derived from the spend key would have undone that.
    """
    b = int_from_prv_key(b_scan)
    hash_input = b.to_bytes(secp256k1.n_size, "big") + _label_bytes(m)
    return _scalar(tagged_hash(_LABEL_TAG, hash_input), "label")


def labeled_address_from_keys(
    b_scan: PrvKey, B_spend: PubKey, m: int, network: str = "mainnet"
) -> str:
    """Return the address of the spend key labelled with the integer m.

    m = 0 is the change label, reserved by convention for the outputs a
    sending wallet pays to itself; BIP352 asks a scanner to check it
    always, which is what makes that convention safe to rely on when
    recovering a wallet from a seed alone.
    """
    B_scan = mult(int_from_prv_key(b_scan))
    B_m = _tweak_add_var(point_from_pub_key(B_spend), label_tweak(b_scan, m), secp256k1)
    return address_from_keys(B_scan, B_m, network)


def label_lookup(b_scan: PrvKey, m_values: Iterable[int]) -> dict[bytes, bytes]:
    """Precompute the {label point: label tweak} map a scan reads.

    Once per wallet, not once per transaction, which is the point of it:
    scanning subtracts the candidate output from P_k and asks whether the
    difference is a label, so a wallet with M labels pays M
    multiplications here instead of M point additions per output for
    ever. Include 0 among the values unless the wallet is certain it
    never paid itself.

    The tweak is 32 bytes, big-endian -- `silentpayments.scan_outputs`'s
    own spelling of a label cache, `Mapping[bytes, bytes]`, which refuses
    a `bytearray` or a `memoryview` as a key and is what
    `scan_transaction_outputs` hands the bindings unconverted where they
    serve. `scan_outputs`'s Python loop reads the same bytes through
    `int_from_prv_key`, which already accepts 32-octet SEC input, so
    neither arm pays a conversion this function did not already do once,
    per wallet rather than per scan.
    """
    tweaks = [label_tweak(b_scan, m) for m in m_values]
    return {
        bytes_from_point(mult(t), secp256k1): t.to_bytes(secp256k1.n_size, "big")
        for t in tweaks
    }


def _pub_key_from_p2pkh(script_pub_key: bytes, script_sig: bytes) -> Point | None:
    """Find the public key in a scriptSig, whatever shape it has.

    BIP352 requires the parse rather than the template match, third-party
    malleability of a p2pkh scriptSig being what it is: `<dummy> OP_DROP
    <sig> <key>` spends the same output, so a scanner reading only the
    last push would miss the input and the payment with it. A 33-byte
    window walked backwards from the end finds the key wherever it sits,
    and the hash in the script_pub_key is what says which window it is.
    """
    key_hash = script_pub_key[3:23]
    for end in range(len(script_sig), _PK_SIZE - 1, -1):
        candidate = script_sig[end - _PK_SIZE : end]
        if hash160(candidate) == key_hash:
            # the hash matching does not make the bytes a public key: an
            # uncompressed key hashed by its own hash160 is a different
            # 20 bytes, so what reaches here and fails to parse is a
            # collision or a 0x04 prefix on 33 bytes
            point = _compressed_point(candidate)
            if point is not None:
                return point
    return None


def _pub_key_from_p2tr(script_pub_key: bytes, witness: Witness) -> Point | None:
    """Return the taproot output key, unless the input is to be skipped.

    The output key and not the key the spend used, script path included:
    a taproot input that a coinjoin peer could re-spend through its
    script path would otherwise let that peer derive the shared secret
    with one key and publish a transaction proving another, and the
    recipient would find nothing. So a script-path spend counts, and its
    output key is what counts.

    The one exception is BIP341's NUMS internal key, which says there is
    no key path to sign with: such an input is skipped, so that an output
    of that shape can be spent into a silent payment at all.
    """
    stack = list(witness.stack)
    if not stack:
        return None
    # BIP341's annex is not part of the spend and is popped first; the
    # control block is what is under it, and only a script path has one
    if len(stack) > 1 and stack[-1][:1] == bytes([_ANNEX_PREFIX]):
        stack.pop()
    if len(stack) > 1:
        internal_key = stack[-1][1:33]
        if internal_key == NUMS_H:
            return None

    # an x-only key of a script nobody validated: not every 32 bytes is
    # an x coordinate, and a taproot output carrying such bytes is
    # unspendable rather than ineligible -- skip it as the reference does
    try:
        return point_from_bip340pub_key(script_pub_key[2:], secp256k1)
    except (TypeError, ValueError):
        return None


def pub_key_from_input(
    script_pub_key: Octets,
    script_sig: Octets = b"",
    witness: Witness | None = None,
) -> Point | None:
    """Return the public key of one input, or None if it does not count.

    None is BIP352's "skip": the four eligible output types are p2pkh,
    p2wpkh, p2sh-p2wpkh and p2tr, and inside them an uncompressed key, a
    taproot NUMS internal key, a p2sh wrapping anything but p2wpkh, and a
    scriptSig or witness that carries no key at all are each skipped
    rather than refused. A transaction of nothing but skipped inputs is a
    transaction no silent payment can be made from, which is the caller's
    to notice -- `pub_key_sum` of an empty sequence says so.
    """
    spk = bytes_from_octets(script_pub_key)
    sig = bytes_from_octets(script_sig)
    wit = Witness() if witness is None else witness

    if is_p2pkh(spk):
        return _pub_key_from_p2pkh(spk, sig)
    if is_p2sh(spk):
        # the nested script is the whole scriptSig but for the push
        # opcode in front of it, and it is not checked against the hash
        # in the script_pub_key: a p2sh input whose redeem script does
        # not hash to it is unspendable, so consensus has already refused
        # the transaction, and a scanner reading one has bytes that no
        # rule constrains rather than a decision to make
        return _compressed_point(wit.stack[-1]) if is_p2wpkh(sig[1:]) and wit else None
    if is_p2wpkh(spk):
        return _compressed_point(wit.stack[-1]) if wit else None
    if is_p2tr(spk):
        return _pub_key_from_p2tr(spk, wit)
    return None


def prv_key_sum(prv_keys: Sequence[tuple[PrvKey, Octets]]) -> int:
    """Return the sum of the input private keys, taproot ones negated.

    Each pair is one input's private key and the script_pub_key it
    spends. The script and not a flag beside it: whether to negate is
    `is_p2tr` of that script, and a caller keeping a boolean in step with
    it is a caller with one more thing to get wrong.

    The negation is BIP340's two private keys per x-only key, d and n-d:
    the recipient sums the x-only public keys and so assumes the even-y
    one, and a sender that summed the other derives an output nobody
    finds.

    A sum of zero is BIP352's "fail", and it is not the same as an empty
    sequence: `Input keys sum up to zero` is a real vector -- two inputs
    whose keys are negatives -- and the payment cannot be made, the
    shared secret being the point at infinity. An intermediate zero is
    fine and is a vector too.
    """
    total = 0
    for prv_key, script_pub_key in prv_keys:
        a = int_from_prv_key(prv_key)
        if is_p2tr(bytes_from_octets(script_pub_key)) and mult(a)[1] % 2:
            a = secp256k1.n - a
        total = (total + a) % secp256k1.n
    if total == 0:
        raise BTClibValueError("input private keys sum to zero")
    return total


def pub_key_sum(pub_keys: Sequence[PubKey]) -> Point:
    """Return the sum of the input public keys, refusing infinity.

    Infinity is BIP352's "skip the transaction" on the receiving side and
    the failure `prv_key_sum` reports on the sending one; a caller
    scanning rather than paying reads it as the skip it is. An empty
    sequence is the same answer, and is what a transaction of nothing but
    skipped inputs sums to.

    One `keys.pubkey_sum` of all the terms rather than a running total
    added one at a time: what kept it here was that an intermediate sum
    at infinity is a BIP352 vector and infinity is what libsecp256k1 has
    no public key for, and `_sum_var` is where that stopped being a
    reason -- a sum at infinity comes back as a value now, and this
    function still refuses it.
    """
    total = _sum_var([point_from_pub_key(pub_key) for pub_key in pub_keys], secp256k1)
    if total[1] == 0:
        raise BTClibValueError("input public keys sum to infinity")
    return total


def input_hash(outpoints: Sequence[OutPoint], A_sum: PubKey) -> int:
    """Return the scalar binding the input keys to this transaction.

    The smallest outpoint lexicographically, hashed with the public sum:
    without it the same input keys spent in two transactions would derive
    the same outputs, and a sender could be made to pay twice to one
    address. Lexicographically on the 36 wire bytes, which are
    little-endian -- so the ordering is the transaction's own and a wallet
    parsing a serialized transaction reorders nothing.

    An empty sequence has no smallest outpoint and no input hash.
    """
    return _input_hash_(outpoints, point_from_pub_key(A_sum))


def _input_hash_(outpoints: Sequence[OutPoint], A_sum: Point) -> int:
    """Return the input hash of a public sum that is already a point.

    `input_hash` with the conversion lifted out of it, for the one caller
    that goes on to multiply the very point it converted: reaching this
    through the public spelling lifts the x of a compressed A_sum twice,
    once to hash it and once to multiply it.
    """
    if not outpoints:
        raise BTClibValueError("no outpoint to derive the input hash from")
    lowest = min(outpoint.serialize() for outpoint in outpoints)
    A = bytes_from_point(A_sum, secp256k1)
    return _scalar(tagged_hash(_INPUTS_TAG, lowest + A), "input hash")


def tweak_data(outpoints: Sequence[OutPoint], A_sum: PubKey) -> Point:
    """Return input_hash*A_sum, the one value a scanner needs per tx.

    BIP352's Appendix A calls it the tweak data, and it is what a light
    client asks a server for: it is derived from the transaction alone,
    reveals nothing about any recipient, and a scanner multiplies it by
    its scan key to reach the shared secret. Which is why `scan_outputs`
    takes it rather than the outpoints -- a light client never sees them.
    """
    A = point_from_pub_key(A_sum)
    return mult(_input_hash_(outpoints, A), A)


def shared_secret(scalar: PrvKey, point: PubKey) -> Point:
    """Return scalar*point, the ECDH shared secret of BIP352.

    One function for both ends, because there is one secret: the sender
    multiplies input_hash*a by the recipient's B_scan, the recipient
    multiplies its b_scan by the tweak data input_hash*A, and
    commutativity is the protocol.

    The public key stays octets rather than becoming a point: nothing here
    reads a coordinate of it, and `_mult_sec_var` is that multiplication
    without the round trip through one. The point itself is the answer,
    which is why `ecdh.shared_secret` of the bindings is no substitute --
    it hashes, and BIP352 tags this point with a counter of its own;
    :mod:`btclib.ecc.dh` has that verdict for all four of the library's
    ECDH-shaped computations.
    """
    sec = pub_keyinfo_from_pub_key(point)[0]
    return _mult_sec_var(sec, int_from_prv_key(scalar), secp256k1)


def _output_tweak(secret: Point, k: int) -> int:
    """Return t_k, the scalar the k-th output of a group is tweaked by."""
    # k is the position in the group and not a label, so it needs no
    # bound of its own: `scan_outputs` counts it up to K_MAX and
    # `output_keys` up to the group size, which K_MAX already caps
    hash_input = bytes_from_point(secret, secp256k1) + k.to_bytes(_LABEL_SIZE, "big")
    return _scalar(tagged_hash(_SHARED_SECRET_TAG, hash_input), f"tweak for k={k}")


def output_key(secret: PubKey, B_m: PubKey, k: int) -> bytes:
    """Return the x-only taproot output key of one recipient of a group.

    The last step of BIP352's derivation, and the one a caller that
    already holds the shared secret needs on its own:
    `btclib.psbt.silent_payments` reaches this point from an ECDH share a
    psbt carries rather than from a private key, so what the two paths
    share is this and not `output_keys`.

    `k` is the recipient's position in its group, which is what stops two
    payments to one scan key landing on one output.
    """
    t_k = _output_tweak(point_from_pub_key(secret), k)
    return _x_only(_tweak_add_var(point_from_pub_key(B_m), t_k, secp256k1))


def _delegated_output_keys(
    prv_keys: Sequence[tuple[PrvKey, Octets]],
    outpoints: Sequence[OutPoint],
    groups: Mapping[Point, list[Point]],
) -> list[bytes]:
    """`output_keys` over `silentpayments.create_outputs`, secp256k1 only.

    `groups` is already validated -- `output_keys` built it and checked
    every K_MAX bound before calling this. Recipients are flattened group
    by group, each group's addresses kept in the order they were appended,
    which is the order `output_keys`'s own Python loop would assign k in:
    `secp256k1_silentpayments_sender_create_outputs` assigns k by a scan
    key's position of first appearance and increments it per repeat, the
    same rule BIP352's reference algorithm groups by, so handing it the
    recipients in that order derives the identical k for every one of
    them. The list it returns is not re-sorted into address order --
    `test_sending_vectors` already compares the *set* `output_keys`
    answers, output order never having been part of the contract.

    The taproot split is `prv_key_sum`'s own -- `is_p2tr` of the script a
    private key spends -- except the negation for an odd-y point is not
    redone here: `keypair` on the bindings' side is a
    `secp256k1_keypair_create` per taproot input, which is BIP340's own
    even-y normalization and does that negation internally, the same way
    `ssa.Signer` never negates a key by hand either.
    """
    outpoint_smallest36 = min(outpoint.serialize() for outpoint in outpoints)
    recipients_bytes = [
        (bytes_from_point(B_scan, secp256k1), bytes_from_point(B_m, secp256k1))
        for B_scan, B_m_values in groups.items()
        for B_m in B_m_values
    ]
    taproot_prvkeys: list[int] = []
    prvkeys: list[int] = []
    for prv_key, script_pub_key in prv_keys:
        bucket = (
            taproot_prvkeys if is_p2tr(bytes_from_octets(script_pub_key)) else prvkeys
        )
        bucket.append(int_from_prv_key(prv_key))
    try:
        return libsecp256k1_silentpayments.create_outputs(
            recipients_bytes, outpoint_smallest36, taproot_prvkeys, prvkeys
        )
    except ValueError as e:
        # `prv_key_sum` and `input_hash` already ran, above, and are what
        # give a caller the specific "sum to zero" or "no outpoint"
        # wording for the two common refusals -- what reaches here is
        # libsecp256k1's own, coarser message for whatever else its own
        # validation catches, kept a BTClibValueError rather than left a
        # bare one so a caller catching this library's exceptions still
        # does
        raise BTClibValueError(str(e)) from e


def output_keys(
    prv_keys: Sequence[tuple[PrvKey, Octets]],
    outpoints: Sequence[OutPoint],
    addresses: Sequence[String],
) -> list[bytes]:
    """Return the x-only taproot output keys to pay a list of addresses.

    One key per address, in the order the addresses are given;
    `btclib.script.script_pub_key.ScriptPubKey.p2tr` turns each into the
    output to put in the transaction. Repeat an address to pay it twice:
    the k that separates two outputs of one recipient is its position in
    that recipient's group, so two payments to one address are two
    different outputs.

    `prv_keys` pairs each input's private key with the script_pub_key it
    spends, as `prv_key_sum` takes them, and every eligible input of the
    transaction must be there -- the recipient sums all of them. The
    outpoints are the transaction's, eligible or not: what the input hash
    binds to is the transaction.

    **Every key returned must be in the final transaction.** The k of a
    group is what a scanner increments, and it stops at the first k it
    does not find: dropping the i-th output of a group hides every later
    one from its recipient.

    Grouping is by scan key, so two labelled addresses of one recipient
    share a group and get consecutive k. That is deliberate: reusing one
    t_k for both would make the difference of the two output keys equal
    the difference of the two published addresses, which is the recipient
    named in public.

    Where the bindings serve secp256k1 -- BIP352 has no other curve to
    ask them for -- this is `silentpayments.create_outputs`'s own
    derivation rather than the Python arithmetic below: one keypair build
    per taproot input and one shared-secret multiplication per recipient
    group inside libsecp256k1, in place of `mult` and `_mult_sec_var`
    here. `a` and `h` are computed either way, for the refusal a zero
    private-key sum or an empty outpoint sequence already has a specific
    message for -- see `_delegated_output_keys`.
    """
    a = prv_key_sum(prv_keys)
    h = input_hash(outpoints, mult(a))

    # a dict keyed on the scan point, so insertion order is the order the
    # addresses were given and a group's k follows it
    groups: dict[Point, list[Point]] = {}
    for address in addresses:
        B_scan, B_m, _ = keys_from_address(address)
        groups.setdefault(B_scan, []).append(B_m)

    for B_m_values in groups.values():
        if len(B_m_values) > K_MAX:
            err_msg = f"too many recipients sharing one scan key: {len(B_m_values)}"
            err_msg += f" > K_MAX ({K_MAX})"
            raise BTClibValueError(err_msg)

    if not groups:
        return []

    if _libsecp256k1_serves(secp256k1, None):
        return _delegated_output_keys(prv_keys, outpoints, groups)

    keys: list[bytes] = []
    for B_scan, B_m_values in groups.items():
        secret = shared_secret((h * a) % secp256k1.n, B_scan)
        keys.extend(output_key(secret, B_m, k) for k, B_m in enumerate(B_m_values))
    return keys


@dataclass(frozen=True)
class SilentPaymentOutput:
    """A silent payment output a scan found, and what it takes to spend it.

    - pub_key is the 32-byte x-only taproot output key, which is what the
      transaction carries and what identifies the output
    - prv_key_tweak is the scalar to add to the spend private key,
      t_k plus the label tweak where a label was used:
      `prv_key_from_tweak` does that addition
    """

    pub_key: bytes
    prv_key_tweak: int


def _labelled(
    output: bytes, P_k: Point, labels: Mapping[bytes, bytes]
) -> tuple[Point, int] | None:
    """Return (P_k + label, label tweak) if the difference is a label.

    Both parities of the output are tried, which is not belt and braces:
    a taproot output is x-only, so the y the subtraction needs is
    unknown, and half of the time the even one is the wrong guess.

    This is the inner loop of a scan -- once per output that did not
    match directly, and again at every k -- so the additions are
    `_sum_var`'s rather than the Python arithmetic under it: a hundred
    outputs 2202.4 us against 3166.5. The negation of P_k is the same
    point for both parities and is taken once.
    """
    try:
        candidate = point_from_bip340pub_key(output, secp256k1)
    except (TypeError, ValueError):
        # 32 bytes that are no x coordinate: an unspendable output rather
        # than one of ours, and the subtraction below has nothing to
        # subtract. The direct comparison above needed no lift, which is
        # why this is reached rather than raised at the top of the scan
        return None

    minus_P_k = secp256k1.negate(P_k)
    for point in (candidate, secp256k1.negate(candidate)):
        label_point = _sum_var([point, minus_P_k], secp256k1)
        # infinity cannot happen here: it would mean the output equals
        # P_k up to parity, which the x-only comparison already caught
        tweak = labels.get(bytes_from_point(label_point, secp256k1))
        if tweak is not None:
            return _sum_var([P_k, label_point], secp256k1), int_from_prv_key(tweak)
    return None


def scan_outputs(
    b_scan: PrvKey,
    B_spend: PubKey,
    tweak: PubKey,
    outputs_to_check: Sequence[Octets],
    labels: Mapping[bytes, bytes] | None = None,
) -> list[SilentPaymentOutput]:
    """Return the outputs of one transaction that belong to this wallet.

    `tweak` is the tweak data of `tweak_data`, input_hash*A_sum -- the
    light client's entry point, BIP352's Appendix A: a server hands a
    light client exactly this and nothing else about the transaction,
    which is why this stays the Python arithmetic below whatever the
    bindings serve. `scan_transaction_outputs` is the counterpart for a
    caller holding the transaction itself. `outputs_to_check` are the
    x-only keys of every taproot output of the transaction, spent ones
    included -- a wallet recovering its history is looking for outputs it
    has already spent. `labels` is `label_lookup`'s map, and BIP352 asks
    for the change label m = 0 in it whatever else the wallet used.

    The scan walks k upwards and stops at the first k that matches
    nothing, which is what makes it one multiplication per transaction
    rather than one per output. That stopping rule is also why the
    decision to continue must be the cryptographic match and nothing
    else: an output found and then dropped by a wallet policy -- dust,
    say -- still has to advance k, or every later output of the same
    sender is missed.
    """
    # every Octets is itself a Sequence, so passing one instead of a list
    # of outputs would zip through its bytes and check each as its own
    # output (issue #1405)
    if is_octets(outputs_to_check) or not isinstance(outputs_to_check, Sequence):
        raise BTClibTypeError(
            f"invalid outputs_to_check type: {type(outputs_to_check).__name__}"
        )
    secret = shared_secret(b_scan, tweak)
    # every k tweaks the one spend key, and `_tweak_add_var` would cross
    # the boundary with it at each of them: the chain crosses with it once
    label_map = {} if labels is None else labels
    chain = _TweakChain(point_from_pub_key(B_spend), secp256k1)
    remaining = [
        bytes_from_octets(output, secp256k1.p_size) for output in outputs_to_check
    ]

    found = []
    for k in range(K_MAX):
        t_k = _output_tweak(secret, k)
        P_k = chain.point(t_k)
        x_only_P_k = _x_only(P_k)
        match = None
        for output in remaining:
            if x_only_P_k == output:
                match = output, SilentPaymentOutput(x_only_P_k, t_k)
                break
            # a wallet that published no labelled address has nothing for
            # the subtraction below to find, and `_labelled` is a lift
            # and two additions per output before it can say so: a
            # hundred outputs 45.8 us against 3167.2. BIP352 asks for the
            # change label m = 0 whatever else was used, so the map is
            # normally not empty -- what this spares is the caller who
            # passed none, and the answer is `_labelled`'s own for an
            # empty map, which is None every time
            labelled = _labelled(output, P_k, label_map) if label_map else None
            if labelled is not None:
                P_km, label = labelled
                tweak_sum = (t_k + label) % secp256k1.n
                match = output, SilentPaymentOutput(_x_only(P_km), tweak_sum)
                break
        if match is None:
            break
        remaining.remove(match[0])
        found.append(match[1])
    return found


def _delegated_scan_outputs(
    b_scan: PrvKey,
    outpoints: Sequence[OutPoint],
    pub_keys: Sequence[tuple[PubKey, Octets]],
    B_spend: PubKey,
    outputs_to_check: Sequence[Octets],
    labels: Mapping[bytes, bytes] | None,
) -> list[SilentPaymentOutput]:
    """`scan_transaction_outputs` over `silentpayments.scan_outputs`.

    `prevouts_summary` is built from the same split `_delegated_output_keys`
    builds on the sending side -- `is_p2tr` of the script a key spends
    decides whether it is folded in x-only or in full, and the even-y
    normalization of the x-only ones is libsecp256k1's own, not repeated
    here. Unlike that function, this one's caller is not required to have
    validated the group already: `pub_key_sum` and `input_hash` already
    ran in `scan_transaction_outputs`, above, for the refusal an infinite
    sum or an empty outpoint sequence has a specific message for.

    `labels` reaches the bindings unconverted: it is `label_lookup`'s own
    map, 33-byte label to 32-byte tweak, which is the bindings' own
    spelling and not this tree's legacy one. The label element of each
    returned triple is discarded -- the tweak the bindings answer already
    has it folded in, the same combined scalar `_labelled` returns on the
    Python arm.
    """
    outpoint_smallest36 = min(outpoint.serialize() for outpoint in outpoints)
    taproot_pubkeys_bytes = []
    pubkeys_bytes = []
    for pub_key, script_pub_key in pub_keys:
        point = point_from_pub_key(pub_key)
        if is_p2tr(bytes_from_octets(script_pub_key)):
            taproot_pubkeys_bytes.append(_x_only(point))
        else:
            pubkeys_bytes.append(bytes_from_point(point, secp256k1))

    try:
        summary = libsecp256k1_silentpayments.prevouts_summary(
            outpoint_smallest36, taproot_pubkeys_bytes, pubkeys_bytes
        )
        outputs_bytes = [
            bytes_from_octets(output, secp256k1.p_size) for output in outputs_to_check
        ]
        found = libsecp256k1_silentpayments.scan_outputs(
            outputs_bytes,
            int_from_prv_key(b_scan),
            summary,
            bytes_from_point(point_from_pub_key(B_spend), secp256k1),
            labels,
        )
    except ValueError as e:
        # mirrors `_delegated_output_keys`'s own wrapping: the specific
        # refusals already ran above, so what reaches here is
        # libsecp256k1's coarser message for whatever else it refuses
        raise BTClibValueError(str(e)) from e

    return [
        SilentPaymentOutput(pub_key, int.from_bytes(tweak, "big"))
        for pub_key, tweak, _label in found
    ]


def scan_transaction_outputs(
    b_scan: PrvKey,
    B_spend: PubKey,
    outpoints: Sequence[OutPoint],
    pub_keys: Sequence[tuple[PubKey, Octets]],
    outputs_to_check: Sequence[Octets],
    labels: Mapping[bytes, bytes] | None = None,
) -> list[SilentPaymentOutput]:
    """Return the outputs of one transaction, from data a full node has.

    `scan_outputs` is the light client's entry point, `tweak` the one
    value BIP352's Appendix A hands it. A full node holds the transaction
    itself instead: `pub_keys` pairs each eligible input's public key
    with the script_pub_key it spends, exactly as `output_keys`'s
    `prv_keys` does on the sending side, and every eligible input must be
    there for the same reason `pub_key_sum` there needs all of them.
    `outpoints` is the transaction's, eligible or not: what the input
    hash binds to is the transaction, precisely as `output_keys` reads it.

    Where the bindings serve secp256k1, this reaches
    `silentpayments.scan_outputs` with a `prevouts_summary` computed once
    from `pub_keys` and `outpoints` -- the shape a wallet scanning a block
    needs, and the one issue #910's own measurement found 6.4x faster
    than the Python loop at a hundred outputs once a label is in play,
    which BIP352 asks every wallet to check (m = 0, the change label).
    Without a label the two arms are close, the Python one ahead at a
    hundred outputs, but that case is not what decided this: see the
    issue's own comments for the numbers.

    `pub_key_sum` and `input_hash` run unconditionally, before either arm
    is chosen, for the same reason `output_keys` computes `a` and `h`
    either way: a zero-sum refusal or an empty outpoint sequence gets the
    specific message those two functions already give it, rather than
    libsecp256k1's coarser one.

    `labels` is `label_lookup`'s map -- 33-byte label to 32-byte tweak,
    the bindings' own spelling -- and reaches the delegated arm
    unconverted; the Python arm, `scan_outputs`, reads the same bytes
    through `int_from_prv_key`.
    """
    # `scan_outputs`'s own guard, checked again here rather than relying
    # on the delegation below: the bindings arm never reaches that
    # function, so `outputs_to_check` is this function's own to refuse
    # (issue #1405)
    if is_octets(outputs_to_check) or not isinstance(outputs_to_check, Sequence):
        raise BTClibTypeError(
            f"invalid outputs_to_check type: {type(outputs_to_check).__name__}"
        )
    A_sum = pub_key_sum([pub_key for pub_key, _script_pub_key in pub_keys])
    h = input_hash(outpoints, A_sum)

    if _libsecp256k1_serves(secp256k1, None):
        return _delegated_scan_outputs(
            b_scan, outpoints, pub_keys, B_spend, outputs_to_check, labels
        )

    # `tweak_data` would recompute `input_hash`, redoing the outpoint sort
    # and the tagged hash over the same data: `h` is already this
    # transaction's, same as `output_keys` reuses its own `h` rather than
    # letting a helper derive it again
    tweak = mult(h, A_sum)
    return scan_outputs(b_scan, B_spend, tweak, outputs_to_check, labels)


def prv_key_from_tweak(b_spend: PrvKey, prv_key_tweak: int) -> int:
    """Return the private key that spends a found output.

    b_spend plus the tweak `scan_outputs` reported, modulo n. The taproot
    output is x-only, so a signer negates this key if it has to; that is
    BIP340's business and `btclib.ecc.ssa.sign` does it.
    """
    d = (int_from_prv_key(b_spend) + int_from_prv_key(prv_key_tweak)) % secp256k1.n
    if d == 0:
        raise BTClibValueError("spend private key and tweak sum to zero")
    return d
