# Where the threshold lives

A bitcoin spend can require more than one party in two ways, and btclib
implements both. They are separate code paths, and the numbers *k*, *t*
and *n* do not tell them apart. What tells them apart is where the
threshold is enforced: in consensus, by every node, or in cryptography,
settled off-chain before the transaction exists.

## The discriminant

In script multisig the threshold is script policy, enforced by
consensus. The script holds *n* public keys, the input supplies *k*
signatures, and every node runs `OP_CHECKMULTISIG` — `OP_CHECKSIGADD` in
tapscript — and counts. Those *k* signatures are ordinary independent
signatures, each under its own key: the signers never talk to one
another, each signs alone, in any order, months apart.

In MuSig2 and in FROST the threshold is cryptography, off-chain.
Consensus knows nothing of it: it sees one key and one 64-byte BIP340
signature, exactly what a single-key spend presents. The group structure
is gone before the transaction exists.

## Where MuSig2 and FROST separate

They are two mechanisms, not two settings of one.

**MuSig2 aggregates independent keys.** Each signer holds its own secret
key and never shares it; the *n* public keys combine into one aggregate
key. All *n* have to take part, because there is nothing to interpolate:
the keys are not points of a polynomial, and a missing partial signature
is a sum that does not close.

**FROST shares one key.** There is a single threshold secret key,
Shamir-split into *n* shares, and nobody holds it whole. Any *t* of the
shares reconstruct, by Lagrange interpolation, not the key but the
signature.

So MuSig2 with a *t* smaller than *n* is not a configuration. It is a
different algorithm.

## What changes in practice

| | script multisig | MuSig2 | FROST |
| --- | --- | --- | --- |
| threshold enforced by | consensus | cryptography | cryptography |
| on chain | *n* keys, *k* sigs | one key, one sig | one key, one sig |
| signer interaction | none | two rounds | two rounds |
| secret keys | *n* independent | *n* independent | one, in *n* shares |
| who signed | in the input | not derivable | not derivable |
| membership change | new address | new aggregate key | same public key |
| bound on *n* | consensus | serialization | security |

### Cost and privacy

A 3-of-5 script spend reveals five public keys and three signatures, and
tells anyone watching that the output was a 3-of-5. MuSig2 and FROST
produce a spend indistinguishable from a single-key one, of constant
size, whatever *n* is.

### No consensus ceiling

`OP_CHECKMULTISIG` stops at `MAX_PUBKEYS_PER_MULTISIG` keys, which
`src/btclib/script/engine/script.py` enforces. A `multi_a()` leaf is
bounded by the stack instead, one element per key, which is what
`_MAX_PUBKEYS_PER_MULTI_A` in `src/btclib/descriptors/miniscript.py`
states; and a tapscript spend charges its sigops budget 50 for every
non-empty signature, whether or not that signature verifies.

MuSig2 and FROST have no ceiling the chain imposes, the chain seeing one
key. What bounds them is the specification, and the two bounds are not
the same kind of thing. BIP327's is serialization: the number of
individual public keys is an unsigned 32-bit count. BIP445's is
security: it refuses an *n* past 128, `src/btclib/ecc/frost.py` refuses
it too, and the module's own docstring carries the reason — the
unforgeability proof assumes the compromised set is fixed before key
generation, and an adaptive adversary's advantage rests on a search
problem BIP445 cites as provably hard for *n* ≤ 131.

### The price is state and simultaneity

Script multisig is stateless and has no shared nonce: a signer that is
compromised or offline does not touch the others. MuSig2 and FROST need
a nonce round before the partial signatures — so, signers available at
the same time — and above all a secret nonce that is never reused.
Reusing one does not degrade security, it hands out the key.
`musig2.sign` and `frost.sign` zero the two secret scalars of the
`bytearray` they are handed the moment they read them, before either is
used for anything, so a second call on the same buffer reads two zeros
and raises rather than signing.

### Attribution

A script multisig input says which *k* of the *n* signed: it is an
audit trail. A MuSig2 or a FROST signature does not — privacy for some
uses, a gap for others, custody and internal delegation among them.

### Membership change

In script multisig, adding or removing a signer means a new script, a
new address, and moving the funds. MuSig2 sits in between: changing the
set changes the aggregate key. In FROST the group public key is a
property of the secret and not of how it is shared, so the same secret
can be shared again over a different set and the funds stay where they
are. Producing those shares is key generation, which is out of scope
here as it is in BIP445.

### Who has seen the secret

Script multisig has no phase in which anybody holds everything. FROST
has one wherever a trusted dealer distributes the shares: that dealer
transiently knows the whole key. Avoiding it takes a distributed key
generation, and `btclib.ecc.frost` takes key material already split
rather than splitting any.
[ISS 257](https://github.com/btclib-org/btclib/issues/257) is where
interactive threshold signing, key generation included, is tracked.

## *t* = *n* FROST is not MuSig2

BIP445's own vectors include a 3-of-3 group, under
`tests/ecc/_data/bip445/`. That group is still not MuSig2: one shared
key against *n* independent keys aggregated, with everything that
follows from it about who has seen the secret and about what a departing
member costs.

## MuSig2 with *t* < *n*

Not natively, for the reason above. The two real routes are composition
rather than configuration.

**A taproot tree with one leaf per admitted subset.** Each leaf carries
a MuSig2 key over that subset alone, or a `multi_a()`. The cost is
combinatorial, C(*n*, *t*) leaves: three for a 2-of-3, 126 for a 5-of-9.
Only the leaf used is revealed, and the key path can stay the *n*-of-*n*
"everybody agrees", which is the cheap case. Workable for a small *n*,
senseless past it.

**Nesting with FROST.** A MuSig2 aggregate key can be one participant of
a FROST group, and a FROST group key can be one key inside a MuSig2
aggregation. That is how "either the board's 2-of-3 or the chief
executive" is expressed with one on-chain key.

## A FROST spend has no psbt transport

BIP373 assigns MuSig2 psbt field types of its own — participant public
keys, a public nonce and a partial signature on an input, participant
public keys on an output — which `src/btclib/psbt/psbt_in.py` and
`src/btclib/psbt/psbt_out.py` carry and `src/btclib/psbt/musig2.py`
gives meaning to. They are MuSig2-specific and do not extend to a
threshold: a participants field would have to map a group key to its
*t*, its *n*, the identifiers and the public shares, rather than an
aggregate key to its participants; nonces and partial signatures would
be indexed by identifier rather than by a participant's public key; and
a session needs a field naming the subset that is signing it, for which
BIP373 has no counterpart, MuSig2's subset always being everybody. The
taproot tweaks are the same and carry over.

BIP445 specifies no psbt transport of its own, and no type bytes are
assigned for FROST: writing one today means choosing bytes nobody has
assigned, and choosing them in the space BIP174 reserves for future
assignment is how two implementations collide.
[ISS 2174](https://github.com/btclib-org/btclib/issues/2174) is where
that is tracked.

## Where each of them lives in btclib

The two routes are both implemented, and they do not touch.

The script threshold is the descriptor grammar in
`src/btclib/descriptors/descriptors.py` — `multi()` and `sortedmulti()`
(BIP383), `multi_a()` and `sortedmulti_a()` (BIP386, BIP387) — with the
op codes `OP_CHECKMULTISIG` and `OP_CHECKSIGADD` under
`src/btclib/script/`.

The cryptographic threshold is `src/btclib/ecc/musig2.py` (BIP327) and
`src/btclib/ecc/frost.py` (BIP445), with `src/btclib/psbt/musig2.py`
(BIP373) carrying a MuSig2 session through a psbt. MuSig2 also has a
spelling in the descriptor grammar, BIP390's `musig()` key expression,
inside a `tr()` or a `rawtr()`; FROST reaches no layer above
`btclib.ecc` at all.

What they produce is not one object for all three.
`musig2.partial_sig_agg` and `frost.partial_sig_agg` each answer an
`ecc.ssa.Sig`, the BIP340 signature `ecc.ssa` verifies and so does every
other BIP340 verifier; a `multi_a()` leaf is checked against BIP340
signatures too, the tapscript engine calling `ecc.ssa` for them.
`OP_CHECKMULTISIG` is the one that differs: it verifies ECDSA, through
`ecc.dsa`.
