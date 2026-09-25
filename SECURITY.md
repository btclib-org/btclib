# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/btclib/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to *security at btclib dot org* is
equally welcome.

## What belongs here, and what belongs upstream

secp256k1 arithmetic is delegated to
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1/security/advisories/new),
the Python bindings, and through them to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/security/advisories/new)
itself, which has its own security policy and its own address. Not every
call: one predicate decides — a process-wide dispatch switch, the curve
and the hash function — with whatever further conditions the call site
ands onto it, and *Limitations, not vulnerabilities* below states each of
them. A flaw in the elliptic curve arithmetic, or in how the bindings
drive it, most likely belongs to one of those.

What belongs here is everything btclib does around them:

- the parsing and serialization of what comes from outside — keys,
    addresses, signatures, scripts, transactions — and the validation
    that decides what is accepted
- the script engine, and the taproot construction it validates against
- the pure Python implementations, which are what runs whenever the
    conditions below are not met
- the distributions published to PyPI and their provenance

Report it wherever you found it, though: routing a report is the
maintainers' job, not the reporter's, and a doubt about which of three
projects owns a flaw is not a reason to keep it to yourself.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

The same files are attached to the GitHub release, and those copies carry
a build provenance attestation of their own, signed in the run that built
them:

```shell
repo=btclib-org/btclib
signer=btclib-org/.github/.github/workflows/reusable-attest.yml
gh attestation verify --repo "$repo" --signer-workflow "$signer" \
  <a distribution file from the release>
```

`--signer-workflow` names the workflow that signed. From v2026.9.24 on
that is the organization's `reusable-attest.yml`, which this repository's
`release.yml` calls: an attestation made inside a called workflow names
the callee as its signer, while `--repo` still names this repository as
the source. For those releases the flag is required rather than a
narrowing, the command refusing a genuine release without it. Through
v2026.9.13 the signer is `release.yml` itself, so for those releases
`signer` is `"$repo/.github/workflows/release.yml"`, and there the flag
narrows what passes: without it an attestation from any workflow in this
repository is accepted. Neither path verifies a release the other
signed. The PEP 740 attestations on PyPI name `release.yml`, the job
that uploads there being its own rather than a called workflow's. The
signed statement for the GitHub release is attached to it as well, as
`<tag>.attestation.jsonl`, so `--bundle <tag>.attestation.jsonl` runs the
same check reading it from disk instead of asking GitHub for it; one
attestation covers every asset of the release. Either file can also be
rebuilt from its tag and verified without being downloaded at all, the
build being reproducible: RELEASING.md has that command and the bounds on
it.

A CycloneDX 1.6 bill of materials is attached beside them,
`btclib-<version>.cdx.json`: the two files with their SHA-256, the
licence, and one component per dependency the wheel's metadata declares.
It is generated from the built wheel rather than from the source tree, so
it describes the files it is attached to, and it is covered by the same
attestation — a bill of materials whose provenance nobody can check says
only what whoever wrote it wanted said. What it records of a dependency is
the requirement as published, so a component carries a version only where
that requirement is an exact pin.

What may be inside those two files is stated in
[the package-content policy](./docs/source/package-content-policy.md),
and a build carrying anything else is refused before it can be published:
an allowlist of the members of a wheel and an sdist, the suffixes and
names neither may ever hold, and — named as policy, because no list of
members can show them — the rules about what runs while the package is
built and installed.

## Limitations, not vulnerabilities

The [assurance case](./ASSURANCE_CASE.md) is the threat model these are
written against, and the argument for what this file does promise.

These are known and inherent. They are worth stating because btclib is
used to teach and to prototype as much as to build:

- secret material handed to btclib lives in Python objects, which are
    immutable and not zeroized: it stays in the process memory until
    garbage collection, and may have been copied by the interpreter
    meanwhile. The constant-time properties of libsecp256k1 apply to the
    C side of the boundary, not to what happens before and after it
- **`musig2.nonce_gen` and `sign` stay on this arithmetic by decision,
    not merely by default** (issue #1050). Delegating them would put
    `musig_nonce_gen`'s secnonce -- an opaque 132-byte struct the
    header calls "implementation defined and not guaranteed to be
    portable between different platforms or versions" -- into
    `btclib.ecc.musig2`'s public API, against `btclib_wallet.psbt.musig2`'s
    own decision to hold no session state at all. What it would buy is
    measured rather than assumed: the point-multiplication side has
    been regular since #254, and `sign`'s own line, `s = (k_1_ +
    values.b * k_2_ + values.e * a * d) % secp256k1.n`
    (`src/btclib/ecc/musig2.py:851`), spreads 1.016x over uniform scalars
    in `[1, n-1]` -- the magnitude leak that remains shows only for
    scalars with zero high bits, keys already lost for other reasons.
    The gain left is narrower than that figure suggests: delegating
    would only keep `k_1` and `k_2` from becoming Python `int`s, and
    the bullet above already covers why that does not decide anything
    -- `curves.scalar_from_prv_key` produces an unzeroizable `int` from
    the private key on the delegated path too. `btclib_secp256k1` itself
    takes the equivalent opaque handle for `musig_keyagg_cache` and
    `musig_session` without this reasoning landing on a different
    answer there: those have no octets form to begin with, where an
    `int` here already does the job. The same reasoning answers two
    more questions this library has never separately decided: it grows
    no private-key class, because zeroization needs exactly the
    delegation declined above -- a class that hands out an `int` the
    moment anything uses it has a session object's ergonomics and none
    of its guarantee -- and curve arithmetic stays on `int` rather than
    `bytes`, `bytes` being immutable exactly like `int` while only
    `bytearray` zeroizes, and bignum arithmetic on a `bytearray` still
    allocating `int` intermediates at every step
- the bindings also let a caller own the buffer a secret is written
    into: a keyword-only `into=`, on every entry point that produces
    one — `keys.prvkey_negate`, `keys.prvkey_tweak_add`,
    `keys.prvkey_tweak_mul`, `xonly.prvkey_tweak_add`,
    `ecdh.shared_secret`, `ellswift.xdh`, `dsa.nonce_rfc6979` and
    `ssa.nonce_bip340`. btclib passes none of them, and that is a
    decision, not an oversight. These call sites read one of those
    straight into a Python `int`: `commit_nonce.commit_nonce_` at
    `int.from_bytes(tweaked, byteorder="big", signed=False)`
    (`src/btclib/ecc/commit_nonce.py:158`) and `taproot._tweaked_prvkey`
    at `int.from_bytes(tweaked, "big")`
    (`src/btclib/script/taproot.py:469`). A caller-owned buffer can be
    wiped once the call that filled it returns; the `int` it is read
    into cannot be, and outlives the call regardless, so taking the
    buffer at these call sites would cost a public signature and buy
    nothing, short of btclib no longer
    holding a private key as a Python `int`, which is a change to that
    representation and not to a call site. `ellswift.xdh`
    (`src/btclib/ecc/ellswift.py:365`) is the one of them that returns
    octets rather than an `int`, so a caller-owned buffer there would
    hold what it wiped: taking it means growing `xdh`'s public
    signature with `into=` and owning the contract that comes with
    it — a buffer too short, a buffer that is not writable, what the
    function then returns. btclib declines that too, for the reason
    the bullet above already gives: no Python object holding a secret
    is zeroized, on either path, and this one is no exception to it.
    `dsa.Signer.__init__` at `self._q.to_bytes(32, "big")`
    (`src/btclib/ecc/dsa.py:1388`) crosses the same boundary the other
    way, once, at construction: the plain `int` `scalar_from_prv_key`
    already produced becomes a transient `bytes` on the way into the
    owned buffer `wipe` overwrites afterwards. That `bytes` is dropped
    rather than erased, same as the `int` it replaces — one call rather
    than the buffer's whole lifetime, which is the trade this class
    exists to make, and stated here for the same reason the call sites
    above are
- the boundary is not always there, and an install decides whether it
    is. `pip install "btclib[secp256k1]"` -- the spelling README.md and
    the guide give -- installs the bindings, and everything the next
    bullet says describes that installation. `pip install btclib`
    installs no C at all: signing, verification and key agreement all
    run the Python arithmetic the last bullet describes,
    which is tens of times slower and not constant-time. Nothing raises
    to say so, and `curves.is_libsecp256k1_serving()` is how a caller
    asks which of the two it has.
    The dispatch is a runtime switch besides:
    `curves.set_libsecp256k1_serving(serving=False)` turns it off for the
    whole process, and `BTCLIB_NO_LIBSECP256K1` set in the environment
    makes that the state from the first call — a test framework built on
    btclib wants exactly that, having to check libsecp256k1 with
    something other than libsecp256k1. With the dispatch off, every
    operation named below is the Python arithmetic, whichever way the
    library was installed
- not every operation crosses that boundary, and one predicate decides
    whether it can: `curve._libsecp256k1_serves` asks for the switch
    above, then for secp256k1 as the curve, then for a hash function
    that is sha256 or absent — `hf is None or hf is sha256`
    (`src/btclib/curves/curve.py:534`) — with whatever further
    conditions the call site ands onto it. The hash function is matched
    by identity rather than by what it computes, so
    `functools.partial(sha256)`, or any other wrapper a caller writes to
    fit an interface, is one the predicate declines, and the call it is
    passed to runs the Python arithmetic — conservative for the
    arithmetic, silent for the caller. The condition each operation below
    states as sha256 is that identity.
    `mult`, `double_mult_var` and
    `multi_mult_var` reach the bindings for secp256k1 and any point of it, a
    zero scalar and the point at infinity excepted — libsecp256k1 has no
    scalar for the one and no public key for the other; `dsa.sign` for
    secp256k1 with sha256, the lower-s form, no caller-imposed nonce and
    no commitment; `ssa.sign` for secp256k1 with sha256, a message of
    any size and no commitment; `taproot.output_prvkey`,
    `dh.diffie_hellman` and `commit_nonce.commit_nonce_` for secp256k1,
    the tweaking of a key, the shared point of a key agreement and the
    tweaking of a sign-to-contract nonce being other places a secret
    meets the curve.
    Verification crosses it whole, not only in its multiplication:
    `dsa.verify` and `ssa.verify` are one libsecp256k1 call each, where
    the dispatch is on, for
    secp256k1 with sha256, a high-s signature being normalized first
    where the lower-s form is not being enforced. Batch verification is
    the exception, libsecp256k1 having no call for it, so
    `ssa.batch_verify` is the Python equation over delegated
    multiplications. `musig2.partial_sig_verify_` is a narrower
    delegation again, of one MuSig2 round-two check rather than of every
    operation the module offers (issue #1049): for secp256k1, sha256, a
    32-byte message and a session with no adaptor.
    `musig_nonce_process` takes a fixed 32-byte `msg32` with no length
    parameter, so a message of any other size runs the Python equation
    below regardless of the bindings, as does a session carrying the
    adaptor extension `btclib.ecc.musig2` implements and the bindings do
    not. `key_agg`, `key_sort` and `nonce_agg` stay Python's alone
    either way: measured too close to the delegated arithmetic they
    already call, or run once per session rather than once per signer,
    to earn a second code path. This paragraph is about a secret meeting
    the curve and verification holds none, which is why it is named here
    only to say that the sentence below is not about it.
    A signature the bindings decline is not all Python for that:
    `dsa.gen_keys` and the nonce point of `dsa._sign_` go through `mult`,
    and the verification equation of both `dsa` and `ssa` through
    `double_mult_var`, so those multiplications are delegated whatever else
    the signature asks for. The rest of that signature is not — the
    inversion of the nonce and the arithmetic on the key around it are
    Python integers. That inversion is blinded, and is the one place in
    the library where a secret is inverted at all: `mod_inv`
    draws a random factor, so that the extended Euclid's iteration count
    follows the factor rather than the nonce. Unblinded it followed the
    nonce's bit-length — roughly twice the cost for a 256-bit scalar as
    for a 128-bit one on secp256k1's order — which is the correlation the
    Minerva attack turns into the private key.
    `bms.sign` is delegated outright, `recovery.sign` signing and naming
    the recovery flag in one call: message signing is defined for
    secp256k1 alone, so there is no argument that sends it down the
    Python path — the switch above is what reaches it, and nothing a
    caller passes does.
    Whatever the predicate above and a call's own conditions decline
    runs the Python implementation, whose scalar multiplication is
    a double-and-add in Jacobian coordinates: it is validated against the
    bindings, which are the authority on the answer, but it is not
    constant-time. It tries, which is not the same claim. The Jacobian
    group law neither branches on the point at infinity nor lets it reach
    the arithmetic: a full-size stand-in takes its place and a table
    answers for it, because a Python integer costs what its size costs
    and the zero coordinates of infinity would time the case as well as a
    branch would. That is the case that matters, infinity being the
    identity and so the accumulator every multiplication starts from and
    the multiple a zero digit names: an addition of it costs what any
    other addition costs, and a multiplication takes the same time
    whatever the bits of the scalar. Two points that coincide, or that
    are opposite, do still branch — that case needs the accumulator to
    land on a table entry, 2^-250 on a curve with a real order, and a
    caller spelling out `P + P` knows it did.
    Nor does the scalar decide how many additions there are, or how many
    windows: `mult` recodes it into signed odd digits, none of them zero
    and always `ceil(nlen / w)` of them, and starts the accumulator at a
    table entry rather than at the identity, so every scalar of the curve
    costs the same additions and the same doublings, and its size is
    hidden as its bits are. The plain fixed window is the contrast: its
    digits are `ceil(m.bit_length() / w)` of them, so a scalar short of a
    full top window costs one window less there and its size is what the
    count shows. On secp256k1, whose endomorphism halves the doublings,
    the regular windows of its decomposition are uniform the same way.
    The interleaved wNAFs of that same decomposition add on a nonzero
    digit and so once per unit of the recoded weight of the coefficient,
    which is why they are not what `mult` reaches for; they are what
    `double_mult_var` and signature verification reach, where the
    coefficients are a signature and a message hash rather than a secret.

    What is left is out of reach from pure Python, and is enough to
    matter: the windowed multiplications index a table of precomputed
    multiples with a secret digit, which is the memory access pattern the
    FLUSH+RELOAD recovery of OpenSSL's nonces read; every reduction and
    multiplication takes the time its operand sizes ask for, and a
    residue is not always the full size; the affine group law spends a
    modular inverse, an extended Euclid whose iteration count follows its
    input, and so does the conversion back from Jacobian coordinates —
    that one on a Z coordinate `_blinded_jac` has randomized, which is
    why it is named here as a cost and not as a channel; and `multi_mult_var`
    is Bos-Coster, whose shape is the scalars themselves.
    Using it on key material that matters is a choice, and this is the
    notice of it
- **the delegated multiplication of a point that is not the generator is
    constant time in its scalar where the multiplication is `mult`'s, and
    variable time where it is a `_var` one's.** `mult` reaches
    libsecp256k1 through `secp256k1_ecdh`, whose multiplication is
    `secp256k1_ecmult_const`, constant time in its scalar;
    `ecdh.shared_point` of the bindings is that call answering the point
    rather than a hash of it. The arm `curves.curve.mult` shares with
    `PreparedPoint.mult` asks for a non-zero reduced scalar and then for
    the predicate above, with no hash function, so the switch and the
    curve are the whole of what the predicate asks; the generator is a
    different call inside that arm and infinity is not delegated at
    all — `curve._libsecp256k1_mult` at
    `libsecp256k1_shared_point(_sec_from_point(Q), m, False)`
    (`src/btclib/curves/curve.py:797`). `dh.diffie_hellman` at
    `sec = libsecp256k1_shared_point(`
    (`src/btclib/ecc/dh.py:100`) and `sec_point._mult_sec` at
    `libsecp256k1_shared_point(sec, m, False)`
    (`src/btclib/curves/sec_point.py:361`), under `sec_point.mult_pub_key`
    and `ecies.derive_keys`, make the same call on the octets they
    already hold.
    `double_mult_var` and `multi_mult_var`, and `ssa.batch_verify`, are
    the other call: `keys.pubkey_tweak_mul_sum`, one
    `secp256k1_ec_pubkey_tweak_mul` per term, which runs
    `secp256k1_ecmult`, whose windowed NAF holds at most one more digit
    than the scalar has bits — so the work follows the scalar rather than
    the order of the curve, which is what their suffix says. A
    verification's scalars are public; a secret handed to them is timed
    by them all the same, and `pedersen.commit` hands that call a value
    and a blinding factor, `rangeproof.rewind` the ones it recovered
    (issue #2267).
    `ellswift.xdh` is delegated to
    `secp256k1_ellswift_xdh`, which multiplies with
    `secp256k1_ecmult_const_xonly` — constant time in its scalar, and a
    different function from `secp256k1_ecmult_const`.
    The other delegations the bullet above names are different calls:
    a multiple of the generator is `secp256k1_ec_pubkey_create`, which
    runs `secp256k1_ecmult_gen`, and the tweaking of a key is
    `secp256k1_ec_seckey_tweak_add` or
    `secp256k1_keypair_xonly_tweak_add`, which add scalars. Those three
    and `secp256k1_ecdh` are among the entry points libsecp256k1's own
    `src/ctime_tests.c` declassifies a secret for, and
    `secp256k1_ec_pubkey_tweak_mul` is named nowhere in that file
- a sign-to-contract commitment is the signer's to open, and opening it
    twice over one message is safe only because the committed value
    reaches the nonce derivation: that is what keeps two such signatures
    from sharing an untweaked nonce and handing out the key. The
    derivation is `btclib.ecc.commit_nonce`, and the property is worth
    knowing about for anyone building the anti-exfil protocol on top,
    which btclib does not yet offer: there, the ordering matters as
    well — the signer must publish its `R` before learning the host's
    randomness, and `sign` alone cannot enforce that
- **a `btclib.ecc.borromean` ring signature made before issue #1053's fix
    names its own signer.** The real signer's s-value was the only one
    computed rather than drawn, and the only one left unreduced: it ran
    to about twice the bit length of the forged values beside it, so the
    longest s in a ring was the real signer's position, read off a
    signature that was otherwise valid and without breaking anything
    cryptographically. The fix reduces that value mod `ec.n`, the same
    reduction every verifier already applied to it, and draws the forged
    values from the same range rather than `secrets.randbits(256)`; no
    signature changes, so a signature made before the fix still verifies
    after it, and this bullet is about what it already disclosed, not
    about needing a new one. A ring signature published under the old
    code is not repaired by upgrading btclib: whatever bit length its
    published s-values carry is public already, and nothing library-side
    can withdraw that
- randomness comes from the operating system through the `secrets`
    module: the auxiliary randomness of BIP340 signing and the private
    keys of the key generation helpers. Nothing here seeds a generator
    of its own
- `btclib.ecc.ecies` ships no block cipher and takes AES-128-CBC as two
    callables, so the cipher's own resistance to timing and side-channel
    attack is whatever the caller passed in — btclib neither provides it
    nor can check it. That is the point of the parameter rather than a gap
    in it: a pure-Python AES here would be table-driven and would leak its
    key through cache timing, and the caveat above about the Python curve
    arithmetic is exactly the one this design refuses to add a second of.
    The MAC is verified before the cipher is called, and compared with
    `hmac.compare_digest`, so what btclib does with the envelope does not
    depend on the secret byte by byte; a caller wanting the same of the
    decryption should bring a cipher that gives it
