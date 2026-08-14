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

Signing, verification and generator multiplication on secp256k1 are
delegated to
[btclib_secp256k1](https://github.com/btclib-org/btclib-secp256k1/security/advisories/new),
the Python bindings, and through them to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/security/advisories/new)
itself, which has its own security policy and its own address. A flaw in
the elliptic curve arithmetic, or in how the bindings drive it, most
likely belongs to one of those.

What belongs here is everything btclib does around them:

- the parsing and serialization of what comes from outside — keys,
    addresses, signatures, scripts, transactions, PSBTs — and the
    validation that decides what is accepted
- the derivation paths: BIP32, BIP39, Electrum mnemonics, SLIP132
- the script engine, and the taproot construction it validates against
- the pure Python implementations, which are what runs whenever the
    conditions below are not met
- the JSON-RPC client of `btclib.fetch`: how it authenticates, and what
    it does with a reply
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
gh attestation verify btclib-<version>-py3-none-any.whl \
  --repo btclib-org/btclib \
  --signer-workflow btclib-org/btclib/.github/workflows/release.yml
```

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has. The signed statement
is attached to the release as well, as `<tag>.attestation.jsonl`, so
`--bundle <tag>.attestation.jsonl` runs the same check reading it from
disk instead of asking GitHub for it; one attestation covers every asset
of the release. Either file can also be rebuilt from its tag and
verified without being downloaded at all, the build being reproducible:
RELEASING.md has that command and the bounds on it.

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

These are known and inherent. They are worth stating because btclib is
used to teach and to prototype as much as to build:

- secret material handed to btclib lives in Python objects, which are
    immutable and not zeroized: it stays in the process memory until
    garbage collection, and may have been copied by the interpreter
    meanwhile. The constant-time properties of libsecp256k1 apply to the
    C side of the boundary, not to what happens before and after it.
    `bip32._cached_base58_decode` extends this by one step for an xprv
    or xpub string handed to `derive` or `derive_from_account`: the
    decoded key stays reachable from that cache, bounded by its
    `maxsize`, past whatever reference the caller itself still holds
- not every operation crosses that boundary. `mult`, `double_mult_var` and
    `multi_mult_var` reach the bindings for secp256k1 and any point of it, a
    zero scalar and the point at infinity excepted — libsecp256k1 has no
    scalar for the one and no public key for the other; `dsa.sign` for
    secp256k1 with sha256, the lower-s form, no caller-imposed nonce and
    no commitment; `ssa.sign` for secp256k1 with sha256, a message of
    any size and no commitment; `taproot.output_prvkey`,
    `dh.diffie_hellman` and `commit_nonce.commit_nonce_` for secp256k1,
    the tweaking of a key, the shared point of a key agreement and the
    tweaking of a sign-to-contract nonce being three other places a
    secret meets the curve.
    Verification crosses it whole, not only in its multiplication:
    `dsa.verify` and `ssa.verify` are one libsecp256k1 call each for
    secp256k1 with sha256, a high-s signature being normalized first
    where the lower-s form is not being enforced. Batch verification is
    the exception, libsecp256k1 having no call for it, so
    `ssa.batch_verify` is the Python equation over delegated
    multiplications. This paragraph is about a secret meeting the curve
    and verification holds none, which is why it is named here only to
    say that the sentence below is not about it.
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
    nonce's bit-length — 8.8 us for a 256-bit scalar against 4.3 for a
    128-bit one on secp256k1's order — which is the correlation the
    Minerva attack turns into the private key.
    `bms.sign` is delegated outright, `recovery.sign` signing and naming
    the recovery flag in one call: message signing is defined for
    secp256k1 alone, so there is no argument that sends it down the
    Python path — which the test suite reaches by switching the dispatch
    off, and which no caller can.
    Anything else — another
    curve, another hash function, a nonce of your own — runs the Python
    implementation, whose scalar multiplication is
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
    hidden as its bits are. Measured over 200 random scalars: 71 additions
    and 253 doublings for every one of them, where the plain fixed window
    makes 68 to 70 and 251 to 259; and on secp256k1, whose endomorphism
    halves the doublings, 79 and 126 for every one of them, where the
    interleaved wNAFs of the same decomposition make 51 to 64 and 124 to
    131. Those wNAFs add on a nonzero digit and so once per unit of the
    recoded weight of the coefficient, which is why they are not what
    `mult` reaches for; they are what `double_mult_var` and signature
    verification reach, where the coefficients are a signature and a
    message hash rather than a secret.

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
- a sign-to-contract commitment is the signer's to open, and opening it
    twice over one message is safe only because the committed value
    reaches the nonce derivation: that is what keeps two such signatures
    from sharing an untweaked nonce and handing out the key. The
    derivation is `btclib.ecc.commit_nonce`, and the property is worth
    knowing about for anyone building the anti-exfil protocol on top,
    which btclib does not yet offer: there, the ordering matters as
    well — the signer must publish its `R` before learning the host's
    randomness, and `sign` alone cannot enforce that
- randomness comes from the operating system through the `secrets`
    module: the auxiliary randomness of BIP340 signing, the entropy of a
    generated mnemonic, and the private keys of the key generation
    helpers. Nothing here seeds a generator of its own
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
- **a `btclib.fetch` backend is trusted, and the two are trusted
    differently.** `BitcoinCoreFetcher` talks to a node that validated the
    chain it reports; `EsploraFetcher` talks to a host that says it did.
    Only one answer of the four is checked at all — the transaction, whose
    id is recomputed from the bytes that came back — so a height, a tip
    hash and the amount of an output all rest on the backend's word. An
    explorer also learns every txid and outpoint you look up, which is a
    good deal of what a wallet is; btclib names a public deployment as a
    constant and never as a default, so nothing here contacts anyone
    until a caller writes the endpoint down
- **rpc credentials.** They are passed as arguments and refused in the
    url, so that a password is not carried in a string that ends up in
    config files, tracebacks and logs. bitcoind's `.cookie` needs none at
    all and is the default. The transport is plain HTTP against
    `127.0.0.1`, which is what bitcoind serves: a node on another host is
    reached over an ssh tunnel or a TLS proxy, not by trusting the
    network in between — the basic authentication this sends is a
    base64 of the credential and nothing more. With the default
    `urlopen_transport` it reaches the url the caller wrote down and no
    other: no redirect is followed, so a 30x is a status the backend
    reports rather than a second request carrying the same `Authorization`
    to wherever a `Location` header named. A transport of the caller's own
    is supported and does its own I/O, so there the same guarantee is
    theirs to provide — a client that follows redirects is one that
    decides where the credential goes
