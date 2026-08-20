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
- the bindings also let a caller own the buffer a secret is written
    into: a keyword-only `into=`, on every entry point that produces
    one — `keys.prvkey_negate`, `keys.prvkey_tweak_add`,
    `keys.prvkey_tweak_mul`, `xonly.prvkey_tweak_add`,
    `ecdh.shared_secret`, `ellswift.xdh`, `dsa.nonce_rfc6979` and
    `ssa.nonce_bip340`. btclib passes none of them, and that is a
    decision, not an oversight. Three call sites read one of those
    straight into a Python `int`: `bip32.derive`
    (`btclib/bip32/bip32.py:624`), `commit_nonce.commit_nonce_`
    (`btclib/ecc/commit_nonce.py:145`) and `taproot._tweaked_prvkey`
    (`btclib/script/taproot.py:429`). A caller-owned buffer can be
    wiped once the call that filled it returns; the `int` it is read
    into cannot be, and outlives the call regardless —
    `bip32.derive` keeps `prv_key_int` for the life of the key
    object — so taking the buffer at these three would cost a public
    signature and buy nothing, short of btclib no longer holding a
    private key as a Python `int`, which is a change to that
    representation and not to a call site. `ellswift.xdh`
    (`btclib/ecc/ellswift.py:346`) is the one of them that returns
    octets rather than an `int`, so a caller-owned buffer there would
    hold what it wiped: taking it means growing `xdh`'s public
    signature with `into=` and owning the contract that comes with
    it — a buffer too short, a buffer that is not writable, what the
    function then returns. btclib declines that too, for the reason
    the bullet above already gives: no Python object holding a secret
    is zeroized, on either path, and this one is no exception to it.
    `dsa.Signer.__init__` (`btclib/ecc/dsa.py:1346`) crosses the same
    boundary the other way, once, at construction: the plain `int`
    `int_from_prv_key` already produced becomes a transient `bytes` via
    `self._q.to_bytes(32, "big")` on the way into the owned buffer
    `wipe` overwrites afterwards. That `bytes` is dropped rather than
    erased, same as the `int` it replaces — one call rather than the
    buffer's whole lifetime, which is the trade this class exists to
    make, and stated here for the same reason the other three call
    sites are
- the boundary is not always there, and an install decides whether it
    is. `pip install "btclib[secp256k1]"` -- the spelling README.md and
    the guide give -- installs the bindings, and everything the next
    bullet says describes that installation. `pip install btclib`
    installs no C at all: signing, verification, BIP32 derivation and key
    agreement all run the Python arithmetic the last bullet describes,
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
- not every operation crosses that boundary. `mult`, `double_mult_var` and
    `multi_mult_var` reach the bindings for secp256k1 and any point of it, a
    zero scalar and the point at infinity excepted — libsecp256k1 has no
    scalar for the one and no public key for the other; `dsa.sign` for
    secp256k1 with sha256, the lower-s form, no caller-imposed nonce and
    no commitment; `ssa.sign` for secp256k1 with sha256, a message of
    any size and no commitment; `taproot.output_prvkey`,
    `dh.diffie_hellman`, `commit_nonce.commit_nonce_` and the private
    half of `bip32.derive` for secp256k1, the tweaking of a key, the
    shared point of a key agreement, the tweaking of a sign-to-contract
    nonce and the offsetting of a parent key by the left half of an hmac
    being four other places a secret meets the curve.
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
    nonce's bit-length — 8.8 us for a 256-bit scalar against 4.3 for a
    128-bit one on secp256k1's order — which is the correlation the
    Minerva attack turns into the private key.
    `bms.sign` is delegated outright, `recovery.sign` signing and naming
    the recovery flag in one call: message signing is defined for
    secp256k1 alone, so there is no argument that sends it down the
    Python path — the switch above is what reaches it, and nothing a
    caller passes does. BIP32 derivation is the same case, and
    for the same reason: `bip32.derive` adds the offset with
    `keys.prvkey_tweak_add` privately and `keys.PubkeyTweakChain`
    publicly, and the Python arm behind them — BIP32's two sums, on
    integers and on a point — is one no argument selects either.
    `silent_payments.output_keys` is the sender's half of BIP352, which
    is the same case a third time: it reaches
    `silentpayments.create_outputs` for every private key an eligible
    input carries, a keypair built and wiped per taproot input and a
    scalar buffer per other one, exactly as `dsa.sign` and `ssa.sign`
    build and wipe theirs. `scan_outputs`, BIP352's light-client scan, is
    not delegated — it takes the shared secret already reduced, which is
    the shape a light client has and the bindings' own `scan_outputs`
    does not accept, wanting the raw inputs to derive it from instead —
    so every secret that function meets is still Python's alone.
    `scan_transaction_outputs`, the full-node sibling a wallet holding
    the transaction itself can call, is a fourth case: where the
    bindings serve secp256k1 it reaches `silentpayments.scan_outputs`
    with `b_scan`, the recipient's scan private key, built once for a
    whole transaction rather than once per input; off that path it falls
    back to `scan_outputs` above and stays Python's alone.
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
