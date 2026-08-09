# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A production custody wallet, in the two shapes it is deployed in.

The design is one a custodian runs on mainnet today, and it is two p2wsh
wallets rather than one: a *vault* that holds the coins, and a *transit*
wallet they pass through on the way out. Each hides two spending paths
behind a single address -- a quorum that spends now, and a recovery
quorum that spends only after a relative timelock -- and each is ranged
over a receive branch and a change branch, so an address is a
(wallet, branch, index) triple.

What earns the module its place is that the same design is deployed in
two shapes, and only one of them is a descriptor.

The **ranged** shape is miniscript, exactly: `andor(multi,multi,and_v(v:multi,
older))` for the vault, `or_i(multi,and_v(v:multi,older))` for the transit
wallet. Its keys are ordered once, at the account level, so one ranged
descriptor covers every index -- and `Descriptor.address(i)` is then the
whole of the wallet's address book. Two independent deployments of it are
pinned below, one against the other, so a regression has to survive being
wrong the same way twice.

The **plain** shape, older, is not a descriptor and cannot be made into
one, for two reasons that do not depend on each other:

- it spells its timelock `<n> OP_CSV OP_DROP`, where `and_v(v:older(n),X)`
  compiles to `<n> OP_CSV OP_VERIFY`. The two are equivalent to the
  interpreter and different to sha256, so the p2wsh addresses differ. No
  miniscript fragment emits the OP_DROP form;
- it orders the keys of each quorum by BIP67 on the *derived* keys, so the
  order is remade at every index. `sortedmulti()` follows that order, but
  it is a BIP383 descriptor function, not a BIP379 fragment, and is
  refused inside a combinator.

So the plain shape is built here the only way it can be built -- BIP32
derivation, a sort, `script.serialize`, `p2wsh` -- and its addresses are
pinned beside the descriptor ones. That is the point of testing it here:
those four calls are the supported path for a script no descriptor
expresses, and this module is what says so. The two refusals are pinned
as well, message included, because a later release that started *accepting*
either spelling would change what a descriptor means, not just what it
parses.

Every address below is a mainnet address that has held value. They are
transcribed from the wallets' own committed address lists, and the two
timelocks -- 5184 blocks, 576 blocks -- are the deployed ones.
"""

import pytest

from btclib.b32 import p2wsh
from btclib.bip32.bip32 import BIP32KeyData, derive_from_account
from btclib.descriptors import (
    MiniscriptDescriptor,
    WshDescriptor,
    add_checksum,
    miniscript,
    parse,
    strip_checksum,
)
from btclib.exceptions import BTClibValueError
from btclib.script import Command, op_int, script
from btclib.utils import encode_num

# The ranged shape, twice: the descriptor of each (wallet, branch), and
# the first eleven addresses it derives. The two deployments share the
# design and share no key.
_RANGED: dict[str, dict[str, dict[int, tuple[str, list[str]]]]] = {
    "A": {
        "vault": {
            0: (
                "wsh(andor(multi(2,[2a840f9a/44h/0h/0h]xpub6CnduF4oQjma6Mfi6y152nQr6Kajn2S2FFtDBL5n8VHAK1a2yNgL21N3oEY64rwt4YqM7fWfjCuiFLGLnSdCRZNrWR79d73TrygetmkUrnZ/0/*,[6dd4ac6b/44h/0h/0h]xpub6CuLXhy6wGUr4VBG3Zy7erP3xqE7PyWo1FjwB8A8Yyvu9qxMk5YioetECypEmNw1hH7ydJCo5ZhAgzqj5d7rc4CD2UdRuJqzCLrQ58qmcEe/0/*,[33ed73ce/44h/0h/0h]xpub6CzDVp3oZQnipC2LdNAPr3iPQsYbCANmSj6b9GEMEyXxHqCKbfceB5SmC5fYPXHZ62eLffpmvRUj3khVDSjCyzpDtpoXWH6qz5TJFnAMLfd/0/*),multi(3,[f4227b38/44h/0h/0h]xpub6BykPdbm1hu98pcHwHXMcou9EZjU7Mav3ehvjkpR1sXyH5jTjiih6eegZ4K2sLc99eU846GLyvadexHgnXDqx7E6hs7vYJKR8Jqwspf56AM/0/*,[f45a5bf7/44h/0h/0h]xpub6Bz9qcmBHwwVD5QvQKb52NKKzyL2Ltf5yvagANN8zfs38raqcWsqYJM34oD5M58wybocFeUbxxqA19EkkzGqhSxv5FSUDVsap6DsNxdS411/0/*,[a1358590/44h/0h/0h]xpub6CBC1SBNaTzbDG8W68wh4EZu69EVTR1zp1g5DN1HTvCzLEzhWu4X6qcP6UmEcvmrbdpwpj36wKUh9JyT9Snz3fTgKPFY2CpPi7S83896cpR/0/*,[7be8cfb9/44h/0h/0h]xpub6CmAvs9iNE83QDzo4PCca22jbJZy1riV1RGwc9ZRYMxFWH1Xkxmmm2L1Er5Nad69FPd1gdaaUa1K94ipJcFrbTaDMKFda7GEcikfYzxssEG/0/*,[a997d159/44h/0h/0h]xpub6CScGsh3T2uNSyaKW1ZJRTg4rFAdKQd4DQQnva4Gj25QBYU4nZj5Yb7whfJmrBXG1gZKVT8QMxLnCntyFPTH82xHSezkCVN4i1EtbQEdf5k/0/*,[9236d126/44h/0h/0h]xpub6DSwqmov12UpAEPCssM5jCL6ETySftDQdabRsQZKvTgQDezT3Cy2s5qYa8HxFxFGsexREh6tgTZgZDGyKcmvXaRtAE7qHmtoTxnuncK1ySy/0/*),and_v(v:multi(2,[f80a24f2/44h/0h/0h]xpub6BrtYCAymUwZsNqfebu9pkrLv3YXwBSo7deRs7GhXqCBJriUFPU72h9bbMRoZTBXY1rXAEtuL928U19nLqhvvyBvVb7RMYMuvy9qS2LUr85/0/*,[2f86cb6b/44h/0h/0h]xpub6CA5nedvMo7P9d1qHVuUghDWNS7ENZFBnNZaTXfKJxd1h4eXjTaByt5vudfHjgNFStcbrFurtRZfe1VjRkubNfgoEvGJxpBeq8GM8xhwh95/0/*,[81849a8b/44h/0h/0h]xpub6CGf5YsRUXN2pbRtBHFyVfCro7ZZChki8NCp1Wmxhk1RfmZAVF7zfppqfisgJQm1DU3mTzGJJJYeWfW96hbXMsFQLG7QyjVauDvjx72LnSM/0/*),older(5184))))#qm9csdex",
                [
                    "bc1qqgjmdnlcg2ecg9nwnxpw8atavjkh8hd8t8kf8dtsy23zxc0hny6srkf0cz",
                    "bc1qwkl0v4cu0024jxlwhel3pp26m2edsl6uh7yppqxd4s5wn9ktmuuq7lqux4",
                    "bc1qvm8rgerj6jkkkddlcvwvu6gma5aj4lyeh3n2mcx58nuy64tgwqtqy0pqvg",
                    "bc1qxzphkwqptp4zy95u94yq963wj263tda0zk6fm5upjucjz22taxns6amuq8",
                    "bc1qw8ts5yks4wmw2ljk966gtqdpzf940shkgjwfwwpzjhn6gwdmcw6qpp6ne8",
                    "bc1qnsxuqzvrpamywftuhhry3rpkcpjuvl6j3k6nrg4ua2kx5ulgeuxs57s3r6",
                    "bc1q5dghywwksnm2mclr7jqe0vd8du6phxntdszplvrylnrqd8vatstsmusplp",
                    "bc1qhgzt8a0tznxzurwgftqv9zd4r477fuc75hznvv8g34k2g7n4wqlsjpypul",
                    "bc1q3th9a22q008x6ls8yh7gy2sq5c8kdv9xcv3yqhtt9mgg65m6mssqljm6t9",
                    "bc1q084843u5ed4cuamlutmusktgf765cw9pun6kvzhkvu7elrwv58qquqg58m",
                    "bc1qqhmmqjyey32m78dyxeazya5tqytgny8tdd8u536n9w3lqnlmlnhsfagv05",
                ],
            ),
            1: (
                "wsh(andor(multi(2,[2a840f9a/44h/0h/0h]xpub6CnduF4oQjma6Mfi6y152nQr6Kajn2S2FFtDBL5n8VHAK1a2yNgL21N3oEY64rwt4YqM7fWfjCuiFLGLnSdCRZNrWR79d73TrygetmkUrnZ/1/*,[6dd4ac6b/44h/0h/0h]xpub6CuLXhy6wGUr4VBG3Zy7erP3xqE7PyWo1FjwB8A8Yyvu9qxMk5YioetECypEmNw1hH7ydJCo5ZhAgzqj5d7rc4CD2UdRuJqzCLrQ58qmcEe/1/*,[33ed73ce/44h/0h/0h]xpub6CzDVp3oZQnipC2LdNAPr3iPQsYbCANmSj6b9GEMEyXxHqCKbfceB5SmC5fYPXHZ62eLffpmvRUj3khVDSjCyzpDtpoXWH6qz5TJFnAMLfd/1/*),multi(3,[f4227b38/44h/0h/0h]xpub6BykPdbm1hu98pcHwHXMcou9EZjU7Mav3ehvjkpR1sXyH5jTjiih6eegZ4K2sLc99eU846GLyvadexHgnXDqx7E6hs7vYJKR8Jqwspf56AM/1/*,[f45a5bf7/44h/0h/0h]xpub6Bz9qcmBHwwVD5QvQKb52NKKzyL2Ltf5yvagANN8zfs38raqcWsqYJM34oD5M58wybocFeUbxxqA19EkkzGqhSxv5FSUDVsap6DsNxdS411/1/*,[a1358590/44h/0h/0h]xpub6CBC1SBNaTzbDG8W68wh4EZu69EVTR1zp1g5DN1HTvCzLEzhWu4X6qcP6UmEcvmrbdpwpj36wKUh9JyT9Snz3fTgKPFY2CpPi7S83896cpR/1/*,[7be8cfb9/44h/0h/0h]xpub6CmAvs9iNE83QDzo4PCca22jbJZy1riV1RGwc9ZRYMxFWH1Xkxmmm2L1Er5Nad69FPd1gdaaUa1K94ipJcFrbTaDMKFda7GEcikfYzxssEG/1/*,[a997d159/44h/0h/0h]xpub6CScGsh3T2uNSyaKW1ZJRTg4rFAdKQd4DQQnva4Gj25QBYU4nZj5Yb7whfJmrBXG1gZKVT8QMxLnCntyFPTH82xHSezkCVN4i1EtbQEdf5k/1/*,[9236d126/44h/0h/0h]xpub6DSwqmov12UpAEPCssM5jCL6ETySftDQdabRsQZKvTgQDezT3Cy2s5qYa8HxFxFGsexREh6tgTZgZDGyKcmvXaRtAE7qHmtoTxnuncK1ySy/1/*),and_v(v:multi(2,[f80a24f2/44h/0h/0h]xpub6BrtYCAymUwZsNqfebu9pkrLv3YXwBSo7deRs7GhXqCBJriUFPU72h9bbMRoZTBXY1rXAEtuL928U19nLqhvvyBvVb7RMYMuvy9qS2LUr85/1/*,[2f86cb6b/44h/0h/0h]xpub6CA5nedvMo7P9d1qHVuUghDWNS7ENZFBnNZaTXfKJxd1h4eXjTaByt5vudfHjgNFStcbrFurtRZfe1VjRkubNfgoEvGJxpBeq8GM8xhwh95/1/*,[81849a8b/44h/0h/0h]xpub6CGf5YsRUXN2pbRtBHFyVfCro7ZZChki8NCp1Wmxhk1RfmZAVF7zfppqfisgJQm1DU3mTzGJJJYeWfW96hbXMsFQLG7QyjVauDvjx72LnSM/1/*),older(5184))))#c5evhl7t",
                [
                    "bc1qemrhxeshwdu8d46egf99zwdvv3s0e69xlzwdfcrc7usvkfm6em4q59wrm2",
                    "bc1qc7476m7pw8n07dcqt0k33355vadq474evs5ldkwlrd2dnupc7etq69tcpv",
                    "bc1qnqvuv7wl7wdzenkqegxsz8mw2trzjavelcyw3mgvg3ghrhgxlnxsjl33qp",
                    "bc1qen4auru6malcqnth2cs6430gg9s0tsk0nk3aq266nhl9jlpm4x9syrpfmm",
                    "bc1qrmfhtn0822wx853t7vr9rek2897qpdykdnwxum7vh69ltfdramrq5de3u9",
                    "bc1q8ahdwsx5rc98kkelcyt4sn6z77qjydw9c8lsh0q0mmhevmjflg8qsqj95p",
                    "bc1q9xmy2c69cqexp6vzfd8ecqnaz7lymy05nstvpwaueqnpr72mzxzstdlmch",
                    "bc1qhy95dnxh93nzwzpzvea9symnrkp4trvdc2eym086qa0cgl8n79cs04wz06",
                    "bc1q0lh088s3jfs003zkmz8zd7c8pstlng8fatp0nnepjjwy6zfhjdkq9p6fd4",
                    "bc1qpyg97x3utkalgy5gll0dfjwj6t3wk7gnynrfwnemjzpp82rchkwsncnjkx",
                    "bc1qgddcdvphkv44h6kdzmtvnrc59ctzd80s5jttfyxnt0frd0nr4a9q3agjfa",
                ],
            ),
        },
        "transit": {
            0: (
                "wsh(or_i(multi(2,[f80a24f2/44h/0h/0h]xpub6BrtYCAymUwZsNqfebu9pkrLv3YXwBSo7deRs7GhXqCBJriUFPU72h9bbMRoZTBXY1rXAEtuL928U19nLqhvvyBvVb7RMYMuvy9qS2LUr85/0/*,[2f86cb6b/44h/0h/0h]xpub6CA5nedvMo7P9d1qHVuUghDWNS7ENZFBnNZaTXfKJxd1h4eXjTaByt5vudfHjgNFStcbrFurtRZfe1VjRkubNfgoEvGJxpBeq8GM8xhwh95/0/*,[81849a8b/44h/0h/0h]xpub6CGf5YsRUXN2pbRtBHFyVfCro7ZZChki8NCp1Wmxhk1RfmZAVF7zfppqfisgJQm1DU3mTzGJJJYeWfW96hbXMsFQLG7QyjVauDvjx72LnSM/0/*),and_v(v:multi(2,[ee152952/44h/0h/0h]xpub6CQNpTktGtmk4mQLsjJv4SZ2ktqqrdgdHGked7xa6Uf5tf3Ajv1y3gHHsTkZwDrARoFBU7VLbR8RHTru5cC1wDrtm9dV8oojHo7SGKJRBxz/0/*,[2db2ddf4/44h/0h/0h]xpub6D732Pcbfder9q9ksDHtRcWLFkLgp6oqhJ9ZnwoCPCuHA6iRfqVMaTwRc8oSiZx9E8GyHjkdefpCqEqwbC7wTswxFfcA5SHaj5R8ivfMHxj/0/*,[d297fae9/44h/0h/0h]xpub6DStLkmQgMrH8WfbXEZEVVzFx8u3VqVcYSt5m8wwomtjpzjFuQTFRc1eoRW8MyMEuCnfpQCpebE5T9vXUSdHHkANBCCvpXmg6v8pY12dDCu/0/*),older(576))))#d7axyyl0",
                [
                    "bc1qaf60wnl3403973swcamz0ly6q8u2whxvnv0efzlq8f65uhwv46psnatmxy",
                    "bc1qfq8p4wmx6t58mxkykxkrgs5n6nrul2tgxj0hk3szlxttecdxsdwslv9yc3",
                    "bc1qxrrsg4ccd772dd58lp5qmllpselgdfrfqvky067qal7sp8rgd6squ447jt",
                    "bc1qjucls7c0cv284p74r3mzae29efw04l2g3avzqe6vd8n9z8chcntsm6nm89",
                    "bc1qpharjf6ftjv9rpj5gdvau3ak6s32ftlswpjy5z3tgcqmhvank4pqfuzjwj",
                    "bc1qzccjpxdxadkns2m4zne4de3rxzyqffagq0f5unnee7tdkscwez3sz73pje",
                    "bc1qmg44wle2jt8fufldxjpxzvwp3en8y8zud389y69ptwxjnkealxkqqlqjat",
                    "bc1qmrvv7xugpg355t46fcn7wcjeu5ar35ce02u9kqd78h7tz8p9vq4qqhn088",
                    "bc1qvxsghqvwxhhylfhjvmqectsjqkle3rtsgwe5pnwa47xtxfvz0r7qcumuu3",
                    "bc1q7x62g35jqv8fxl237ea4lsta5hva7zpk6g2jefg88gcm6m3cawjqp5aq0n",
                    "bc1qdrqlsdg8xdrs0058zx5dz8j7g2s05sqhyjfnch9y282z7s8mgs4sdkk45f",
                ],
            ),
            1: (
                "wsh(or_i(multi(2,[f80a24f2/44h/0h/0h]xpub6BrtYCAymUwZsNqfebu9pkrLv3YXwBSo7deRs7GhXqCBJriUFPU72h9bbMRoZTBXY1rXAEtuL928U19nLqhvvyBvVb7RMYMuvy9qS2LUr85/1/*,[2f86cb6b/44h/0h/0h]xpub6CA5nedvMo7P9d1qHVuUghDWNS7ENZFBnNZaTXfKJxd1h4eXjTaByt5vudfHjgNFStcbrFurtRZfe1VjRkubNfgoEvGJxpBeq8GM8xhwh95/1/*,[81849a8b/44h/0h/0h]xpub6CGf5YsRUXN2pbRtBHFyVfCro7ZZChki8NCp1Wmxhk1RfmZAVF7zfppqfisgJQm1DU3mTzGJJJYeWfW96hbXMsFQLG7QyjVauDvjx72LnSM/1/*),and_v(v:multi(2,[ee152952/44h/0h/0h]xpub6CQNpTktGtmk4mQLsjJv4SZ2ktqqrdgdHGked7xa6Uf5tf3Ajv1y3gHHsTkZwDrARoFBU7VLbR8RHTru5cC1wDrtm9dV8oojHo7SGKJRBxz/1/*,[2db2ddf4/44h/0h/0h]xpub6D732Pcbfder9q9ksDHtRcWLFkLgp6oqhJ9ZnwoCPCuHA6iRfqVMaTwRc8oSiZx9E8GyHjkdefpCqEqwbC7wTswxFfcA5SHaj5R8ivfMHxj/1/*,[d297fae9/44h/0h/0h]xpub6DStLkmQgMrH8WfbXEZEVVzFx8u3VqVcYSt5m8wwomtjpzjFuQTFRc1eoRW8MyMEuCnfpQCpebE5T9vXUSdHHkANBCCvpXmg6v8pY12dDCu/1/*),older(576))))#ytw57782",
                [
                    "bc1qv875v3v7sxwk8pr43v20exwrsgp4paycp83xfvxztmg8hgxklu9qm8cgxr",
                    "bc1q97u8xn4sylj007795w64wdm5nphde7l2598jzrqm9pjy0wltpkxssa3htl",
                    "bc1ql8lrsk3vdeghk8p9kgpnxelxfhygv2q2agl576p8r0wsp2w8vljqlggtsl",
                    "bc1qeafgkv8qg6e4ekmdxrarcsy00tkupmlkpm24l3h4p8nkfdx6hc8qt62wcc",
                    "bc1qausugn4dgcv8lmy2f7ppyhpng0jqse4pwshlffsc795zg5wp78xquv4jjl",
                    "bc1qjqx3e7ut7yug8je6cl5kftzs83msdfgw2hlasqnygydslmlrq67qx6dld5",
                    "bc1qt8el6n6gv6acel54240ncdske99zqjpws59fxm6wthaw0vncn8uqdvq02j",
                    "bc1qhlcp0zm7s3lr6g00lmukgaz8aumquclhvdn8v6l74qksznpqyexskdc4al",
                    "bc1qy4g2q0vk2lrtp7mpvex60dwcj4lk0eje8ndgtawset439h2nhlusx3mwhy",
                    "bc1qa2pt6jue7k9kge8232tdg5fxgj38rse3uqxlthgmvq70e8tnlhfqqg7c68",
                    "bc1qxg3th30rjpr0zn6tv4t4n6lc9nnjmzy6kl5pgsldl08c5hkz64zq982q68",
                ],
            ),
        },
    },
    "B": {
        "vault": {
            0: (
                "wsh(andor(multi(2,[2a840f9a/44h/0h/1h]xpub6CnduF4oQjma8i21gnojXUdikzmskguKXSq7GLPRiBS1oT8Q93AA4JATYjgt4HstNW44oX7wKW4A3phQJLQN9116DKwPACFprxvVTUzetva/0/*,[6dd4ac6b/44h/0h/1h]xpub6CuLXhy6wGUr7vMzFYGcFxLXozjzEntiFephwF7y285NtQMm5BFmzfwo7D9HnHuTUiaiH1Gh3TTzrvwr4gSFJK3V2nhLx7Sb1jGZfUjGWtk/0/*,[33ed73ce/44h/0h/1h]xpub6CzDVp3oZQnipJKXQnkjfw1sN7VjSC29vvDk3r4EPirDL7ZcEjgNsru3n3mbCosruJLQFpRaJBSnQi95kmLmWSgtb6N2XhjSbdDpVwJHGwy/0/*),multi(3,[f4227b38/44h/0h/1h]xpub6BykPdbm1hu9CTNJ6ibqWVmFqiBRmXnT2S83MGoEuX6ohJkmJBvWYrFHCEjJ6QeCmLuAZ9rhLd8P72WCnsLG2tdvZ1UVsNGBheYegPksYKB/0/*,[f45a5bf7/44h/0h/1h]xpub6Bz9qcmBHwwVFk3AXD7YmMZhbT8xUhXKM6pREdBqTEpBPN9kWJ7sE47BECTxFs4dfHzLp7oTXgMvffpwv18SfQDdyzAU62wPrv7iUVa97xk/0/*,[a1358590/44h/0h/1h]xpub6CBC1SBNaTzbFgjuU9T1EQyDZLsHr13LS6NWdUNzVciMKcCBuYBLHEJ588uGoMtyqGdR35GS2hWYoydVxze5nzUxQK4j5X9M6AbWbqz4C6i/0/*,[7be8cfb9/44h/0h/1h]xpub6CmAvs9iNE83TeZjoWP4wgotisQrC3cUg7mYHviaT4HSydpnCjgtb1fY7TzM8BwMovHP1mtibh1fSQDgBC4xXXmBuMNfs4ysZWV1bNKUP8x/0/*,[a997d159/44h/0h/1h]xpub6CScGsh3T2uNVkY9KNoh4bjkZBXYgLja8kyWgxiHC51aL4hHTKjYpLMvoRFEH5N7KyFx6wkFCsV1y1rfBUz3tkE7EUDY4zf2ks3ffMV7cD8/0/*,[9236d126/44h/0h/1h]xpub6DSwqmov12UpECm9yYiXr3tQ8qTRfUCubpdUw3Y1YiUztu5zjWbyPPpSsE6xf7B5kqt6kVrrorJbLGNdTKxw4NHnKjWCGo11erNr4dpkeqs/0/*),and_v(v:multi(2,[f80a24f2/44h/0h/1h]xpub6BrtYCAymUwZseFSfGv3h1YN9nDPLW62boA11fLwxeYdX6CJ75UZyZAQXk5AGWhhgnGtP165azpD9iZHh1KPiruK6dTKUbJYmmkWUzzDtqj/0/*,[2f86cb6b/44h/0h/1h]xpub6CA5nedvMo7PD39SYXYE8QdTEZZWRBvmuUYG5cVgr4um2FhYztj8oJKUKY4RdVGKwhWRDMZAa2JDbNwSJAUTZnFwaGqHL5WHV5sdCn4whuA/0/*,[81849a8b/44h/0h/1h]xpub6CGf5YsRUXN2sGF5ugBPjkwYQSvdKDRAnLcH798QseaM5rvpG2Q89oLmd5uZzeDucCaMSwdMnkxBVc3PruY97QNoLrLnYw7PpcJGPNVFjWe/0/*),older(5184))))#s4avyxhh",
                [
                    "bc1q74ktjuq0caxpvavn7v9jna6h9qfs9c680a3ut5t39nc5rcdhhfysdzxq5q",
                    "bc1q8gwljxetlyh7encp6vl0hjdxuyjrnu2g2lypd3a6r9hmsa2mexwq83lywr",
                    "bc1q6s360jcjc048tacfx4hxzeckegwa38t9x2ch6vjerfcjtz7afmhs2sz3rf",
                    "bc1q5zw0llh3jvusxkp8ae76eaw7dpsc83ramfxyaluxa6ru83085mksk8pjx9",
                    "bc1q8qsfr33tcguanauqn6u94h925fder6jtpte0wyduxn99wge7keusycx3gt",
                    "bc1qnrdsme8v429rcjt737wrakz3g3nayagew0vu4w03968enlumhsvs92e7uc",
                    "bc1qczmm4fr7k9u459500hqnqa5nlendnuw4yrqhfzxk7g8j2ng9ce9sdrn3wt",
                    "bc1qcxqq32x34tk027gjvgwtrzdzuxnd9m3nqkrjrx2h3erf9jgfjjwqakuckt",
                    "bc1q0t0ze3tyf9jjnpuuml5frm0munth3mfcsqc3s64eg8sxsvdas7hqkmsyp8",
                    "bc1q74vz79uw9srqjskjx3fs2d8ecwfhljrq46egq20z80tgxlv368askps3t7",
                    "bc1quzkn8g8delchj2ntsrwdquhguwcscd73mk8apq2q0402mpp9a43qhe5y98",
                ],
            ),
            1: (
                "wsh(andor(multi(2,[2a840f9a/44h/0h/1h]xpub6CnduF4oQjma8i21gnojXUdikzmskguKXSq7GLPRiBS1oT8Q93AA4JATYjgt4HstNW44oX7wKW4A3phQJLQN9116DKwPACFprxvVTUzetva/1/*,[6dd4ac6b/44h/0h/1h]xpub6CuLXhy6wGUr7vMzFYGcFxLXozjzEntiFephwF7y285NtQMm5BFmzfwo7D9HnHuTUiaiH1Gh3TTzrvwr4gSFJK3V2nhLx7Sb1jGZfUjGWtk/1/*,[33ed73ce/44h/0h/1h]xpub6CzDVp3oZQnipJKXQnkjfw1sN7VjSC29vvDk3r4EPirDL7ZcEjgNsru3n3mbCosruJLQFpRaJBSnQi95kmLmWSgtb6N2XhjSbdDpVwJHGwy/1/*),multi(3,[f4227b38/44h/0h/1h]xpub6BykPdbm1hu9CTNJ6ibqWVmFqiBRmXnT2S83MGoEuX6ohJkmJBvWYrFHCEjJ6QeCmLuAZ9rhLd8P72WCnsLG2tdvZ1UVsNGBheYegPksYKB/1/*,[f45a5bf7/44h/0h/1h]xpub6Bz9qcmBHwwVFk3AXD7YmMZhbT8xUhXKM6pREdBqTEpBPN9kWJ7sE47BECTxFs4dfHzLp7oTXgMvffpwv18SfQDdyzAU62wPrv7iUVa97xk/1/*,[a1358590/44h/0h/1h]xpub6CBC1SBNaTzbFgjuU9T1EQyDZLsHr13LS6NWdUNzVciMKcCBuYBLHEJ588uGoMtyqGdR35GS2hWYoydVxze5nzUxQK4j5X9M6AbWbqz4C6i/1/*,[7be8cfb9/44h/0h/1h]xpub6CmAvs9iNE83TeZjoWP4wgotisQrC3cUg7mYHviaT4HSydpnCjgtb1fY7TzM8BwMovHP1mtibh1fSQDgBC4xXXmBuMNfs4ysZWV1bNKUP8x/1/*,[a997d159/44h/0h/1h]xpub6CScGsh3T2uNVkY9KNoh4bjkZBXYgLja8kyWgxiHC51aL4hHTKjYpLMvoRFEH5N7KyFx6wkFCsV1y1rfBUz3tkE7EUDY4zf2ks3ffMV7cD8/1/*,[9236d126/44h/0h/1h]xpub6DSwqmov12UpECm9yYiXr3tQ8qTRfUCubpdUw3Y1YiUztu5zjWbyPPpSsE6xf7B5kqt6kVrrorJbLGNdTKxw4NHnKjWCGo11erNr4dpkeqs/1/*),and_v(v:multi(2,[f80a24f2/44h/0h/1h]xpub6BrtYCAymUwZseFSfGv3h1YN9nDPLW62boA11fLwxeYdX6CJ75UZyZAQXk5AGWhhgnGtP165azpD9iZHh1KPiruK6dTKUbJYmmkWUzzDtqj/1/*,[2f86cb6b/44h/0h/1h]xpub6CA5nedvMo7PD39SYXYE8QdTEZZWRBvmuUYG5cVgr4um2FhYztj8oJKUKY4RdVGKwhWRDMZAa2JDbNwSJAUTZnFwaGqHL5WHV5sdCn4whuA/1/*,[81849a8b/44h/0h/1h]xpub6CGf5YsRUXN2sGF5ugBPjkwYQSvdKDRAnLcH798QseaM5rvpG2Q89oLmd5uZzeDucCaMSwdMnkxBVc3PruY97QNoLrLnYw7PpcJGPNVFjWe/1/*),older(5184))))#g6pcr5s6",
                [
                    "bc1q69nhxraezwpv7l9hn3u659wht7ttqvq4684ah068p3e66ctjphfsl6mwsp",
                    "bc1qf7r4dp6lhnlpfjqc6r9hv05w22ahxvyrau732h5w0676ts4umg3qn5l0zf",
                    "bc1qqaxs5djza9yj3hmgdaxahxg65qp8wn6yncrzlkvnzjr08gshpq7qy5c69v",
                    "bc1qk2s8andhrjy46esgqsfqcyuwx93cv0vlhuw9gzupfmvt8u5dfuuqwgqa3t",
                    "bc1qfj3frz9fqz52a6w9fjtcdhcf7lt3knwwlscz2q6ynjaj053hw5msyspymm",
                    "bc1q4waw2p38tezn5uka32z07pe5zx9wtcnmqz85xk0ufytdg4d7g5rs8s3h95",
                    "bc1qgs7gq4uce9rl9hgds2d0sr6dsgtw0nxtaqn0vzu0xsvpte6j3flspl6plj",
                    "bc1qjkfhpe8sgkp83exrzp8teet6werptxr93864a8n9tmnte70e3dnspqw56z",
                    "bc1qjn2njkvxevfq0d7gk69mf7ykyg5r48u76mgnxtsp5phryf2hn6xswegj24",
                    "bc1qeldknjlvlunh89v6w0v565vc6fuvdauqt7v7ad4wnh35v2pjnd9spn7lwe",
                    "bc1qkna75lrv7v8r7ftudmlfk2fr38eh3pl85ltmlx4nzd7uqn77glds9weaay",
                ],
            ),
        },
        "transit": {
            0: (
                "wsh(or_i(multi(2,[f80a24f2/44h/0h/1h]xpub6BrtYCAymUwZseFSfGv3h1YN9nDPLW62boA11fLwxeYdX6CJ75UZyZAQXk5AGWhhgnGtP165azpD9iZHh1KPiruK6dTKUbJYmmkWUzzDtqj/0/*,[2f86cb6b/44h/0h/1h]xpub6CA5nedvMo7PD39SYXYE8QdTEZZWRBvmuUYG5cVgr4um2FhYztj8oJKUKY4RdVGKwhWRDMZAa2JDbNwSJAUTZnFwaGqHL5WHV5sdCn4whuA/0/*,[81849a8b/44h/0h/1h]xpub6CGf5YsRUXN2sGF5ugBPjkwYQSvdKDRAnLcH798QseaM5rvpG2Q89oLmd5uZzeDucCaMSwdMnkxBVc3PruY97QNoLrLnYw7PpcJGPNVFjWe/0/*),and_v(v:multi(2,[ee152952/44h/0h/1h]xpub6CQNpTktGtmk7S5YDVhyU1kCo8wRHMfJ3g5oMaiU39w6kk4r7urJaJ4tA8S6FAY7xGMoyxaB7jZUvWkPo2H13SfZz2r96dJCvL4rajjg3Zw/0/*,[2db2ddf4/44h/0h/1h]xpub6D732PcbfderBFhPyyGT2NZij3GJrDGwoiSoUe3coHTSH89v1X85S2enrJ8Hm4GBwvyLR1JNjofGcjFzBmRpeca9NweJVUSPQWZCzTvDbtN/0/*,[d297fae9/44h/0h/1h]xpub6DStLkmQgMrH9Sb2EjejQ2omBj7WqVEBmMbeijAvpcgLTUCdWQ7iDFu4QGq1PHV5pZDLw6fPyFxV219NLzzDcPn6MY4nVi6txLe8JCG5w6Z/0/*),older(576))))#j9cg0exa",
                [
                    "bc1quawl6tulewtau7kt2ek9v66846lgtuhn6y9q3h98783gdp87ymcqecldh0",
                    "bc1q40y283uhg67qtpu7mw7vlxgyygvmzftytfeacy4pm9ag77mzahrszfzmhw",
                    "bc1qn8uds844mk8c38m52fv3h6n6g4cff0dt02ke5r3kwxs65jrecvys6tc83r",
                    "bc1qr3lz0uq5fyjzfh84fpeq8nzz4shcea7qn8fadmjrpdqddq3rsv3s6f4h03",
                    "bc1q0ezynxwzqqscac2du8e6zmp3ehdva9g5c7mdrdg7d9qxrpflsx7s9qwg5a",
                    "bc1qet66rmemq5d2dk2cxspv9uky8m6nuays4ux73nkw3ws2n5g6nrvq0kwyrg",
                    "bc1qmnzeg48y2ga5qsxmmew9xgg88ugmaszr7ds0tgdv3v0wzutnx33shuyulw",
                    "bc1qsrpeas35kfztfdc0jdk4efkwa2vujmus4flqgttg2hdgkr2l0g7sn5jsyh",
                    "bc1q8uwf5sac83pet9a5z0ggf5hmpgjvxanxxcu892cc0u727a2uucdqsrl9yc",
                    "bc1q4a8n53dn0vlj99wx0wlu74k4ndm4a58acrmgf9l4ejtp2vsuzrfql0euuc",
                    "bc1q05mecjxwzjh7k9c22jmf6rtmsywt98x2z7089aqrmwu4fn8j7qvsrv99hj",
                ],
            ),
            1: (
                "wsh(or_i(multi(2,[f80a24f2/44h/0h/1h]xpub6BrtYCAymUwZseFSfGv3h1YN9nDPLW62boA11fLwxeYdX6CJ75UZyZAQXk5AGWhhgnGtP165azpD9iZHh1KPiruK6dTKUbJYmmkWUzzDtqj/1/*,[2f86cb6b/44h/0h/1h]xpub6CA5nedvMo7PD39SYXYE8QdTEZZWRBvmuUYG5cVgr4um2FhYztj8oJKUKY4RdVGKwhWRDMZAa2JDbNwSJAUTZnFwaGqHL5WHV5sdCn4whuA/1/*,[81849a8b/44h/0h/1h]xpub6CGf5YsRUXN2sGF5ugBPjkwYQSvdKDRAnLcH798QseaM5rvpG2Q89oLmd5uZzeDucCaMSwdMnkxBVc3PruY97QNoLrLnYw7PpcJGPNVFjWe/1/*),and_v(v:multi(2,[ee152952/44h/0h/1h]xpub6CQNpTktGtmk7S5YDVhyU1kCo8wRHMfJ3g5oMaiU39w6kk4r7urJaJ4tA8S6FAY7xGMoyxaB7jZUvWkPo2H13SfZz2r96dJCvL4rajjg3Zw/1/*,[2db2ddf4/44h/0h/1h]xpub6D732PcbfderBFhPyyGT2NZij3GJrDGwoiSoUe3coHTSH89v1X85S2enrJ8Hm4GBwvyLR1JNjofGcjFzBmRpeca9NweJVUSPQWZCzTvDbtN/1/*,[d297fae9/44h/0h/1h]xpub6DStLkmQgMrH9Sb2EjejQ2omBj7WqVEBmMbeijAvpcgLTUCdWQ7iDFu4QGq1PHV5pZDLw6fPyFxV219NLzzDcPn6MY4nVi6txLe8JCG5w6Z/1/*),older(576))))#mst64r7c",
                [
                    "bc1qw0ch7pychgesetfzrmnvjsyhds5ruxcykp3kayjwlg5fvhv9yc2qpydgk2",
                    "bc1qcqk2rrsva4h575a7v9fwkm0tltwmzqypxrr6z6j2x40pe8e7wfvqp9ufyu",
                    "bc1q4gy8mc5pc0z7jpc5a6qdfm94tfn5k8qura5kfczjtg9xeazja9jslj2wfq",
                    "bc1qcfmmw70yfwzrul9uxrr0tagm6a0uvs2y9dprxzhxn86saadalnysl4nxgz",
                    "bc1qks4q3tmah3xhea4v3zhnn3st5jyqe4t2tautwqepr0x9w22xm9lqyhvl8g",
                    "bc1qzl700mv0td54etkhznsgvt2f5gmhr5qq2s6sagy77hz5v0uvltfq4s4wjv",
                    "bc1q2un9jxfy96mehyfym2sa9kh0qzrf25vdavx4yn4tndq5ptt0srqq3xfza7",
                    "bc1qkv9gsjvlsvpmkdng4q94gx9agmndfwpnegryt4wmm96gdnc54yssrh9u27",
                    "bc1qtpr6npaejd0af6a9ejkfgqs3f2cgywsen452rfuh59ckeqgsk7ssmjuhz8",
                    "bc1qwyavdknzpe5263pajd26wt54cmyqwreg273up92450d0g7zcuj0sksstxl",
                    "bc1qll2f7dec7kkjdhntvt6jgz2df84rkgjnffd0h4mnm5qf076k7x9sut4h4m",
                ],
            ),
        },
    },
}

# The three quorums of the plain shape, as the deployment declares them:
# the order here is not the order any script carries, that being remade
# at every index by the sort in _quorum() below.
_PRIMARY = [
    "xpub6D6awsXa3fUQLn2XmtUkcasyEjSDud7AWYSHozQN7Saa96wsKobXU16xtbUFiTBfLAGWMoCgYpXFV9JucMbYrp39HzpmB6KqqPiDN8V9Ku2",
    "xpub6CJYVn69dkz2yjgSS57yjKxcMwvZwjrchEnjfCSFYtrpYmzZuJN3117TaN9brxeVNZsAy28y4vYCafMC42VRoaWy5HbSRbQzarfBnHayozq",
    "xpub6CtqcCdzB3FaZ2ZtViA1BRagjQaEguHP42NMwhfaMXwWXzszJaoZLtEa2yCQTMW1SowRKsWRENdp4kE7XbEpfBZP1dSqRTkHppEJz9RFfnL",
    "xpub6BfqXB44WfJboBbs3MwaN3iFrXPT6wyikAmPgs7GBX6JABdwuUfgCZGBY5Qpbj4qDMGYPWcUXtRsNBqNbgqDxEvpsdfR3pb77FVhjENz91K",
    "xpub6BntFtGKWcGiRd2xmeiUmq4fKamot1nVXdAV8h4z3tiybQrZPqr1NZPQt1wunkv6W6ny7UPfARuKj34GnXkX7GCkb9oHLQqufvnazdKZT3U",
    "xpub6D1G61LzXXXSH8PShtTbiwx46YdmDcuhQmX5AoXKHkm5cKuzvDfbuoxXKBPVXn4TaqRLq897U42qx9mcEA2HNtFcy8BsfAkBgzLWcYu3rS2",
]

# 2-of-3, both wallets: one set of keys exercises both recovery paths.
_RECOVERY = [
    "xpub6CA5nedvMo7P9d1qHVuUghDWNS7ENZFBnNZaTXfKJxd1h4eXjTaByt5vudfHjgNFStcbrFurtRZfe1VjRkubNfgoEvGJxpBeq8GM8xhwh95",
    "xpub6CGf5YsRUXN2pbRtBHFyVfCro7ZZChki8NCp1Wmxhk1RfmZAVF7zfppqfisgJQm1DU3mTzGJJJYeWfW96hbXMsFQLG7QyjVauDvjx72LnSM",
    "xpub6BrtYCAymUwZsNqfebu9pkrLv3YXwBSo7deRs7GhXqCBJriUFPU72h9bbMRoZTBXY1rXAEtuL928U19nLqhvvyBvVb7RMYMuvy9qS2LUr85",
]

# 2-of-3, transit only.
_CUSTODIAN = [
    "xpub6Cr9tNnAaCsiDM5koANKzdDhnvftXdh53bXPaww4ahcGHMazPhXN9phBUKeGMwXxHyZ4WKQAL2wdqpwCuXFqAQMXsRJ16wcQ5v78ou4zge6",
    "xpub6CN4B8FUzABoCQ5i2WPPSEGhHC8fPUKAyTFDSHK6U5j2znSmDetT9LNJiHVgFPZpahPpBcBKdicv3SHeVJyDN9FeTPxLdS8bmaX8yebZVUo",
    "xpub6CfVyv5uHm7S4Aeb9Zppc6V2nrfufUfJf5o1Q6NKoc1ZFMJ6GRfD8DzSfRQEbbL7DVg35vtY36cqxQgg1F5aFAysH9i79QF9dt6HhH1QQNE",
]

# The deployed timelocks: 36 days on the vault's recovery path, 4 days
# on the transit wallet's ordinary one.
_VAULT_RECOVERY_BLOCKS = 5184
_TRANSIT_PRIMARY_BLOCKS = 576

# The addresses the plain shape derives, by (wallet, branch).
_PLAIN: dict[str, dict[int, list[str]]] = {
    "vault": {
        0: [
            "bc1q0wk2apulgmd982ssqyxuq4vhhxrzrgg4qdynqkz7yhw4sqq62gqqcpvyjn",
            "bc1qg0lza27ftrad9pcpuujrj6kw5dnj4wfetgnl746tp3u4u6x5fs7q9rc8kz",
            "bc1q6mums3uac9lkfm5as95725t2zq0egh3a4k08ggd9m6evudrh4axsu27u54",
            "bc1qezddpg5746xv95ymsy2yg6m8cdajrjrd4e2e8fe7zvx365a3ezys9fj3l8",
            "bc1qgep553eurd38c740v8k53p5tmnnlswpq54424cjz6nmssq47ctkqvyqfk3",
            "bc1q9zvzszm80dwk2dp52ygn6z2wkrw23c335qn5r6all4868x6qwn9q6g0chh",
            "bc1qavyww34wlpjemvvjpr0apmpandjsk284rwyctres2jsulrpc7m3qwhgzgv",
            "bc1qvzvvhc2xqkq8tjrr4q40lwwq3w58g62crzzedzmz7xrm37r37ysqk7w69c",
            "bc1q2yupfwr54k33ghr6apjxu4g7klwx7ganzpxpqd0cw07zh992p9kqv38e7p",
            "bc1qfnxyjy8dx6qauzwp6gne2x37cwzupra77x9r5rx4gqtef96hjetspg3pgm",
            "bc1qehln0s5vlxwc4c9zhl4tt5hvtmtf0ye6sfqn0c0wgpdf40hx8kgs83r028",
        ],
        1: [
            "bc1q3hyj6evw35jkdj6dpq2pgd35zwlnfzhhx408mfy0ylmtmtexak8swydu0h",
            "bc1q2fnez9qznnk3m7cjht0xy3euhq6eldn3cu6vzf5r7hv7lzleacxsen3lda",
            "bc1qh39wmrkv9hv20y499c3ahrsmcsh7xpv9rhqa94p2rwqtu6df982s9fwenl",
            "bc1qehxuzx5tqvg0jw74q93m7zgec8hrrte9e5nnrafls5gcmympyuxstyzg0f",
            "bc1qkanzllzw7kgwghx0fsn3hadl2amkp389hw3gmd4lackmduv5p40qmvtxxh",
            "bc1qcntnm7qvwmfkc2ssfhlkyhdpncfjfv4uf6a9th94egtxrdl489qs4j8ncu",
            "bc1qqst9un5sz8576fy2nnqkpm4rpfh0weveqwtt8zxgjp02g2mx5q7s2vresu",
            "bc1qms8pucsgj4j5axstjul42gcelsah34qxr63ccml324r3rtch7w3qt6a9xx",
            "bc1qmjtzvgk50afwezsld70qj4g43usdyewmjulj8rhqvksdervdt67szj322f",
            "bc1q9jeqlz7v9ahlrlldmgk432ac582d2n4th8r8nkarpmc20pf3r2nse5nvzx",
            "bc1qqhjhk5jrj8semqq3l83ea2jwwtdpun2fd48rxd4revd390ucf2wqgsk2xc",
        ],
    },
    "transit": {
        0: [
            "bc1qs0325qjlgy7uu55ag5ud4kzpmqz97e8ne8e4d0r2zr5t83egtjusm25l8c",
            "bc1q3rpx4l4h2t3l5m2zxfsmkt9pvvez8a68nkz2ve3tv292jsr4yhwq29hvlw",
            "bc1qyq8w2t06qlqp3ye7ep9d772f9kfhkhu7rhndfy42h2m7uzn5rj8qddqfl4",
            "bc1q3pcr5ec8a58lzrfdh884cs8vn4p7vf79en97zrgst62f7rzukgfqajrrq8",
            "bc1q4fgg8nmqk9lxtg25vx4z9egykd2xtceh9rh9fn55zm3wmalr5s2qmkwfyy",
            "bc1q0qhu06w5ejd2dugyj5a9fvuwjnlwysye0n8l2dadjwf45848nkqsvmwsrj",
            "bc1qdxl49d40p5pqwdq3xjutxrv748v8e93rg6zsjpgf3z772256js8sru060j",
            "bc1qzag6qr973h6jyyjppm8r3w6mgdtztr9agnf4uxjjt9hlrxt50ntskaucj6",
            "bc1qqzrshchansrd9aaatpnccqxuxukg4zef9uel3hge0zdtg0jdt9pqhye9rz",
            "bc1qur7vyqn7u60sffm607etctvamwr2u4fsup85g8nqhly52mazfm2s8acmt6",
            "bc1qlg32mta6gwzry8qa9jnug725lfpxzw9uydsku2t3v9yv8fzuxzksmw9a7t",
        ],
        1: [
            "bc1qhkf280pycdw3g7n8wqrk8jdr7kagf0umv657dap6nmd2zp89t40qles08e",
            "bc1qa6atf6c3veg9l2mak5y5rnj2ehuqcn5lkagl5jyy22p5wsuwgu0q58lh2m",
            "bc1qzqdctzvuv2xfu4xcyrne2kc8zfmdvuv86sfh04rakv8jxvcqgugq6t9mga",
            "bc1qsf9vsuy5xlfdqwqdcq7s3g5zphpha8yqtgv6z2sq884q3hk6freqjzm7a5",
            "bc1qft33qjwgfzmyc0yf303mhc20u8q5wql2wdzpeq34flalj4n7hkeqagtyya",
            "bc1qk6q9z96fz9sffv6nvdz0xervy2qg9asqsvv5e3q2pmgcqkgx3xlqzhwt87",
            "bc1q049nyw54ggay6dskzt8j45j469eld8v8w833sklq0qrsw3a8nyasdnnhsx",
            "bc1q5qlgusxw458ndw2muczxgkrprt7txgyyrtl9432r0vucd0dhtc3qgkxwav",
            "bc1qhe9x3wxx980hxguewt9twnksugt6mpfescx0zv27zn90wjk6wgdqfeas3v",
            "bc1qz48eajrwf84hujtvfdq38jrsdcskjc8lg6snajp88er975tfm3eqlplnmu",
            "bc1qzfzgxnvxcmmf96ey44ggh8rnfas7s9rtgdwchg8gzmkfvjcyul3qu3q7d2",
        ],
    },
}


_POSITIONS = [
    (deployment, wallet, branch)
    for deployment in _RANGED
    for wallet in ("vault", "transit")
    for branch in (0, 1)
]


def _quorum(threshold: int, xpubs: list[str], branch: int, index: int) -> list[Command]:
    """Return `k <key>... n OP_CHECKMULTISIG`, BIP67 on the derived keys.

    The sort is what no ranged descriptor can follow: it runs on the keys
    of *this* index, so the order a script carries is not a property of
    the wallet, and two indices of one quorum can list the same keys the
    other way round.
    """
    keys = sorted(
        BIP32KeyData.b58decode(derive_from_account(xpub, branch, index)).key
        for xpub in xpubs
    )
    return [op_int(threshold), *keys, op_int(len(keys)), "OP_CHECKMULTISIG"]


def _older(blocks: int) -> list[Command]:
    """Return the timelock as the plain shape spells it, with the OP_DROP."""
    return [encode_num(blocks).hex(), "OP_CHECKSEQUENCEVERIFY", "OP_DROP"]


def _plain_witness_script(wallet: str, branch: int, index: int) -> bytes:
    """Return the witness script of the plain shape, at one position."""
    if wallet == "vault":
        commands = [
            "OP_IF",
            *_quorum(3, _PRIMARY, branch, index),
            "OP_ELSE",
            *_older(_VAULT_RECOVERY_BLOCKS),
            *_quorum(2, _RECOVERY, branch, index),
            "OP_ENDIF",
        ]
    else:
        commands = [
            "OP_IF",
            *_older(_TRANSIT_PRIMARY_BLOCKS),
            *_quorum(2, _CUSTODIAN, branch, index),
            "OP_ELSE",
            *_quorum(2, _RECOVERY, branch, index),
            "OP_ENDIF",
        ]
    return script.serialize(commands)


@pytest.mark.parametrize("deployment,wallet,branch", _POSITIONS)
def test_ranged_descriptor_addresses(deployment: str, wallet: str, branch: int) -> None:
    """Every address of the ranged shape is the one the deployment uses."""
    descriptor, addresses = _RANGED[deployment][wallet][branch]
    parsed = parse(descriptor)
    assert parsed.is_ranged
    assert [parsed.address(i) for i in range(len(addresses))] == addresses


@pytest.mark.parametrize("deployment,wallet,branch", _POSITIONS)
def test_ranged_descriptor_round_trips(
    deployment: str, wallet: str, branch: int
) -> None:
    """The descriptor survives its checksum, and its script lifts back to it.

    Two directions of the same claim, and the second is the one a wallet
    verifying somebody else's script needs: the concrete witness script at
    an index goes back up to a miniscript, and that miniscript writes the
    very same bytes.
    """
    descriptor, _ = _RANGED[deployment][wallet][branch]
    assert add_checksum(strip_checksum(descriptor)) == descriptor

    parsed = parse(descriptor)
    assert isinstance(parsed, WshDescriptor)
    inner = parsed.inner
    assert isinstance(inner, MiniscriptDescriptor)
    for index in (0, 1, 7):
        witness_script = inner.redeem_script(index)
        assert miniscript.from_script(witness_script, miniscript.P2WSH).script() == (
            witness_script
        )


@pytest.mark.parametrize("wallet", ["vault", "transit"])
@pytest.mark.parametrize("branch", [0, 1])
def test_plain_addresses(wallet: str, branch: int) -> None:
    """The plain shape is reachable, and reaches the deployed addresses.

    No descriptor is involved and none can be: this is `derive_from_account`,
    a sort, `script.serialize` and `p2wsh`, which is the whole of what a
    caller needs for a script the descriptor language does not cover.
    """
    addresses = _PLAIN[wallet][branch]
    assert [
        p2wsh(_plain_witness_script(wallet, branch, i), "mainnet")
        for i in range(len(addresses))
    ] == addresses


@pytest.mark.parametrize("wallet", ["vault", "transit"])
def test_plain_script_is_not_a_miniscript(wallet: str) -> None:
    """`<n> OP_CSV OP_DROP` closes no fragment, and that is the message."""
    witness_script = _plain_witness_script(wallet, 0, 0)
    err_msg = "not a miniscript: op code 0x75 closes no fragment"
    with pytest.raises(BTClibValueError, match=err_msg):
        miniscript.from_script(witness_script, miniscript.P2WSH)


def test_sorted_multi_is_not_a_fragment() -> None:
    """`sortedmulti()` is a descriptor function, and stays outside miniscript.

    Which is the second reason the plain shape has no descriptor: its
    per-index order is exactly what `sortedmulti()` follows, and there is
    nowhere inside `or_i()` to write one.
    """
    key = f"[00000000/44h/0h/0h]{_PRIMARY[0]}/0/*"
    with pytest.raises(BTClibValueError, match="unknown miniscript fragment"):
        parse(add_checksum(f"wsh(or_i(sortedmulti(1,{key}),1))"))

    # while the same expression on its own is a descriptor, and a ranged
    # one: what is missing is the combinator around it, not the sort
    assert parse(add_checksum(f"wsh(sortedmulti(1,{key}))")).is_ranged
