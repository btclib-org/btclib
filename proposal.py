from copy import deepcopy
from typing import List

from btclib import var_bytes
from btclib.ecc import dsa, ssa
from btclib.ecc.curve import mult, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256, tagged_hash
from btclib.script import script
from btclib.script.script_pub_key import ScriptPubKey, type_and_payload
from btclib.script.sig_hash import (
    ANYONECANPAY,
    NONE,
    SIG_HASH_TYPES,
    SINGLE,
    from_tx,
    legacy,
    segwit_v0,
)
from btclib.script.witness import Witness
from btclib.to_pub_key import pub_keyinfo_from_key
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut


def taproot(
    transaction: Tx,
    input_index: int,
    prevouts: List[TxOut],
    hashtype: int,
    ext_flag: int,
    annex: bytes,
    message_extension: bytes,
) -> bytes:

    amounts = [x.value for x in prevouts]
    scriptpubkeys = [x.script_pub_key for x in prevouts]

    if hashtype not in SIG_HASH_TYPES:  # pragma: no cover
        raise BTClibValueError(f"Unknown hash type: {hashtype}")
    if hashtype & 0x03 == SINGLE and input_index >= len(
        transaction.vout
    ):  # pragma: no cover
        raise BTClibValueError("Sighash single wihout a corresponding output")

    preimage = b"\x00"
    preimage += hashtype.to_bytes(1, "little")
    preimage += transaction.nVersion.to_bytes(4, "little")
    preimage += transaction.nLockTime.to_bytes(4, "little")

    if hashtype & 0x80 != ANYONECANPAY:
        sha_prevouts = b""
        sha_amounts = b""
        sha_scriptpubkeys = b""
        sha_sequences = b""
        for i, vin in enumerate(transaction.vin):
            sha_prevouts += vin.prev_out.serialize()
            sha_amounts += amounts[i].to_bytes(8, "little")
            sha_scriptpubkeys += var_bytes.serialize(scriptpubkeys[i].script)
            sha_sequences += vin.nSequence.to_bytes(4, "little")
        preimage += sha256(sha_prevouts)
        print(
            "sha_prevouts:",
            f"SHA256({sha_prevouts.hex()}) =",
            sha256(sha_prevouts).hex(),
        )
        preimage += sha256(sha_amounts)
        print(
            "sha_amounts:",
            f"SHA256({sha_amounts.hex()}) =",
            sha256(sha_amounts).hex(),
        )
        preimage += sha256(sha_scriptpubkeys)
        print(
            "sha_scriptpubkeys:",
            f"SHA256({sha_scriptpubkeys.hex()}) =",
            sha256(sha_scriptpubkeys).hex(),
        )
        preimage += sha256(sha_sequences)
        print(
            "sha_sequences:",
            f"SHA256({sha_sequences.hex()}) =",
            sha256(sha_sequences).hex(),
        )

    if hashtype & 0x03 not in [NONE, SINGLE]:
        sha_outputs = b""
        for vout in transaction.vout:
            sha_outputs += vout.serialize()
        preimage += sha256(sha_outputs)
        print(
            "sha_outputs:",
            f"SHA256({sha_outputs.hex()}) =",
            sha256(sha_outputs).hex(),
        )

    annex_present = int(bool(annex))
    preimage += (2 * ext_flag + annex_present).to_bytes(1, "little")

    if hashtype & 0x80 == ANYONECANPAY:
        preimage += transaction.vin[input_index].prev_out.serialize()
        preimage += amounts[input_index].to_bytes(8, "little")
        preimage += var_bytes.serialize(scriptpubkeys[input_index].script)
        preimage += transaction.vin[input_index].nSequence.to_bytes(4, "little")
    else:
        preimage += input_index.to_bytes(4, "little")

    if annex_present:
        sha_annex = var_bytes.serialize(annex)
        preimage += sha256(sha_annex)

    if hashtype & 0x03 == SINGLE:
        preimage += sha256(transaction.vout[input_index].serialize())

    preimage += message_extension
    print()
    print("hash preimage:", preimage.hex())
    print()

    sig_hash = tagged_hash(b"TapSighash", preimage)
    return sig_hash


def tweak_prvkey(prvkey):
    tweaked_prvkey = prvkey
    tweaked_prvkey += int.from_bytes(
        tagged_hash(b"TapTweak", prvkey.to_bytes(32, "big")), "big"
    )
    return tweaked_prvkey % secp256k1.n


def sighash_all():

    tx_id_1 = "8dcb562f365cfeb249be74e7865135cf035add604234fc0d8330b49bec92605f"
    prvkey_1 = (
        48498985203126704114254342778129172809832095360881805809665861396413039236440
    )
    pubkey_1 = mult(prvkey_1)
    pubkey_1_bytes = pub_keyinfo_from_key(pubkey_1)[0]
    vin_i_1 = 0
    amount_1 = 5 * 10 ** 8
    prevout_1 = TxOut(
        value=amount_1,
        script_pub_key=ScriptPubKey(
            script.serialize(["OP_0", hash160(pubkey_1_bytes)])
        ),
    )

    tx_id_2 = "e1323b577ed0d216f4e52bf2b4c490710dfa0088dae3d15e8ba26ad792184361"
    prvkey_2 = (
        93726824068247266672367325031406579275159034217125182473743019242938360769538
    )
    pubkey_2 = mult(tweak_prvkey(prvkey_2))
    pubkey_2_bytes = pub_keyinfo_from_key(pubkey_2)[0][1:]
    vin_i_2 = 1
    amount_2 = 6 * 10 ** 8
    prevout_2 = TxOut(
        value=amount_2,
        script_pub_key=ScriptPubKey(script.serialize(["OP_1", pubkey_2_bytes])),
    )

    unsigned_tx = Tx(
        version=2,
        lock_time=0,
        vin=[
            TxIn(OutPoint(tx_id_1, vin_i_1), script.serialize([]), 0, Witness([])),
            TxIn(OutPoint(tx_id_2, vin_i_2), script.serialize([]), 0, Witness([])),
        ],
        vout=[
            TxOut(
                value=10 * 10 ** 8,
                script_pub_key=ScriptPubKey(
                    script.serialize(
                        [
                            "OP_DUP",
                            "OP_HASH160",
                            "682DFDBC97AB5C31300F36D3C12C6FD854B1B35A",
                            "OP_EQUALVERIFY",
                            "OP_CHECKSIG",
                        ]
                    )
                ),
            ),
        ],
    )

    unsigned_tx_hex = unsigned_tx.serialize(include_witness=True).hex()
    print("Unsigned transaction:", unsigned_tx_hex)
    print()

    print("script_pub_key:", prevout_1.script_pub_key.script.hex())
    print("value:", amount_1 / 10 ** 8)
    print("pubkey", pubkey_1_bytes.hex())
    print("prvkey:", prvkey_1.to_bytes(32, "big").hex())
    print()

    print("script_pub_key:", prevout_2.script_pub_key.script.hex())
    print("value:", amount_2 / 10 ** 8)
    print("prvkey:", prvkey_2.to_bytes(32, "big").hex())
    print()

    sighash_type = 1

    tx = deepcopy(unsigned_tx)

    script_ = script.serialize(
        ["OP_DUP", "OP_HASH160", pubkey_1_bytes, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )
    msg_hash = segwit_v0(script_, tx, 0, sighash_type, amount_1)
    signature = dsa.sign_(msg_hash, prvkey_1).serialize()
    signature += sighash_type.to_bytes(1, "big")
    tx.vin[0].script_witness.stack = [signature, pubkey_1_bytes]

    taproot_sighash_type = 0 if sighash_type == 1 else sighash_type
    msg_hash = taproot(tx, 1, [prevout_1, prevout_2], taproot_sighash_type, 0, b"", b"")
    signature = ssa.sign_(msg_hash, tweak_prvkey(prvkey_2)).serialize()
    signature += b"" if sighash_type == 1 else sighash_type.to_bytes(1, "big")
    tx.vin[1].script_witness.stack = [signature]

    print("msg_hash:", msg_hash.hex())
    print("signature:", signature.hex())
    print()

    signed_tx_hex = tx.serialize(include_witness=True).hex()
    print("Signed transaction:", signed_tx_hex)
    print()

    return tx, 1, [prevout_1, prevout_2]


def sighash_anyonecanpay():

    tx_id = "c27689187fb372f8a2b05ad4405cde0864565223746e51c583520e7a0e84825c"
    prvkey = (
        27190341186540200332819650528449541360438542015203523153592358922397066891571
    )
    pubkey = mult(tweak_prvkey(prvkey))
    pubkey_bytes = pub_keyinfo_from_key(pubkey)[0][1:]
    vin_i = 0
    amount = 25 * 10 ** 7
    prevout = TxOut(
        value=amount,
        script_pub_key=ScriptPubKey(script.serialize(["OP_1", pubkey_bytes])),
    )

    unsigned_tx = Tx(
        version=2,
        lock_time=0,
        vin=[TxIn(OutPoint(tx_id, vin_i), script.serialize([]), 0, Witness([]))],
        vout=[
            TxOut(
                value=14 * 10 ** 7,
                script_pub_key=ScriptPubKey(
                    script.serialize(
                        ["OP_0", "1192FAC5233E4EEFA18859396B74851DE18F8F47"]
                    )
                ),
            ),
            TxOut(
                value=1 * 10 ** 8,
                script_pub_key=ScriptPubKey(
                    script.serialize(
                        [
                            "OP_1",
                            "32C22A6E048B9D4183F612BC1B73A58FC0D4E7F548FD71B732063645D43F4202",
                        ]
                    )
                ),
            ),
        ],
    )

    unsigned_tx_hex = unsigned_tx.serialize(include_witness=True).hex()
    print("Unsigned transaction:", unsigned_tx_hex)
    print()

    print("script_pub_key:", prevout.script_pub_key.script.hex())
    print("value:", amount / 10 ** 8)
    print("prvkey:", prvkey.to_bytes(32, "big").hex())
    print()

    sighash_type = 0x81

    tx = deepcopy(unsigned_tx)

    taproot_sighash_type = 0 if sighash_type == 1 else sighash_type
    msg_hash = taproot(tx, 0, [prevout], taproot_sighash_type, 0, b"", b"")
    signature = ssa.sign_(msg_hash, tweak_prvkey(prvkey)).serialize()
    signature += b"" if sighash_type == 1 else sighash_type.to_bytes(1, "big")
    tx.vin[0].script_witness.stack = [signature]

    print("msg_hash:", msg_hash.hex())
    print("signature:", signature.hex())
    print()

    signed_tx_hex = tx.serialize(include_witness=True).hex()
    print("Signed transaction:", signed_tx_hex)
    print()

    return tx, 0, [prevout]


def sighash_single():

    tx_id_1 = "7b5f4d28196c993caba5232c39adcd4031717d7fceb5197ddf940db20895d4f4"
    prvkey_1 = (
        106443585560504508050339632027251825451215594958091042127652147144059586749368
    )
    pubkey_1 = mult(tweak_prvkey(prvkey_1))
    pubkey_1_bytes = pub_keyinfo_from_key(pubkey_1)[0][1:]
    vin_i_1 = 1
    amount_1 = 1 * 10 ** 8
    prevout_1 = TxOut(
        value=amount_1,
        script_pub_key=ScriptPubKey(script.serialize(["OP_1", pubkey_1_bytes])),
    )

    tx_id_2 = "921533ed566e0afde1b2ec218818c8d5fb77d77cec7b3b7ab7624e1ab4ce1269"
    prvkey_2 = (
        42439479550375352978247565390043052385622333146277802749042178365176187837084
    )
    pubkey_2 = mult(prvkey_2)
    pubkey_2_bytes = pub_keyinfo_from_key(pubkey_2)[0][1:]
    vin_i_2 = 0
    amount_2 = 5 * 10 ** 8
    prevout_2 = TxOut(
        value=amount_2,
        script_pub_key=ScriptPubKey(
            script.serialize(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    hash160(pubkey_2_bytes),
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            )
        ),
    )

    unsigned_tx = Tx(
        version=2,
        lock_time=0,
        vin=[
            TxIn(OutPoint(tx_id_1, vin_i_1), script.serialize([]), 0, Witness([])),
            TxIn(OutPoint(tx_id_2, vin_i_2), script.serialize([]), 0, Witness([])),
        ],
        vout=[
            TxOut(
                value=2 * 10 ** 8,
                script_pub_key=ScriptPubKey(
                    script.serialize(
                        [
                            "OP_DUP",
                            "OP_HASH160",
                            "3BFE0F94EB78A2227664C6EBCF81719467C0106F",
                            "OP_EQUALVERIFY",
                            "OP_CHECKSIG",
                        ]
                    )
                ),
            ),
            TxOut(
                value=3 * 10 ** 8,
                script_pub_key=ScriptPubKey(
                    script.serialize(
                        [
                            "OP_0",
                            "F1DCA6047A919EDC31378DB3C5FCD1E93EEA73F9C7FD8632AB47F18C8B8165F4",
                        ]
                    )
                ),
            ),
        ],
    )

    unsigned_tx_hex = unsigned_tx.serialize(include_witness=True).hex()
    print("Unsigned transaction:", unsigned_tx_hex)
    print()

    print("script_pub_key:", prevout_1.script_pub_key.script.hex())
    print("value:", amount_1 / 10 ** 8)
    print("prvkey:", prvkey_1.to_bytes(32, "big").hex())
    print()

    print("script_pub_key:", prevout_2.script_pub_key.script.hex())
    print("value:", amount_2 / 10 ** 8)
    print("pubkey", pubkey_2_bytes.hex())
    print("prvkey:", prvkey_2.to_bytes(32, "big").hex())
    print()

    sighash_type = 0x03

    tx = deepcopy(unsigned_tx)

    taproot_sighash_type = 0 if sighash_type == 1 else sighash_type
    msg_hash = taproot(tx, 0, [prevout_1, prevout_2], taproot_sighash_type, 0, b"", b"")
    signature = ssa.sign_(msg_hash, tweak_prvkey(prvkey_1)).serialize()
    signature += b"" if sighash_type == 1 else sighash_type.to_bytes(1, "big")
    tx.vin[0].script_witness.stack = [signature]

    print("msg_hash:", msg_hash.hex())
    print("signature:", signature.hex())
    print()

    script_ = prevout_2.script_pub_key.script
    msg_hash = legacy(script_, tx, 1, sighash_type)
    signature = dsa.sign_(msg_hash, prvkey_2).serialize()
    signature += sighash_type.to_bytes(1, "big")
    tx.vin[1].script_sig = script.serialize([signature, pubkey_2_bytes])

    signed_tx_hex = tx.serialize(include_witness=True).hex()
    print("Signed transaction:", signed_tx_hex)
    print()

    return tx, 0, [prevout_1, prevout_2]


def verify(tx, index, prevouts):
    sighash_type = 0  # all
    signature = tx.vin[index].script_witness.stack[0][:64]
    if len(tx.vin[index].script_witness.stack[0]) == 65:
        sighash_type = tx.vin[index].script_witness.stack[0][-1]
        assert sighash_type != 0
    msg_hash = from_tx(prevouts, tx, index, sighash_type)
    pub_key = type_and_payload(prevouts[index].script_pub_key.script)[1]
    ssa.assert_as_valid_(msg_hash, pub_key, signature)


print("Sighash ALL")
print()
verify(*sighash_all())
print("\n" * 2)

print("Sighash ANYONECANPAY")
print()
verify(*sighash_anyonecanpay())
print("\n" * 2)

print("Sighash SINGLE")
print()
verify(*sighash_single())
