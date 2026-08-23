# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib.hwi` against a real HWI, and whatever it is plugged into.

`tests/hwi_test.py` runs the adapter against a stand-in and answers every
question about the argv, the bounds and the failures. What it cannot
answer is whether HWI itself accepts what btclib sends: the descriptor
`displayaddress` is given, the path spelling of `getxpub`, the psbt
`signtx` reads. That is what this is for, and there is no way to ask it
without an HWI and a device.

Bring your own, which is what the emulator item of issue #381 comes down
to: HWI's own suite starts a simulator per device family, each with its
own binary, image and udev rules, and vendoring that is the "large
security and maintenance surface unrelated to btclib's Bitcoin
primitives" the issue rules out. So the switches are two:

    BTCLIB_INTEGRATION=1 BTCLIB_HWI=hwi uv run pytest -n0 tests/integration

with `BTCLIB_HWI` naming the executable -- `hwi`, a path, or a command
with flags of its own, split on spaces, which is how an emulator is
reached: `hwi --emulators`. Signing is asked for only where
`BTCLIB_HWI_SIGN` says so, because a device that signs is a device
somebody is standing in front of, pressing a button. `-n0` because there
is one device: `addopts` passes `-n auto`, and three workers are three
HWI processes reaching for it at once, where the one that arrives
mid-exchange waits out btclib's timeout.

Two emulators are what CI brings, which is issues #529 and #738 and not
a change of that rule. `integration-hwi.yml` runs a pinned Trezor Model T
seeded with the mnemonic HWI's own suite uses, and a Ledger under
Speculos with the Bitcoin app built from a pinned tag -- twice, the coin
being compiled into a Ledger app, so the mainnet build answers the two
read-only tests and the testnet one signs. Both jobs set
`BTCLIB_HWI_SIGN`, because in neither is there anybody to press
anything: HWI opens a udp Trezor with `TrezorClientDebugLink`, which
answers the button request itself, and Speculos is given an automation
file matching the text the app draws.

Two clients of HWI's, therefore, and not one twice -- the protobuf one
and the app-2.x one, which is why the second job is worth its cost. What
neither can answer is whether a device with a secure element, a screen
and firmware of its own agrees, so the vendors they do not run stay what
they were: bring your own.

Nothing here is destructive: enumerate, an xpub, an address on a screen.
Setup, wipe, restore, backup and the PIN flows are deliberately outside
this and outside `btclib.hwi` altogether.
"""

from __future__ import annotations

import os

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient

from btclib.core_import import account_import_requests
from btclib.descriptors import at_index
from btclib.hwi import HwiSigner, enumerate_devices
from btclib.psbt_signer import (
    AddressDisplay,
    PsbtSigner,
    display_address,
    export_account,
    request_signatures,
)
from tests.integration.conftest import as_regtest, broadcast, fund, spending_psbt

pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def hwi_executable() -> list[str]:
    """Return the HWI to run, skipping without both switches."""
    if not os.environ.get("BTCLIB_INTEGRATION"):
        pytest.skip("set BTCLIB_INTEGRATION=1 to run the integration tests")
    named = os.environ.get("BTCLIB_HWI")
    if not named:
        pytest.skip("set BTCLIB_HWI to the hwi executable to run these")
    return named.split()


def _one_device(hwi_executable: list[str], network: str) -> HwiSigner:
    """Return a signer over the one device HWI can see, or skip.

    The refusal of two devices is `btclib.hwi`'s own and is tested against
    the stand-in; here a session with two plugged in is one that cannot
    say which the operator meant, so it skips rather than picking.
    """
    devices = enumerate_devices(executable=hwi_executable, network=network)
    usable = [one for one in devices if one.is_usable]
    if len(usable) != 1:
        pytest.skip(f"{len(usable)} usable devices of {len(devices)} enumerated")
    return HwiSigner(usable[0].fingerprint, executable=hwi_executable, network=network)


@pytest.fixture(scope="session")
def device(hwi_executable: list[str]) -> HwiSigner:
    """Return a mainnet signer over the device, for the read-only asks."""
    return _one_device(hwi_executable, "mainnet")


@pytest.fixture(scope="session")
def regtest_device(hwi_executable: list[str]) -> HwiSigner:
    """Return a regtest signer over the same device, for the spend.

    A separate one because `--chain` is what decides the version bytes of
    the xpubs HWI answers with, and an account of a chain is not an
    account of another: the coin type of the path says which, and BIP44
    gives every test chain 1.
    """
    return _one_device(hwi_executable, "regtest")


def test_hwi_answers_the_contract(device: HwiSigner) -> None:
    """The three read-only questions, against whatever is plugged in.

    The fingerprint is what the device was selected by, so what this adds
    is that HWI accepts the path spelling `getxpub` is given and answers
    an extended key btclib reads back.
    """
    assert isinstance(device, PsbtSigner)
    assert len(device.master_fingerprint) == 4

    receive, change = export_account(device, "m/84h/0h/0h")
    origin = receive.key_expressions[0].origin
    assert origin is not None
    assert origin.master_fingerprint == device.master_fingerprint
    assert receive.address(0) != change.address(0)


def test_the_device_shows_the_address_the_descriptor_describes(
    device: HwiSigner,
) -> None:
    """Somebody has to look at the screen; what this checks is the answer.

    `display_address` compares what HWI returns with what the descriptor
    describes, so a device deriving another index -- which is what a
    ranged descriptor would get, HWI applying index 0 to it -- fails here
    rather than being believed.
    """
    if not isinstance(device, AddressDisplay):
        pytest.skip("this signer does not display addresses")
    receive = export_account(device, "m/84h/0h/0h")[0]

    for index in (0, 3):
        shown = display_address(device, receive, index)
        assert shown == receive.address(index)
        assert shown == at_index(receive, index).address()


@pytest.mark.skipif(
    not os.environ.get("BTCLIB_HWI_SIGN"),
    reason="set BTCLIB_HWI_SIGN=1 to ask a device to sign: it needs a button press",
)
def test_the_device_signs_what_btclib_built(
    regtest_device: HwiSigner,
    node: BitcoinCoreRpcClient,
    wallets: tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient],
) -> None:
    """The same flow as the software signer's, with a device in its place.

    Which is the whole claim of the contract: `request_signatures` does
    not know what is at the other end, so the only line that changes is
    which signer is passed. What this adds is the device -- whether HWI
    accepts the fields btclib's Updater wrote, and whether the signature
    that comes back is one the network takes.

    Behind a switch of its own because it needs a person: a device asks
    before it signs, and nothing here can press the button.
    """
    miner, watcher = wallets
    receive, change = export_account(regtest_device, "m/84h/1h/0h")
    watcher.call(
        "importdescriptors",
        [account_import_requests(receive, change, key_range=(0, 5))],
    )

    fund(miner, as_regtest(receive).address(0), "0.5")
    utxo = watcher.call("listunspent", [1, 9999999])[0]
    psbt = spending_psbt(node, utxo, receive, change, miner.call("getnewaddress"))

    signed = request_signatures(regtest_device, psbt)
    tx_id = broadcast(node, signed)
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    assert node.call("getrawtransaction", [tx_id, True])["confirmations"] == 1
