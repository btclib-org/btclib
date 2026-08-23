# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Wait until HWI sees one usable device, for a CI job that just started one.

An emulator is a process that answers when it is ready and not when it
was started, and the two are seconds apart: Speculos has an app to load
and a screen to draw before the first APDU is taken, and a test that
asks in between reports no device rather than waiting. The trezor
emulator answers a ping on its own socket, which is what
`integration-hwi.yml` waits for there; Speculos has no such thing, so the
question has to be the real one -- does `hwi enumerate` see a device
that can be talked to.

`enumerate_devices` is btclib's own, which makes this the same call the
fixture will make a second later, with `HwiDevice.is_usable` deciding
what counts: a device that answered a fingerprint and no error. A
Speculos that is up but has no app loaded enumerates with an error and
is therefore not ready, which is the distinction a plain "is the port
open" check cannot make.

`BTCLIB_HWI` names the executable, as it does for the tests -- split on
spaces, so `--emulators` reaches HWI as its own argument. What this adds
to a failure is what was seen instead: the device types and the errors
of the last answer, which is where a missing automation rule or an app
built for another model shows up.

    BTCLIB_HWI="hwi --emulators" \
        python .github/scripts/wait_for_hwi_device.py --timeout 90
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from btclib.exceptions import SignerError
from btclib.hwi import HwiDevice, enumerate_devices


def describe(devices: list[HwiDevice]) -> str:
    """Return one line naming what enumerate answered, errors included."""
    if not devices:
        return "no devices"
    return ", ".join(
        f"{device.type} ({device.error or _named(device)})" for device in devices
    )


def _named(device: HwiDevice) -> str:
    """Return the fingerprint a device answered, or say it answered none."""
    return device.fingerprint.hex() if device.fingerprint else "no fingerprint"


def wait(executable: list[str], network: str, timeout: float) -> int:
    """Poll until one usable device is there, and say what was seen."""
    started = time.monotonic()
    deadline = started + timeout
    seen = "nothing yet"
    while True:
        try:
            devices = enumerate_devices(executable=executable, network=network)
        # a device that is not there yet is HWI failing to run or failing
        # to answer json, which is a SignerError and not an outcome to
        # report: this loop is here precisely for the seconds it lasts
        except SignerError as e:
            seen = str(e)
        else:
            seen = describe(devices)
            usable = [device for device in devices if device.is_usable]
            if len(usable) == 1:
                waited = time.monotonic() - started
                print(f"one usable device after {waited:.1f} s: {seen}")
                return 0
        if time.monotonic() > deadline:
            print(f"::error::no usable device within {timeout:.0f} s: {seen}")
            return 1
        time.sleep(0.5)


def main() -> int:
    """Read the executable from the environment and wait for its device."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--network", default="mainnet")
    args = parser.parse_args()

    named = os.environ.get("BTCLIB_HWI")
    if not named:
        print("::error::BTCLIB_HWI names the hwi to run, and is unset")
        return 1
    return wait(named.split(), args.network, args.timeout)


if __name__ == "__main__":
    sys.exit(main())
