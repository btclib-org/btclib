#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Elliptic curves.

* SEC 2 v.2 curves
  http://www.secg.org/sec2-v2.pdf
* SEC 2 v.1 curves, removed from SEC 2 v.2 as insecure ones
  http://www.secg.org/SEC2-Ver-1.0.pdf
* Federal Information Processing Standards Publication 186-4
  (NIST) curves
  https://oag.ca.gov/sites/all/files/agweb/pdfs/erds1/fips_pub_07_2013.pdf
* Brainpool standard curves
  https://tools.ietf.org/html/rfc5639

"""

# FIXME hexstring in json

import json
from os import path
from typing import Dict

from .curve import Curve

datadir = path.join(path.dirname(__file__), "data")

# Elliptic Curve Cryptography (ECC)
# Brainpool Standard Curves and Curve Generation
# https://tools.ietf.org/html/rfc5639
filename = path.join(datadir, 'ec_Brainpool.json')
with open(filename, 'r') as f:
    Brainpool_params2 = json.load(f)
Brainpool: Dict[str, Curve] = {}
for ec_name in Brainpool_params2:
    Brainpool[ec_name] = Curve(*Brainpool_params2[ec_name])


# FIPS PUB 186-4
# FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION
# Digital Signature Standard (DSS)
# https://oag.ca.gov/sites/all/files/agweb/pdfs/erds1/fips_pub_07_2013.pdf
filename = path.join(datadir, 'ec_NIST.json')
with open(filename, 'r') as f:
    NIST_params2 = json.load(f)
NIST: Dict[str, Curve] = {}
for ec_name in NIST_params2:
    NIST[ec_name] = Curve(*NIST_params2[ec_name])


# SEC 2 v.1 curves, removed from SEC 2 v.2 as insecure ones
# http://www.secg.org/SEC2-Ver-1.0.pdf
filename = path.join(datadir, 'ec_SEC2v1_insecure.json')
with open(filename, 'r') as f:
    SEC2v1_params2 = json.load(f)
SEC2v1: Dict[str, Curve] = {}
for ec_name in SEC2v1_params2:
    SEC2v1[ec_name] = Curve(*SEC2v1_params2[ec_name])


# curves included in both SEC 2 v.1 and SEC 2 v.2
# http://www.secg.org/sec2-v2.pdf
filename = path.join(datadir, 'ec_SEC2v2.json')
with open(filename, 'r') as f:
    SEC2v2_params2 = json.load(f)
SEC2v2: Dict[str, Curve] = {}
for ec_name in SEC2v2_params2:
    SEC2v2[ec_name] = Curve(*SEC2v2_params2[ec_name])
    SEC2v1[ec_name] = Curve(*SEC2v2_params2[ec_name])

CURVES = SEC2v1
CURVES.update(NIST)
CURVES.update(Brainpool)

secp256k1 = CURVES['secp256k1']
