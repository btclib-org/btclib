#!/usr/bin/env python3

from ecssa import sha256, int_from_prvkey, ec, int_from_hash, ecssa_verify

prv1 = int_from_prvkey('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d92ad1d')
prv2 = int_from_prvkey('0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d')

Q1 = ec.pointMultiply(prv1)
Q2 = ec.pointMultiply(prv2)

# Steps
HQ1 = int_from_hash(sha256(ec.bytes_from_point(Q1, False)).digest(), ec.order)
HQ2 = int_from_hash(sha256(ec.bytes_from_point(Q2, False)).digest(), ec.order)
Q_All = ec.pointAdd(ec.pointMultiply(HQ1, Q1), ec.pointMultiply(HQ2, Q2))

# stage 1
msg = 'message to sign'
print(msg)
m = sha256(msg.encode()).digest()

eph_prv1 = 0x012a2a833eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbb
eph_prv2 = 0x01a2a0d3eac4e67e06611aba01345b85cdd4f5ad44f72e369ef0dd640424dbdb

## Steps
R1 = ec.pointMultiply(eph_prv1)
if R1[1] % 2 == 1: #must be even
    eph_prv1 = ec.order - eph_prv1 
    R1 = ec.pointMultiply(eph_prv1)
R1_x = R1[0]

R2 = ec.pointMultiply(eph_prv2)
if R2[1] % 2 == 1: #must be even
    eph_prv2 = ec.order - eph_prv2
    R2 = ec.pointMultiply(eph_prv2)
R2_x = R2[0]


## stage 2

## steps
prv1 = HQ1* prv1
prv2 = HQ2* prv2


R2_y_recovered = ec.y(R2_x, 0)   
R2_recovered = (R2_x, R2_y_recovered)
R1_All = ec.pointAdd(R1, R2_recovered)

if R1_All[1] % 2 == 1:      # must be even
    eph_prv1 = ec.order - eph_prv1
R1_All_x = R1_All[0].to_bytes(32, 'big')

e1 = int_from_hash(sha256(R1_All_x + m).digest(), ec.order)
assert e1 != 0 and e1 < ec.order, "sign fail"
s1 = (eph_prv1 - e1 * prv1) % ec.order


R1_y_recovered = ec.y(R1_x, 0)
R1_recovered = (R1_x, R1_y_recovered)
R2_All = ec.pointAdd(R2, R1_recovered)

if R2_All[1] % 2 == 1:
    eph_prv2 = ec.order - eph_prv2
R2_All_x = R2_All[0].to_bytes(32, 'big')

e2 = int_from_hash(sha256(R2_All_x + m).digest(), ec.order)
assert e2 != 0 and e2 < ec.order, "sign fail"
s2 = (eph_prv2 - e2 * prv2) % ec.order

## combine stage 2 signatures into a full signature

assert R1_All_x == R2_All_x, "sign fail"
R_All_x = R1_All[0]
s_All = (s1 + s2) % ec.order
ssasig = (R_All_x, s_All)


#verification
v = ecssa_verify(msg, ssasig, Q_All, sha256)
print(v)
