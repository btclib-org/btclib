from btclib.ellipticcurves import pointMultiply, pointMultiplyJacobian, \
                                  secp192k1, secp192r1, secp224k1, secp224r1, \
                                  secp256k1, secp256r1, secp384r1, secp521r1
import os
import time

all_curves = [secp192k1, secp192r1, secp224k1, secp224r1, \
              secp256k1, secp256r1, secp384r1, secp521r1]

names = ['secp192k1', 'secp192r1', 'secp224k1', 'secp224r1', \
         'secp256k1', 'secp256r1', 'secp384r1', 'secp521r1']

counter = 0
for curve in all_curves:
    # random point
    q = os.urandom(curve.bytesize)
    start1 = time.time()
    Q = pointMultiply(curve, q, curve.G)
    end1 = time.time()

    start2 = time.time()
    Qjac = pointMultiplyJacobian(curve, q, curve.G)
    end2 = time.time()

    print("On the curve", names[counter], "the jacobian " + \
          "scalar multiplication is around ", (end1 - start1) // (end2 - start2), 
          " times faster then the affine case.")
    counter += 1