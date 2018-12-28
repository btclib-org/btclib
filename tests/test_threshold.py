#!/usr/bin/env python3

import os
import unittest
from btclib.numbertheory import mod_inv, legendre_symbol
from btclib.ellipticcurves import int_from_Scalar, bytes_from_Point, \
                                  pointMultiply, DoubleScalarMultiplication, \
                                  secondGenerator, \
                                  secp256k1 as ec, sha256
from btclib.ecssa import sha256, int_from_hash, _ecssa_verify

class TestEcssaThreshold(unittest.TestCase):
    """ testing a 2-of-3 threshold signature based on Pedersen secret sharing"""
    
    def test_threshold(self):
        # parameters
        t = 2
        H = secondGenerator(ec, sha256)
        msg = sha256('message to sign'.encode()).digest()

        ### FIRST PHASE: key pair generation ###

        # signer one acting as the dealer
        commits1 = list()
        q1 = 0 # secret value
        while q1 == 0:
            q1 = int_from_Scalar(ec, os.urandom(ec.bytesize))
        q1_prime = 0
        while q1_prime == 0:
            q1_prime = int_from_Scalar(ec, os.urandom(ec.bytesize))

        commits1.append(DoubleScalarMultiplication(ec, q1, ec.G, q1_prime, H))

        # sharing polynomials
        f1 = list()
        f1.append(q1)
        f1_prime = list()
        f1_prime.append(q1_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f1.append(temp) 
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f1_prime.append(temp)
            commits1.append(DoubleScalarMultiplication(ec, f1[i], ec.G, f1_prime[i], H))

        # shares of the secret
        alpha12 = 0 # share of q1 belonging to P2
        alpha12_prime = 0
        alpha13 = 0  # share of q1 belonging to P3
        alpha13_prime = 0
        for  i in range(0, t):
            alpha12 += (f1[i] * pow(2, i)) % ec.n
            alpha12_prime += (f1_prime[i] * pow(2, i)) % ec.n

            alpha13 += (f1[i] * pow(3, i)) % ec.n
            alpha13_prime += (f1_prime[i] * pow(3, i)) % ec.n

        # player two verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(2, i), commits1[i])) 
        assert DoubleScalarMultiplication(ec, alpha12, ec.G, alpha12_prime, H) == RHS, 'player one is cheating'

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(3, i), commits1[i])) 
        assert DoubleScalarMultiplication(ec, alpha13, ec.G, alpha13_prime, H) == RHS, 'player one is cheating'
         
        

        # signer two acting as the dealer
        commits2 = list()
        q2 = 0 # secret value
        while q2 == 0:
            q2 = int_from_Scalar(ec, os.urandom(ec.bytesize))
        q2_prime = 0
        while q2_prime == 0:
            q2_prime = int_from_Scalar(ec, os.urandom(ec.bytesize))

        commits2.append(DoubleScalarMultiplication(ec, q2, ec.G, q2_prime, H))

        # sharing polynomials
        f2 = list()
        f2.append(q2)
        f2_prime = list()
        f2_prime.append(q2_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f2.append(temp)
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f2_prime.append(temp)
            commits2.append(DoubleScalarMultiplication(ec, f2[i], ec.G, f2_prime[i], H))

        # shares of the secret
        alpha21 = 0 # share of q2 belonging to P1
        alpha21_prime = 0
        alpha23 = 0  # share of q2 belonging to P3
        alpha23_prime = 0
        for  i in range(0, t):
            alpha21 += (f2[i] * pow(1, i)) % ec.n
            alpha21_prime += (f2_prime[i] * pow(1, i)) % ec.n

            alpha23 += (f2[i] * pow(3, i)) % ec.n
            alpha23_prime += (f2_prime[i] * pow(3, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(1, i), commits2[i])) 
        assert DoubleScalarMultiplication(ec, alpha21, ec.G, alpha21_prime, H) == RHS, 'player two is cheating'

        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(3, i), commits2[i])) 
        assert DoubleScalarMultiplication(ec, alpha23, ec.G, alpha23_prime, H) == RHS, 'player two is cheating'


        # signer three acting as the dealer
        commits3 = list()
        q3 = 0 # secret value
        while q3 == 0:
            q3 = int_from_Scalar(ec, os.urandom(ec.bytesize))
        q3_prime = 0
        while q3_prime == 0:
            q3_prime = int_from_Scalar(ec, os.urandom(ec.bytesize))

        commits3.append(DoubleScalarMultiplication(ec, q3, ec.G, q3_prime, H))

        # sharing polynomials
        f3 = list()
        f3.append(q3)
        f3_prime = list()
        f3_prime.append(q3_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f3.append(temp)
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f3_prime.append(temp)
            commits3.append(DoubleScalarMultiplication(ec, f3[i], ec.G, f3_prime[i], H))

        # shares of the secret
        alpha31 = 0 # share of q3 belonging to P1
        alpha31_prime = 0
        alpha32 = 0  # share of q3 belonging to P2
        alpha32_prime = 0
        for  i in range(0, t):
            alpha31 += (f3[i] * pow(1, i)) % ec.n
            alpha31_prime += (f3_prime[i] * pow(1, i)) % ec.n

            alpha32 += (f3[i] * pow(2, i)) % ec.n
            alpha32_prime += (f3_prime[i] * pow(2, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(1, i), commits3[i])) 
        assert DoubleScalarMultiplication(ec, alpha31, ec.G, alpha31_prime, H) == RHS, 'player three is cheating'

        # player two verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(2, i), commits3[i])) 
        assert DoubleScalarMultiplication(ec, alpha32, ec.G, alpha32_prime, H) == RHS, 'player two is cheating'
         

        # shares of the secret key q = q1 + q2 + q3
        alpha1 = (alpha21 + alpha31) % ec.n
        alpha2 = (alpha12 + alpha32) % ec.n
        alpha3 = (alpha13 + alpha23) % ec.n
        for i in range(0, t):
            alpha1 += (f1[i] * pow(1, i)) % ec.n
            alpha2 += (f2[i] * pow(2, i)) % ec.n
            alpha3 += (f3[i] * pow(3, i)) % ec.n

        # it's time to recover the public key Q = Q1 + Q2 + Q3 = (q1 + q2 + q3)G
        A1 = list()
        A2 = list()
        A3 = list()

        # each participant i = 1, 2, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(0, t):
            A1.append(pointMultiply(ec, f1[i], ec.G))
            A2.append(pointMultiply(ec, f2[i], ec.G))
            A3.append(pointMultiply(ec, f3[i], ec.G))
        
        # he checks the others' values
        # player one
        RHS2 = 1, 0
        RHS3 = 1, 0
        for i in range(0, t):
            RHS2 = ec.add(RHS2, pointMultiply(ec, pow(1, i), A2[i]))
            RHS3 = ec.add(RHS3, pointMultiply(ec, pow(1, i), A3[i]))
        assert pointMultiply(ec, alpha21, ec.G) == RHS2, 'player two is cheating'
        assert pointMultiply(ec, alpha31, ec.G) == RHS3, 'player three is cheating'

        # player two
        RHS1 = 1, 0
        RHS3 = 1, 0
        for i in range(0, t):
            RHS1 = ec.add(RHS1, pointMultiply(ec, pow(2, i), A1[i]))
            RHS3 = ec.add(RHS3, pointMultiply(ec, pow(2, i), A3[i]))
        assert pointMultiply(ec, alpha12, ec.G) == RHS1, 'player one is cheating'
        assert pointMultiply(ec, alpha32, ec.G) == RHS3, 'player three is cheating'

        # player three
        RHS1 = 1, 0
        RHS2 = 1, 0
        for i in range(0, t):
            RHS1 = ec.add(RHS1, pointMultiply(ec, pow(3, i), A1[i]))
            RHS2 = ec.add(RHS2, pointMultiply(ec, pow(3, i), A2[i]))
        assert pointMultiply(ec, alpha13, ec.G) == RHS1, 'player one is cheating'
        assert pointMultiply(ec, alpha23, ec.G) == RHS2, 'player two is cheating'


        A = list() # commitment at the global sharing polynomial
        for i in range(0, t):
            A.append(ec.add(A1[i], ec.add(A2[i], A3[i])))
            
        Q = A[0] # aggregated public key



        ### SECOND PHASE: generation of the nonces' pair ###
        # This phase follows exactly the key generation procedure
        # suppose that player one and three want to sign

        # signer one acting as the dealer
        commits1 = list()
        k1 = 0 # secret value
        while k1 == 0:
            k1 = int_from_Scalar(ec, os.urandom(ec.bytesize))
        k1_prime = 0
        while k1_prime == 0:
            k1_prime = int_from_Scalar(ec, os.urandom(ec.bytesize))

        commits1.append(DoubleScalarMultiplication(ec, k1, ec.G, k1_prime, H))

        # sharing polynomials
        f1 = list()
        f1.append(k1)
        f1_prime = list()
        f1_prime.append(k1_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f1.append(temp)
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f1_prime.append(temp)
            commits1.append(DoubleScalarMultiplication(ec, f1[i], ec.G, f1_prime[i], H))

        # shares of the secret
        beta13 = 0  # share of k1 belonging to P3
        beta13_prime = 0
        for  i in range(0, t):
            beta13 += (f1[i] * pow(3, i)) % ec.n
            beta13_prime += (f1_prime[i] * pow(3, i)) % ec.n


        # player three verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(3, i), commits1[i])) 
        assert DoubleScalarMultiplication(ec, beta13, ec.G, beta13_prime, H) == RHS, 'player one is cheating'
         
        

        # signer three acting as the dealer
        commits3 = list()
        k3 = 0 # secret value
        while k3 == 0:
            k3 = int_from_Scalar(ec, os.urandom(ec.bytesize))
        k3_prime = 0
        while k3_prime == 0:
            k3_prime = int_from_Scalar(ec, os.urandom(ec.bytesize))

        commits3.append(DoubleScalarMultiplication(ec, k3, ec.G, k3_prime, H))

        # sharing polynomials
        f3 = list()
        f3.append(k3)
        f3_prime = list()
        f3_prime.append(k3_prime)
        for i in range(1, t):
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f3.append(temp)
            temp = 0
            while temp == 0:
                temp = int_from_Scalar(ec, os.urandom(ec.bytesize))
            f3_prime.append(temp)
            commits3.append(DoubleScalarMultiplication(ec, f3[i], ec.G, f3_prime[i], H))

        # shares of the secret
        beta31 = 0 # share of k3 belonging to P1
        beta31_prime = 0
        for  i in range(0, t):
            beta31 += (f3[i] * pow(1, i)) % ec.n
            beta31_prime += (f3_prime[i] * pow(1, i)) % ec.n

        # player one verifies consistency of his share
        RHS = 1, 0
        for i in range(0, t):
            RHS = ec.add(RHS, pointMultiply(ec, pow(1, i), commits3[i])) 
        assert DoubleScalarMultiplication(ec, beta31, ec.G, beta31_prime, H) == RHS, 'player three is cheating'

        # shares of the secret nonce
        beta1 =  beta31 % ec.n
        beta3 = beta13 % ec.n
        for i in range(0, t):
            beta1 += (f1[i] * pow(1, i)) % ec.n
            beta3 += (f3[i] * pow(3, i)) % ec.n

        # it's time to recover the public nonce
        B1 = list()
        B3 = list()

        # each participant i = 1, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(0, t):
            B1.append(pointMultiply(ec, f1[i], ec.G))
            B3.append(pointMultiply(ec, f3[i], ec.G))

        
        # he checks the others' values
        # player one
        RHS3 = 1, 0
        for i in range(0, t):
            RHS3 = ec.add(RHS3, pointMultiply(ec, pow(1, i), B3[i]))
        assert pointMultiply(ec, beta31, ec.G) == RHS3, 'player three is cheating'

        # player three
        RHS1 = 1, 0
        for i in range(0, t):
            RHS1 = ec.add(RHS1, pointMultiply(ec, pow(3, i), B1[i]))
        assert pointMultiply(ec, beta13, ec.G) == RHS1, 'player one is cheating'

        B = list() # commitment at the global sharing polynomial
        for i in range(0, t):
            B.append(ec.add(B1[i], B3[i]))

        K = B[0] # aggregated public nonce
        if legendre_symbol(K[1], ec._p) != 1:
            beta1 = ec.n - beta1
            beta3 = ec.n - beta3

        

        ### PHASE THREE: signature generation ###
        
        # partial signatures
        e = int_from_hash(sha256(K[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q, True) + msg).digest(), ec, sha256)
        gamma1 = (beta1 + e * alpha1) % ec.n
        gamma3 = (beta3 + e * alpha3) % ec.n

        # each participant verifies the other partial signatures

        # player one
        if legendre_symbol(K[1], ec._p) == 1:
            RHS3 = ec.add(K, pointMultiply(ec, e, Q))
            for i in range(1, t):
                RHS3 = ec.add(RHS3,
                    DoubleScalarMultiplication(ec, pow(3, i), B[i], e * pow(3, i), A[i]))
        else:
            assert legendre_symbol(K[1], ec._p) != 1
            RHS3 = ec.add(ec.opposite(K), pointMultiply(ec, e, Q))
            for i in range(1, t):
                RHS3 = ec.add(RHS3,
                    DoubleScalarMultiplication(ec, pow(3, i), ec.opposite(B[i]), e * pow(3, i), A[i]))

        assert pointMultiply(ec, gamma3, ec.G) == RHS3, 'player three is cheating'


        # player three
        if legendre_symbol(K[1], ec._p) == 1:
            RHS1 = ec.add(K, pointMultiply(ec, e, Q))
            for i in range(1, t):
                RHS1 = ec.add(RHS1,
                    DoubleScalarMultiplication(ec, pow(1, i), B[i], e * pow(1, i), A[i]))
        else:
            assert legendre_symbol(K[1], ec._p) != 1
            RHS1 = ec.add(ec.opposite(K), pointMultiply(ec, e, Q))
            for i in range(1, t):
                RHS1 = ec.add(RHS1,
                    DoubleScalarMultiplication(ec, pow(1, i), ec.opposite(B[i]), e * pow(1, i), A[i]))

        assert pointMultiply(ec, gamma1, ec.G) == RHS1, 'player two is cheating'


        ### PHASE FOUR: aggregating the signature ###
        omega1 = 3 * mod_inv(3 - 1, ec.n) % ec.n
        omega3 = 1 * mod_inv(1 - 3, ec.n) % ec.n
        sigma = (gamma1 * omega1 + gamma3 * omega3) % ec.n

        ecssa = (K[0], sigma)

        self.assertTrue(_ecssa_verify(ecssa, msg, Q, ec))

        ### ADDITIONAL PHASE: reconstruction of the private key ###
        secret = (omega1 * alpha1 + omega3 * alpha3)  % ec.n
        self.assertEqual((q1 + q2 + q3) % ec.n, secret)


    if __name__ == "__main__":
        # execute only if run as a script
        unittest.main()
    