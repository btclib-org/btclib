#!/usr/bin/env python3

import unittest
from btclib.ellipticcurves import int_from_Scalar, bytes_from_Point, \
                                  pointAdd, pointMultiplyJacobian, \
                                  secondGenerator, opposite
from btclib.ecssa import sha256, ec, int_from_hash, ecssa_verify
from btclib.numbertheory import mod_inv
import os

# testing a 2-of-3 threshold signature based on Pedersen secret sharing

class TestEcssaThreshold(unittest.TestCase):
    
    def test_threshold(self):
        # parameters
        t = 2
        m = 3

        H = secondGenerator(ec)

        msg = 'message to sign'
        msg = sha256(msg.encode()).digest()

        ### FIRST PHASE: key pair generation ###

        # signer one acting as the dealer
        commits1 = list()
        q1 = int.from_bytes(os.urandom(ec.bytesize), 'big') # secret value
        while q1 == 0:
            q1 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        q1_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')
        while q1_prime == 0:
            q1_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')

        commits1.append(pointAdd(ec, pointMultiplyJacobian(ec, q1, ec.G), \
                                     pointMultiplyJacobian(ec, q1_prime, H)))

        # sharing polynomials
        f1 = list()
        f1.append(q1)
        f1_prime = list()
        f1_prime.append(q1_prime)
        for i in range(1, t):
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f1.append(temp)
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f1_prime.append(temp)
            commits1.append(pointAdd(ec, pointMultiplyJacobian(ec, f1[i], ec.G), \
                                     pointMultiplyJacobian(ec, f1_prime[i], H)))

        # shares of the secret
        alpha12 = 0 # share of q1 belonging to P2
        alpha12_prime = 0
        alpha13 = 0  # share of q1 belonging to P3
        alpha13_prime = 0
        for  i in range(0, t):
            alpha12 += f1[i] * pow(2, i) % ec.n
            alpha12_prime += f1_prime[i] * pow(2, i) % ec.n

            alpha13 += f1[i] * pow(3, i) % ec.n
            alpha13_prime += f1_prime[i] * pow(3, i) % ec.n

        # player two verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(2, i), commits1[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, alpha12, ec.G), \
                            pointMultiplyJacobian(ec, alpha12_prime, H)) == RHS, 'player one is cheating'

        # player three verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(3, i), commits1[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, alpha13, ec.G), \
                            pointMultiplyJacobian(ec, alpha13_prime, H)) == RHS, 'player one is cheating'
         
        

        # signer two acting as the dealer
        commits2 = list()
        q2 = int.from_bytes(os.urandom(ec.bytesize), 'big') # secret value
        while q2 == 0:
            q2 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        q2_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')
        while q2_prime == 0:
            q2_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')

        commits2.append(pointAdd(ec, pointMultiplyJacobian(ec, q2, ec.G), \
                                     pointMultiplyJacobian(ec, q2_prime, H)))

        # sharing polynomials
        f2 = list()
        f2.append(q2)
        f2_prime = list()
        f2_prime.append(q2_prime)
        for i in range(1, t):
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f2.append(temp)
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f2_prime.append(temp)
            commits2.append(pointAdd(ec, pointMultiplyJacobian(ec, f2[i], ec.G), \
                                     pointMultiplyJacobian(ec, f2_prime[i], H)))

        # shares of the secret
        alpha21 = 0 # share of q2 belonging to P1
        alpha21_prime = 0
        alpha23 = 0  # share of q2 belonging to P3
        alpha23_prime = 0
        for  i in range(0, t):
            alpha21 += f2[i] * pow(1, i) % ec.n
            alpha21_prime += f2_prime[i] * pow(1, i) % ec.n

            alpha23 += f2[i] * pow(3, i) % ec.n
            alpha23_prime += f2_prime[i] * pow(3, i) % ec.n

        # player one verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(1, i), commits2[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, alpha21, ec.G), \
                            pointMultiplyJacobian(ec, alpha21_prime, H)) == RHS, 'player two is cheating'

        # player three verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(3, i), commits2[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, alpha23, ec.G), \
                            pointMultiplyJacobian(ec, alpha23_prime, H)) == RHS, 'player two is cheating'
         
        


        # signer three acting as the dealer
        commits3 = list()
        q3 = int.from_bytes(os.urandom(ec.bytesize), 'big') # secret value
        while q3 == 0:
            q3 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        q3_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')
        while q3_prime == 0:
            q3_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')

        commits3.append(pointAdd(ec, pointMultiplyJacobian(ec, q3, ec.G), \
                                     pointMultiplyJacobian(ec, q3_prime, H)))

        # sharing polynomials
        f3 = list()
        f3.append(q3)
        f3_prime = list()
        f3_prime.append(q3_prime)
        for i in range(1, t):
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f3.append(temp)
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f3_prime.append(temp)
            commits3.append(pointAdd(ec, pointMultiplyJacobian(ec, f3[i], ec.G), \
                                     pointMultiplyJacobian(ec, f3_prime[i], H)))

        # shares of the secret
        alpha31 = 0 # share of q3 belonging to P1
        alpha31_prime = 0
        alpha32 = 0  # share of q3 belonging to P2
        alpha32_prime = 0
        for  i in range(0, t):
            alpha31 += f3[i] * pow(1, i) % ec.n
            alpha31_prime += f3_prime[i] * pow(1, i) % ec.n

            alpha32 += f3[i] * pow(2, i) % ec.n
            alpha32_prime += f3_prime[i] * pow(2, i) % ec.n

        # player one verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(1, i), commits3[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, alpha31, ec.G), \
                            pointMultiplyJacobian(ec, alpha31_prime, H)) == RHS, 'player three is cheating'

        # player two verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(2, i), commits3[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, alpha32, ec.G), \
                            pointMultiplyJacobian(ec, alpha32_prime, H)) == RHS, 'player two is cheating'
         

        # shares of the secret key q = q1 + q2 + q3
        alpha1 = alpha21 + alpha31 % ec.n
        alpha2 = alpha12 + alpha32 % ec.n
        alpha3 = alpha13 + alpha23 % ec.n
        for i in range(0, t):
            alpha1 += f1[i] * pow(1, i) % ec.n
            alpha2 += f2[i] * pow(2, i) % ec.n
            alpha3 += f3[i] * pow(3, i) % ec.n

        # it's time to recover the public key Q = Q1 + Q2 + Q3 = (q1 + q2 + q3)G
        A1 = list()
        A2 = list()
        A3 = list()

        # each participant i = 1, 2, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(0, t):
            A1.append(pointMultiplyJacobian(ec, f1[i], ec.G))
            A2.append(pointMultiplyJacobian(ec, f2[i], ec.G))
            A3.append(pointMultiplyJacobian(ec, f3[i], ec.G))
        
        # he checks the others' values
        # player one
        RHS2 = None
        RHS3 = None
        for i in range(0, t):
            RHS2 = pointAdd(ec, RHS2, pointMultiplyJacobian(ec, pow(1, i), A2[i]))
            RHS3 = pointAdd(ec, RHS3, pointMultiplyJacobian(ec, pow(1, i), A3[i]))
        assert pointMultiplyJacobian(ec, alpha21, ec.G) == RHS2, 'player two is cheating'
        assert pointMultiplyJacobian(ec, alpha31, ec.G) == RHS3, 'player three is cheating'

        # player two
        RHS1 = None
        RHS3 = None
        for i in range(0, t):
            RHS1 = pointAdd(ec, RHS1, pointMultiplyJacobian(ec, pow(2, i), A1[i]))
            RHS3 = pointAdd(ec, RHS3, pointMultiplyJacobian(ec, pow(2, i), A3[i]))
        assert pointMultiplyJacobian(ec, alpha12, ec.G) == RHS1, 'player one is cheating'
        assert pointMultiplyJacobian(ec, alpha32, ec.G) == RHS3, 'player three is cheating'

        # player three
        RHS1 = None
        RHS2 = None
        for i in range(0, t):
            RHS1 = pointAdd(ec, RHS1, pointMultiplyJacobian(ec, pow(3, i), A1[i]))
            RHS2 = pointAdd(ec, RHS2, pointMultiplyJacobian(ec, pow(3, i), A2[i]))
        assert pointMultiplyJacobian(ec, alpha13, ec.G) == RHS1, 'player one is cheating'
        assert pointMultiplyJacobian(ec, alpha23, ec.G) == RHS2, 'player two is cheating'


        A = list() # commitment at the global sharing polynomial
        for i in range(0, t):
            A.append(pointAdd(ec, A1[i], pointAdd(ec, A2[i], A3[i])))
            
        Q = A[0] # aggregated public key



        ### SECOND PHASE: generation of the nonces' pair ###
        # This phase follows exactly the key generation procedure
        # suppose that player one and three want to sign

        # signer one acting as the dealer
        commits1 = list()
        k1 = int.from_bytes(os.urandom(ec.bytesize), 'big') # secret value
        while k1 == 0:
            k1 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        k1_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')
        while k1_prime == 0:
            k1_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')

        commits1.append(pointAdd(ec, pointMultiplyJacobian(ec, k1, ec.G), \
                                     pointMultiplyJacobian(ec, k1_prime, H)))

        # sharing polynomials
        f1 = list()
        f1.append(k1)
        f1_prime = list()
        f1_prime.append(k1_prime)
        for i in range(1, t):
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f1.append(temp)
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f1_prime.append(temp)
            commits1.append(pointAdd(ec, pointMultiplyJacobian(ec, f1[i], ec.G), \
                                     pointMultiplyJacobian(ec, f1_prime[i], H)))

        # shares of the secret
        beta13 = 0  # share of k1 belonging to P3
        beta13_prime = 0
        for  i in range(0, t):
            beta13 += f1[i] * pow(3, i) % ec.n
            beta13_prime += f1_prime[i] * pow(3, i) % ec.n


        # player three verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(3, i), commits1[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, beta13, ec.G), \
                            pointMultiplyJacobian(ec, beta13_prime, H)) == RHS, 'player one is cheating'
         
        

        # signer three acting as the dealer
        commits3 = list()
        k3 = int.from_bytes(os.urandom(ec.bytesize), 'big') # secret value
        while k3 == 0:
            k3 = int.from_bytes(os.urandom(ec.bytesize), 'big')
        k3_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')
        while k3_prime == 0:
            k3_prime = int.from_bytes(os.urandom(ec.bytesize), 'big')

        commits3.append(pointAdd(ec, pointMultiplyJacobian(ec, k3, ec.G), \
                                     pointMultiplyJacobian(ec, k3_prime, H)))

        # sharing polynomials
        f3 = list()
        f3.append(k3)
        f3_prime = list()
        f3_prime.append(k3_prime)
        for i in range(1, t):
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f3.append(temp)
            temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            while temp == 0:
                temp = int.from_bytes(os.urandom(ec.bytesize), 'big')
            f3_prime.append(temp)
            commits3.append(pointAdd(ec, pointMultiplyJacobian(ec, f3[i], ec.G), \
                                     pointMultiplyJacobian(ec, f3_prime[i], H)))

        # shares of the secret
        beta31 = 0 # share of k3 belonging to P1
        beta31_prime = 0
        for  i in range(0, t):
            beta31 += f3[i] * pow(1, i) % ec.n
            beta31_prime += f3_prime[i] * pow(1, i) % ec.n

        # player one verifies consistency of his share
        RHS = None
        for i in range(0, t):
            RHS = pointAdd(ec, RHS, pointMultiplyJacobian(ec, pow(1, i), commits3[i])) 
        assert pointAdd(ec, pointMultiplyJacobian(ec, beta31, ec.G), \
                            pointMultiplyJacobian(ec, beta31_prime, H)) == RHS, 'player three is cheating'

        # shares of the secret nonce
        beta1 =  beta31 % ec.n
        beta3 = beta13 % ec.n
        for i in range(0, t):
            beta1 += f1[i] * pow(1, i) % ec.n
            beta3 += f3[i] * pow(3, i) % ec.n

        # it's time to recover the public nonce
        B1 = list()
        B3 = list()

        # each participant i = 1, 3 shares Qi as follows

        # he broadcasts these values
        for i in range(0, t):
            B1.append(pointMultiplyJacobian(ec, f1[i], ec.G))
            B3.append(pointMultiplyJacobian(ec, f3[i], ec.G))

        
        # he checks the others' values
        # player one
        RHS3 = None
        for i in range(0, t):
            RHS3 = pointAdd(ec, RHS3, pointMultiplyJacobian(ec, pow(1, i), B3[i]))
        assert pointMultiplyJacobian(ec, beta31, ec.G) == RHS3, 'player three is cheating'

        # player three
        RHS1 = None
        for i in range(0, t):
            RHS1 = pointAdd(ec, RHS1, pointMultiplyJacobian(ec, pow(3, i), B1[i]))
        assert pointMultiplyJacobian(ec, beta13, ec.G) == RHS1, 'player one is cheating'

        B = list() # commitment at the global sharing polynomial
        for i in range(0, t):
            B.append(pointAdd(ec, B1[i], B3[i]))

        K = B[0] # aggregated public nonce
        if ec.jacobi(K[1]) != 1:
            beta1 = ec.n - beta1
            beta3 = ec.n - beta3

        

        ### PHASE THREE: signature generation ###
        
        # partial signatures
        e = int_from_hash(sha256(K[0].to_bytes(32, byteorder="big") + bytes_from_Point(ec, Q, True) + msg).digest(), ec.n)
        gamma1 = beta1 + e * alpha1 % ec.n
        gamma3 = beta3 + e * alpha3 % ec.n

        # each participant verifies the other partial signatures

        # player one
        if ec.jacobi(K[1]) == 1:
            RHS3 = pointAdd(ec, K, pointMultiplyJacobian(ec, e, Q))
            for i in range(1, t):
                RHS3 = pointAdd(ec, RHS3, pointAdd(ec, pointMultiplyJacobian(ec, \
                        pow(3, i), B[i]), pointMultiplyJacobian(ec, e * pow(3, i), A[i])))
        else:
            assert ec.jacobi(K[1]) != 1
            RHS3 = pointAdd(ec, opposite(ec, K), pointMultiplyJacobian(ec, e, Q))
            for i in range(1, t):
                RHS3 = pointAdd(ec, RHS3, pointAdd(ec, pointMultiplyJacobian(ec, \
                        pow(3, i), opposite(ec, B[i])), pointMultiplyJacobian(ec, e * pow(3, i), A[i])))

        assert pointMultiplyJacobian(ec, gamma3, ec.G) == RHS3, 'player three is cheating'


        # player three
        if ec.jacobi(K[1]) == 1:
            RHS1 = pointAdd(ec, K, pointMultiplyJacobian(ec, e, Q))
            for i in range(1, t):
                RHS1 = pointAdd(ec, RHS1, pointAdd(ec, pointMultiplyJacobian(ec, \
                        pow(1, i), B[i]), pointMultiplyJacobian(ec, e * pow(1, i), A[i])))
        else:
            assert ec.jacobi(K[1]) != 1
            RHS1 = pointAdd(ec, opposite(ec, K), pointMultiplyJacobian(ec, e, Q))
            for i in range(1, t):
                RHS1 = pointAdd(ec, RHS1, pointAdd(ec, pointMultiplyJacobian(ec, \
                        pow(1, i), opposite(ec, B[i])), pointMultiplyJacobian(ec, e * pow(1, i), A[i])))

        assert pointMultiplyJacobian(ec, gamma1, ec.G) == RHS1, 'player two is cheating'


        ### PHASE FOUR: aggregating the signature ###
        omega1 = 3 * mod_inv(3 - 1, ec.n)
        omega3 = 1 * mod_inv(1 - 3, ec.n)
        sigma = (gamma1 * omega1 + gamma3 * omega3) % ec.n

        ecssa = (K[0], sigma)

        self.assertTrue(ecssa_verify(msg, ecssa, Q))