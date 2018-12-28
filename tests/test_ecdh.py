#!/usr/bin/env python3

import unittest
from btclib.ellipticcurves import secp160r1, to_Point, pointMultiply, \
    bytes_from_Point
from btclib.ecdh import ecdh, key_setup, key_agreement_operation, \
    key_derivation_function
from btclib.ecsignutils import int2octets

# source: http://read.pudn.com/downloads168/doc/772358/TestVectorsforSEC%201-gec2.pdf
# test vectors taken from the guidelines for efficient cryptography - GEC 2: test vectors for SEC 1


class TestEcdh(unittest.TestCase):
    def test_ecdh_naif(self):
        ec = secp160r1
        G = ec.G
        prv_sender = 0x1
        prv_recv = 0x2
        prv_alternative = prv_sender * prv_recv
        pub_sender = to_Point(ec, pointMultiply(ec, prv_sender, G))
        pub_recv = to_Point(ec, pointMultiply(ec, prv_recv, G))
        shared_sender = ecdh(ec, prv_recv, pub_sender)
        shared_recv = ecdh(ec, prv_sender, pub_recv)
        shared_alternative = ecdh(ec, prv_alternative, G)
        self.assertEqual(shared_sender, shared_recv)
        self.assertEqual(shared_alternative, shared_sender)
        key_data_len = 20
        hash_digest_size = 20
        keying_data_sender = key_agreement_operation(
            ec, key_data_len, prv_sender, pub_recv, hash_digest_size)
        keying_data_recv = key_agreement_operation(
            ec, key_data_len, prv_recv, pub_sender, hash_digest_size)
        self.assertEqual(keying_data_sender, keying_data_recv)

    def test_key_deployment(self):
        ec = secp160r1
        G = ec.G
        hash_digest_size = 20
        prv_sender = 971761939728640320549601132085879836204587084162
        prv_octet_string = int2octets(prv_sender, ec.bytesize)  # FIXME
        prv_octet_string_unpad = prv_octet_string[len(
            prv_octet_string)-hash_digest_size:]
        self.assertEqual(prv_octet_string_unpad.hex(),
                         'aa374ffc3ce144e6b073307972cb6d57b2a4e982')
        pub_sender = pointMultiply(ec, prv_sender, G)
        self.assertEqual(
            pub_sender[0], 466448783855397898016055842232266600516272889280)
        self.assertEqual(
            pub_sender[1], 1110706324081757720403272427311003102474457754220)
        self.assertEqual(bytes_from_Point(ec, pub_sender, True).hex(
        ), '0251b4496fecc406ed0e75a24a3c03206251419dc0')

        prv_recv = 399525573676508631577122671218044116107572676710
        prv_octet_string = int2octets(prv_recv, ec.bytesize)  # FIXME
        prv_octet_string_unpad = prv_octet_string[len(
            prv_octet_string)-hash_digest_size:]
        self.assertEqual(prv_octet_string_unpad.hex(),
                         '45fb58a92a17ad4b15101c66e74f277e2b460866')
        pub_recv = pointMultiply(ec, prv_recv, G)
        self.assertEqual(
            pub_recv[0], 420773078745784176406965940076771545932416607676)
        self.assertEqual(
            pub_recv[1], 221937774842090227911893783570676792435918278531)
        self.assertEqual(bytes_from_Point(ec, pub_recv, True).hex(),
                         '0349b41e0e9c0369c2328739d90f63d56707c6e5bc')

    def test_key_agreement_operation(self):
        ec = secp160r1
        key_data_len = 20
        hash_digest_size = 20
        prv_sender = 971761939728640320549601132085879836204587084162
        pub_recv = (420773078745784176406965940076771545932416607676,
                    221937774842090227911893783570676792435918278531)
        shared_sender = ecdh(ec, prv_sender, pub_recv)
        self.assertEqual(
            shared_sender, 1155982782519895915997745984453282631351432623114)
        octet_shared_sender = int2octets(shared_sender, ec.bytesize)  # FIXME
        octet_shared_sender_unpad = octet_shared_sender[len(
            octet_shared_sender)-hash_digest_size:]
        self.assertEqual(octet_shared_sender_unpad.hex(),
                         'ca7c0f8c3ffa87a96e1b74ac8e6af594347bb40a')
        keying_data = key_derivation_function(
            ec, octet_shared_sender_unpad, key_data_len, hash_digest_size)
        self.assertEqual(keying_data.hex(),
                         '744ab703f5bc082e59185f6d049d2d367db245c2')

        prv_recv = 399525573676508631577122671218044116107572676710
        pub_sender = (466448783855397898016055842232266600516272889280,
                      1110706324081757720403272427311003102474457754220)
        shared_recv = ecdh(ec, prv_recv, pub_sender)
        self.assertEqual(
            shared_recv, 1155982782519895915997745984453282631351432623114)
        octet_shared_recv = int2octets(shared_recv, ec.bytesize)  # FIXME
        octet_shared_recv_unpad = octet_shared_recv[len(
            octet_shared_recv)-hash_digest_size:]
        self.assertEqual(octet_shared_recv_unpad.hex(),
                         'ca7c0f8c3ffa87a96e1b74ac8e6af594347bb40a')
        keying_data = key_derivation_function(
            ec, octet_shared_recv_unpad, key_data_len, hash_digest_size)
        self.assertEqual(keying_data.hex(),
                         '744ab703f5bc082e59185f6d049d2d367db245c2')


if __name__ == "__main__":
    # execute only if run as a script
    unittest.main()
