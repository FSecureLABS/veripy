from veripy.models import ComplianceTestCase
from veripy.assertions import *
from scapy.all import *
import hashlib
import time
import veripy_crypto

class SendHelper(ComplianceTestCase):

    def construct_valid_sign_ns(self):

        ns_pket = ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
        ns_pket = self.add_send_options(ns_pket)
        
        packet_to_send = self.sign(self.ipv6_layer/ns_pket, ICMPv6ND_NS)
        return packet_to_send

    def add_send_options(self, packet):
        return packet/self.cga_opt/ICMPv6NDOptNO(nonce=chr(random.randint(0,255))*6, len=1)/ICMPv6NDOptTS(timestamp=time.time())

    def string_to_sign(self, packet, ndp_type):
        # Take a copy of the packet
        pkt = packet.copy()
        sig = pkt[ICMPv6NDOptRSA]
        ts = sig.underlayer

        # Remove the exisiting signature
        ts.payload = None
        sig.underlayer = None

        # Clear the Check sum and length values
        pkt[ndp_type].cksum = None
        pkt[IPv6].plen = None

        ndp_message = pkt[ndp_type]

        # Now, let's build the string that will be signed
        s = self.send_message_type_tag + \
            socket.inet_pton(socket.AF_INET6, pkt[IPv6].src) + \
            socket.inet_pton(socket.AF_INET6, pkt[IPv6].dst) + \
            ndp_message.build()

        return s

    def sign(self, packet, ndp_type):
        string_to_sign = self.string_to_sign(packet/ICMPv6NDOptRSA(), ndp_type)

        signature = veripy_crypto.sign(self.private_key, string_to_sign)

        return packet/ICMPv6NDOptRSA(signature=signature, hash=self.key_hash)

    def verify_signature(self, pkt, ndp_type):
        
        # Construct key from packet
        pub_key_string = veripy_crypto.convert_der_encoded_to_pem(pkt.pub_key)

        public_key = veripy_crypto.load_public_key(pub_key_string)
        
        # Signature length is length of modulus in bytes rest is padding
        # get_modulus returns string so /2 for bytes
        return veripy_crypto.verify_signature(public_key, self.string_to_sign(pkt, ndp_type), pkt.signature[:len(public_key.get_modulus())/2])


    def set_up(self):
        self.cga_ip = "fe80::2450:b04b:a209:1a26"
        self.ipv6_layer = IPv6(src=self.cga_ip, dst=str(self.target(1).link_local_ip()))
        self.send_message_type_tag = "\x08\x6F\xCA\x5E\x10\xB2\x00\xC9\x9C\x8C\xE0\x01\x64\x27\x7C\x08"
        self.modifier = "ef1add5592f601ceff72dd433fe1505c".decode('hex')
        self.subnet_prefix = "fe80::"

        self.public_key = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLDKRFdJeGAsVl4nHRbz+Bz3kb
aH6idRs9M/OhWAmac/17KGSEIYQcqvfWn7ctiLXVnvqOy4v9OG3ofBAI1k+CNaIB
kZPlza/oEmlDmWw9vrvns6wWGislq4m+0fqo0G5J/GzlK+u4QdbTJUfXZf+chiT3
Vj0pz35ITrW28tev/wIDAQAB
-----END PUBLIC KEY-----
"""
        pubkey = veripy_crypto.load_public_key(self.public_key)
        self.public_key_der = pubkey.as_der()
        
        self.key_hash = hashlib.sha1(self.public_key_der).digest()[:16]

        self.private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDLDKRFdJeGAsVl4nHRbz+Bz3kbaH6idRs9M/OhWAmac/17KGSE
IYQcqvfWn7ctiLXVnvqOy4v9OG3ofBAI1k+CNaIBkZPlza/oEmlDmWw9vrvns6wW
Gislq4m+0fqo0G5J/GzlK+u4QdbTJUfXZf+chiT3Vj0pz35ITrW28tev/wIDAQAB
AoGAOvGrimIjTorlZQNMiUDjTbq97H/0KxMV2jmHozHcb9L2Jdd+/oCASpYzJkHt
OjGyn5XsJKHgPJ0yAshpGzejkqNHgI7vvfOgP+BPdmrA4qBRnwa46VVBEOIvQHrd
yVRmQDQ2PW0LQohlRBTVe6xpF28xqYWrpIrqItWbvAnxPjkCQQDRalRyPtr1prH/
Q+dEOBr2Y3fvY2tqfhbQdIlJx6wlmdJVNYinr3HIEKayW2Tyy1HxN7sy2gEBLGP2
nmkVJio7AkEA+DfJPU7eGQoDB1qcEiYAgendOfvwpEKNVrAJwhVM6pAoH0O4Bt7N
Y9SC44dz/7b6VwOyXxbccv+crlYRThLxDQJAAJqa5b1yqjSx3LeYaiTzRvSgeutB
ewwkCrPbVYAi6fTYm3BNFZa28EnEAU2sK9sUQGrVul7Qk+1J2IM6cFos0wJBAILz
c3CrvhJ5rLVhgTs130iqp7Lijscp8UUNpGhHMogBO5ma8Wh2fOcxA0ikencrApGL
erwd5HmrDu8OqxyEc7UCQGzzIi76o+/WD5EfCIGAzOJfH6igT8YJQRqGMuMjr6dF
tfNxExZWXkWW/Ife+QfqXO2x/3/4YCpcy3X7VwTvKBM=
-----END RSA PRIVATE KEY-----
"""

        self.cga_opt = ICMPv6NDOptCGA(modifier=self.modifier, pub_key=self.public_key_der, mask=self.subnet_prefix)

        # Currently Scapy doesn't handle this. All fields other than pub key total 29
        self.cga_opt.pad_len = 8-(len(self.cga_opt.pub_key)+29)%8
        self.cga_opt.padding = '\x00'*self.cga_opt.pad_len
        self.cga_opt.len = (len(self.public_key_der) + self.cga_opt.pad_len + 29)/8


class ValidSendHelper(SendHelper):

    def run(self):
        self.node(1).send(self.packet_to_send)

        # Get the UUT to respond with an NA
        na_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.cga_ip, type=ICMPv6ND_NA)

        self.logger.info("Checking for Neighbor Advertisement in reply")
        assertGreaterThanOrEqualTo(1, len(na_packets), "Expect Neighbor solicitation to be received" )

        self.logger.info("Checking for CGA Option in reply")
        assertHasLayer(ICMPv6NDOptCGA, na_packets[0], "Expected CGA Option")

        self.logger.info("Checking for RSA Option in reply")
        assertHasLayer(ICMPv6NDOptRSA, na_packets[0], "Expected RSA Option")

        self.logger.info("Checking for NONCE Option in reply")
        assertHasLayer(ICMPv6NDOptNO, na_packets[0], "Expected Nonce Option")

        self.logger.info("Check NONCE is same as in solicitation")
        assertEqual(self.packet_to_send[ICMPv6NDOptNO].nonce, na_packets[0][ICMPv6NDOptNO].nonce, "Expected Nonce to be same in advertisement")

class InvalidSendButCanContinueHelper(SendHelper):

    def run(self):
        self.node(1).send(self.packet_to_send)

        # Get the UUT to respond with an NA
        na_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.cga_ip, type=ICMPv6ND_NA)

        # The UUT may reply but treating in unsecured or not reply at all
        if(len(na_packets) >= 1):
            self.logger.info("UUT replied check for no nonce")
            assertNotHasLayer(ICMPv6NDOptNO, na_packets[0], "Not Expecting Nonce Option")
        else:
            # Doesn't respond to non-send check for no reply
            self.logger.info("Checking for no Neighbor Advertisement in reply")
            assertEqual(0, len(na_packets), "Not expecting Neighbor Advertisement to be received" )



  
