from veripy.assertions import assertEqual
from veripy.models.ip_address import IPAddress
from veripy.assertions import assertTrue
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase, IPAddress
from libs.ipcalc import Network
import hashlib


class VerifyCGAGenerationTestCase(ComplianceTestCase):
    """
    CGA Generation

    Verifies that the UUT generates a CGA packet with a valid source address
    and CGA options.

    @private
    Source:         RFC4861 2,4,5
    Problems:       This test verifies CGA through SEND. If another protocol
                    is using CGA and SEND is not configured, it may report false
                    failure.
    """

    def run(self):
        # This relies on SEND - Ping it so it sends an NS
        self.logger.info("Sending an ICMPv6 Echo Request to the UUT, to trigger a Secure Neighbor Solicitation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a signed CGA packet...")
        cga_packets = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6NDOptCGA, timeout=120)
        assertGreaterThanOrEqualTo(1, len(cga_packets), "expect to receive one-or-more CGA packets")

        self.logger.info("Receive a CGA packet. Verifying it:")
        cga_layer = cga_packets[0][ICMPv6NDOptCGA]
        
        self.logger.info("Checking Collision count is in range...")
        assertTrue(cga_layer.collision in [0,1,2], "expected Collision Count to be 0, 1 or 2")
        
        iface_identifier = inet_pton(socket.AF_INET6, IPAddress.identify(cga_packets[0].src).ip)[8:]
        prefix           = IPAddress.identify(cga_packets[0].src).network()
        # check the CGA subnet prefix(mask) is equal to the subnet prefix
        self.logger.info("Checking the Subnet Prefix Mask...")
        assertEqual(str(Network(cga_layer.mask)), prefix, "expected the CGA Prefix to match the Address Prefix")

        self.logger.info("Checking Hash One...")
        hash1 = self.hash_one(cga_layer)
        mask1 = '\x1c\xff\xff\xff\xff\xff\xff\xff' # RFC3972, Section 2
        # Hash1 & Mask1 == Interface Identifier & Mask1, last 7 octets should match exactly
        assertEqual(self.and_byte_strings(hash1, mask1), self.and_byte_strings(iface_identifier, mask1), "expected hash1 to match the interface identifier")
        assertEqual(hash1[7:], iface_identifier[7:], "expected hash1 to match the interface identifier")

        self.logger.info("Checking Hash Two...")
        hash2 = self.hash_two(cga_layer)
        sec = (ord(iface_identifier[0]) >> 5) & 0x07
        mask2 = '\xff\xff'*sec + '\x00\x00'*(7-sec) # 112bit mask as in RFC 3972, Section 2
        # Hash2 & Mask2  ==  0x0000000000000000000000000000
        assertEqual(self.and_byte_strings(hash2, mask2), '\x00\x00'*7, "expected hash2 & mask2 to be zero")
        
        
    def and_byte_strings(self, string1, string2):
        res = ''
        for a,b in zip(string1,string2):
            res += chr(ord(a) & ord(b))
        return res

    def hash_one(self, cga_layer):
        # hash 1 is a sha1 of the cga params datastructure
        return hashlib.sha1(cga_layer.modifier + \
                            "fe80000000000000".decode('hex') + \
                            chr(cga_layer.collision) + \
                            cga_layer.pub_key + \
                            cga_layer.ext.decode('hex')).digest()[:8]

    def hash_two(self, cga_layer):
        return hashlib.sha1(cga_layer.modifier + \
                            '\x00'*9 + \
                            cga_layer.pub_key + \
                            cga_layer.ext.decode('hex')).digest()[:14]
                            