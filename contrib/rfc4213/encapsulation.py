from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class EncapsulationHelper(ComplianceTestCase):

    def send_request(self):
        self.logger.info("Sending ICMPv6 Echo Request through IPv6-IPv4 tunnel.")
        self.node(1).send( \
            IP(src=str(self.node(1).ip(type="v4")), dst=str(self.target(1).ip(type="v4")))/
                IPv6(src=str(self.node(1).ip(type="6in4")), dst=str(self.target(1).ip(type="6in4")))/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        return self.node(1).received(src=self.target(1).ip(type="v4"), seq=self.seq(), type=ICMPv6EchoReply)


class IPv4HeaderAddedTestCase(EncapsulationHelper):
    """
    Encapsulation - IPv4 Header Added
    
    Verifies that a node performing encapsulation takes an IPv6 header and
    encapsulates it with an IPv4 header.
    
    @private
    Source:       RFC 4213 Page 7 Paragraph 1
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertHasLayer(IPv6, r1[0], "expected the Echo Reply to include an IPv6 header")


class CorrectVersionFieldTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct Version Field Set
    
    Verifies that a node performing encapsulation sets the correct IP version
    on the encapsulating IPv4 header.
    
    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """

    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(4, r1[0].getlayer(IP).version, "expected the IPv4 header to have the correct version")


class CorrectLengthFieldTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct Length Field Set
    
    Verifies that a node performing encapsulation sets the correct length on
    the encapsulating IPv4 header.
    
    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(len(r1[0]), r1[0].len)


class CorrectProtocolFieldTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct Protocol Field Set
    
    Verifies that a node performing encapsulation sets the correct protocol on
    the encapsulating IPv4 header.
    
    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(41, r1[0].proto, "expected the IPv4 header to have protocol of 41")


class CorrectIPv4SourceAddressTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct IPv4 Source Address
    
    Verifies that a node performing encapsulation sets the IPv4 source address
    on the encapsulating IPv4 header.
    
    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(self.target(1).ip(type="v4"), r1[0].getlayer(IP).src, "expected the IPv4 header to have source address of %s" % self.target(1).ip(type="v4"))


class CorrectIPv4DestinationAddressTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct IPv4 Destination Address
    
    Verifies that a node performing encapsulation sets the IPv4 destination
    address on the encapsulating IPv4 header.
    
    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(self.node(1).ip(type="v4"), r1[0].getlayer(IP).dst, "expected the IPv4 header to have destination address of %s" % self.node(1).ip(type="v4"))


class CorrectIPv6SourceAddressTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct IPv6 Source Address
    
    Verifies that a node performing encapsulation sets the IPv6 source address
    on the encapsulated IPv6 header.

    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(self.target(1).ip(type="6in4"), r1[0].getlayer(IPv6).src, "expected the IPv6 header to have source address of %s" % self.target(1).ip(type="tunnel"))


class CorrectIPv6DestinationAddressTestCase(EncapsulationHelper):
    """
    Encapsulation - Correct IPv6 Destination Address
    
    Verifies that a node performing encapsulation sets the IPv6 destination
    address on the encapsulated IPv6 header.
    
    @private
    Source:         RFC 4213 Page 12 Paragraph 2
    """
    
    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")
            
        r1 = self.send_request()
        
        assertEqual(1, len(r1), "expected to receive an Echo Reply")
        
        assertHasLayer(IP, r1[0], "expected the Echo Reply to include an IPv4 header")
        assertEqual(self.node(1).ip(type="6in4"), r1[0].getlayer(IPv6).dst, "expected the IPv6 header to have destination address of %s" % self.node(1).ip(type="tunnel"))
        