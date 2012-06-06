from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RespondsToNUDProbeTestCase(ComplianceTestCase):
    """
    Responds to NUD Probe
    
    Verifies that a node performing encapsulation responds to a NUD probe
    attempt.
    
    @private
    Source:         RFC 4213 Page 17 Paragraph 2
    """

    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")
            
        self.logger.info("Sending ICMPv6 Neighbor Solicitation through IPv6-IPv4 tunnel.")
        self.node(1).send( \
            IP(src=str(self.node(1).ip(type="v4")), dst=str(self.target(1).ip(type="v4")))/
                IPv6(src=str(self.node(1).ip(type="6in4")), dst=str(self.target(1).ip(type="6in4")))/ \
                    ICMPv6ND_NS(tgt=str(self.target(1).ip(type="6in4"))))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).ip(type="v4"), type=ICMPv6ND_NA)
        
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Neighbor Advertisement")
        
        assertHasLayer(IP, r1[0])
        assertHasLayer(IPv6, r1[0])
