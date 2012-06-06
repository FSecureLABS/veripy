from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class HopLimitZeroTestCase(ComplianceTestCase):
    """
    Hop Limit Zero - End Node
    
    Verifies that a node correctly processes the Hop Limit field of received
    packets and generates a valid value in transmitted packets.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.8)
    """
    
    def run(self):
        self.logger.info("Send an ICMP Echo Request with a Hop Limit of 0.")
        self.node(1).send(IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), hlim=0, nh=58)/ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")
        assertGreaterThan(0, r1[0].hlim, "expected the ICMPv6 Echo Reply to have a Hop Limit greater than 0")
