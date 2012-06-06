from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class StubFragmentHeaderTestCase(ComplianceTestCase):
    """
    Stub Fragment Header
    
    Verify that a node accepts the offset zero fragment with the More
    Fragments flag clear.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.4)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with an offset zero fragment and cleared More Fragments flag.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=44)/
                IPv6ExtHdrFragment(offset=0, m=0, nh=58)/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")
        assertNotHasLayer(IPv6ExtHdrFragment, r1[0], "did not expect the Echo Reply to contain a fragment header")
        