from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class NextHeaderZeroTestCase(ComplianceTestCase):
    """
    Next Header Zero
    
    Verify that a node discards a packet that has a Next Header field of zero
    in a header other than an IPv6 header and generates an ICMPv6 Parameter
    Problem message to the source of the packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.1)
    """
    
    def run(self):
        self.logger.info("Sending an ICMP Echo Request with a Hop-by-Hop header that has a Next Header field of 0.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=0, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    IPv6ExtHdrHopByHop(nh=58, len=0, options=[PadN(otype='PadN', optlen=4)])/
                        ICMPv6EchoRequest(seq=self.seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem message")
        
        assertEqual(1, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem to have a Code Field of 1")
        assertEqual(40, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem to have a Pointer Field of 0x28")
        