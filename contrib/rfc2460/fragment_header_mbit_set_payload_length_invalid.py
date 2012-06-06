from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class FragmentHeaderMBitSetPayloadLengthInvalidTestCase(ComplianceTestCase):
    """
    Fragment Header M-Bit Set, Payload Length Invalid
    
    Verify that a node takes the proper actions when it receives a
    fragment with the M-bit set (more fragments), but which has a
    Payload Length that is not a multiple of 8 bytes.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.3.3)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with an invalid payload length and fragment header More Fragments flag set.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), plen=21)/
                IPv6ExtHdrFragment(m=1)/ICMPv6EchoRequest(seq=self.next_seq())/("\0"*5))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")
        assertEqual(0, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem with a Code Field of 0")
        assertEqual(4, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem with a Pointer Field of 4")
