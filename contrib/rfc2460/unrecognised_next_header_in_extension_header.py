from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UnrecognisedNextHeaderInExtensionHeaderTestCase(ComplianceTestCase):
    """
    Unrecognised Next Header In Extension Header
    
    Verify that a node discards a packet with an unrecognized or unexpected
    next header in an extension header and transmits an ICMPv6 Parameter
    Problem message to the source of the packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.3a)
    """
    
    NextHeaderUnassignedValues = range(143,253)
    
    def run(self):
        for nh in UnrecognisedNextHeaderInExtensionHeaderTestCase.NextHeaderUnassignedValues:
            self.node(1).clear_received()

            self.logger.info("Sending an IPv6 packet header with Next Header of %d", nh)
            self.node(1).send( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=60)/
                    IPv6ExtHdrDestOpt(nh=nh, len=0, options=[PadN(otype='PadN', optlen=4)]))
            
            self.logger.info("Checking for a reply...")
            r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

            assertEqual(1, len(r1), "expected to receive an ICMPv6 Paramter Problem message")
            assertEqual(1, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 1")
            assertEqual(40, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 40")
            
            self.logger.info("Sending an ICMPv6 Echo Request.")
            self.node(1).send( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()))
            
            self.logger.info("Checking for a reply...")
            r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

            assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply message")

class UnexpectedNextHeaderInExtensionHeaderTestCase(ComplianceTestCase):
    """
    Unrecognised Next Header In Extension Header
    
    Verify that a node discards a packet with an unrecognized or unexpected
    next header in an extension header and transmits an ICMPv6 Parameter
    Problem message to the source of the packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.3b)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a destination options header and fragment extension header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=60)/
                IPv6ExtHdrDestOpt(nh=60, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    IPv6ExtHdrFragment(nh=58, res1=0, offset=4320, res2=2, m=0)/
                        ICMPv6EchoRequest())

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Paramter Problem message")
	assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 2")
	assertEqual(50, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 50")
