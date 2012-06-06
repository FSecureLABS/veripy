from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UnrecognisedNextHeaderInIPv6HeaderTestCase(ComplianceTestCase):
    """
    Unrecognised Next Header in IPv6 Header
    
    Verifies that a node generates the appropriate response to an unrecognized
    or unexpected Next Header field.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.7a)
    """
    
    NextHeaderUnassignedValues = range(143,253)
    
    def run(self):
        for nh in UnrecognisedNextHeaderInIPv6HeaderTestCase.NextHeaderUnassignedValues:
            self.node(1).clear_received()

            self.logger.info("Trial with Next Header of %d", nh)
            
            self.logger.info("Sending an IPv6 packet with an invalid Next Header of %d", nh)
            self.node(1).send(IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=nh))
            
            self.logger.info("Checking for a reply...")
            r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
            
            assertEqual(1, len(r1), "expected to receive an ICMP Parameter Problem")
            assertEqual(1, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem to have a Code Field of 1")
            assertEqual(6, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem to have a Pointer Field of 0x06")
            
            self.logger.info("Sending a valid ICMP Echo Request.")
            self.node(1).send( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()))
            
            self.logger.info("Checking for a reply...")
            r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

            assertEqual(1, len(r1), "expected to receive an ICMP Echo Reply")

class UnexpectedNextHeaderInIPv6HeaderTestCase(ComplianceTestCase):
    """
    Unexpected Next Header in IPv6 Header
    
    Verifies that a node generates the appropriate response to an unrecognized
    or unexpected Next Header field.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.7b)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet with an Next Header of 0, but with a fragment header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrFragment(nh=0, offset=0, m=0, id=135)/
                    ICMPv6EchoRequest())
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        
        assertEqual(1, len(r1), "expected to receive an ICMP Parameter Problem")
        assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem message to have a Code Field of 2")
        assertEqual(46, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem message to have a Pointer Field set to 0x2e")
