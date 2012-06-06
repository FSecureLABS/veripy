from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ErroneousHeaderFieldTestCase(ComplianceTestCase):
    """
    Erroneous Header Field (Parameter Problem Generation)
    
    Verify that a node generates valid ICMPv6 Param Problem Messages

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.6)
    """

    def run(self):
        self.logger.info("Sending erroneous packet to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                IPv6ExtHdrFragment(m=1)/
                    ICMPv6EchoRequest(seq=self.next_seq())/("\0"*5))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMP Parameter Problem")
        
        self.logger.info("Checking code is correct")
        assertEqual(0, r1[0].getlayer(ICMPv6ParamProblem).code, "Expecting code to equal 0")
        
        self.logger.info("Checking pointer is correct")
        assertEqual(4, r1[0].getlayer(ICMPv6ParamProblem).ptr, "Expecting pointer to equal 4")
        
        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r1[0]), "Expecting MTU of received packet not to exceed 1280")
        