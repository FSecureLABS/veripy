from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UnrecognizedNextHeaderTestCase(ComplianceTestCase):
    """
    Unrecognized Next Header (Parameter Problem Generation)
    
    Verify that a node properly generates Parameter Problem Messages when
    an Unrecognized Next Header type is encountered.

    @private
    Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core
                      Test v6LC.5.1.7
    """

    def run(self):
        self.logger.info("Sending erroneous packet to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                IPv6ExtHdrDestOpt(nh=252)/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Echo Reply")

        self.logger.info("Checking for reply")
        r2 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r2), "expected to receive an ICMPv6 Parameter Problem")

        assertEqual(self.node(1).global_ip(), r2[0].getlayer(IPv6).dst, "expected dst to be TN1's global ip address")
        assertEqual(1, r2[0].getlayer(ICMPv6ParamProblem).code, "expected Parameter Problem code = 1")
        assertEqual(0x0028, r2[0].getlayer(ICMPv6ParamProblem).ptr, "expected Parameter Problem pointer = 0x0028")
        assertLessThan(1281, len(r2[0]), "expected MTU to not exceed 1280")
        