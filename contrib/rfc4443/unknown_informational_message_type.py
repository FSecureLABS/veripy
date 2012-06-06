from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UnknownInformationalMessageTypeTestCase(ComplianceTestCase):
    """
    Unknown Informational Message Type
    Send to NUT
    
    Verify that a node discards packets with unknown informational message type

    @private
    Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core
                      Test v6LC.5.1.8: Unknown Informational Message Type

    """
    
    def run(self):
        self.logger.info("Sending erroneous packet to NUT")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6Unknown(type=254))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Echo Reply")