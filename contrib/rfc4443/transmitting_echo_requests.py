from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class TransmittingEchoRequestsTestCase(ComplianceTestCase):
    """
    Transmitting Echo Requests

    Verify that a node properly transmits ICMPv6 Echo Requests.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.1
    """

    def run(self):
        assertFalse(self.ui.ask("Is the NUT passive?", True), "NUT is passive")
        
        self.ui.tell("Send an ICMPv6 Echo Request from the NUT to %s" % (self.node(1).link_local_ip()))
        assertTrue(self.ui.ask("Once done, please press Y."), "Unable to complete test due to user not sending ping")
        self.logger.info("User sent ping and pressed Y")

        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6EchoRequest)
        
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Request")
        
        assertEqual(self.node(1).link_local_ip(), r1[0].getlayer(IPv6).dst, "expected dst to be NUT's link local address")
        
        assertEqual(128, r1[0].getlayer(ICMPv6EchoRequest).type, "expecting ICMPv6 Echo Request type = 128")
        assertEqual(0, r1[0].getlayer(ICMPv6EchoRequest).code, "expected ICMPv6 Echo Request code = 0")
        self.logger.info("Check packet has valid checksum")
        p1 = IPv6(r1[0].build())
        p1.getlayer(ICMPv6EchoRequest).cksum = None
        p1 = IPv6(p1.build())

        assertEqual(p1.getlayer(ICMPv6EchoRequest).cksum, r1[0].getlayer(ICMPv6EchoRequest).cksum, "expected the Echo Reply to have a valid checksum")
        