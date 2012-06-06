from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class TrafficClassNonZeroEndNodeTestCase(ComplianceTestCase):
    """
    Traffic Class Non-Zero (End Node)
    
    Verifies that a node properly processes the Traffic Class of received
    packets and generates a valid value in transmitted packet.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.2)
    """
    
    def run(self):
        self.logger.info("Sending ICMP echo request, with Traffic Class of 32.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), tc=32)/
                ICMPv6EchoRequest(seq=self.next_seq()))
            
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply, got %d (seq: %d)" % (len(r1), self.seq()))

        if r1[0].tc > 0:
            self.logger.info("Traffic Class in reply was non-Zero.")

            self.ui.tell("Traffic Class Non-Zero Test Case: the UUT responded with a Non-Zero traffoc class.")
            assertTrue(self.ui.ask("Does the UUT support a specific use of the Traffic Class field?"), "expected to receive an ICMPv6EchoReply with a traffic class of zero")
        else:
            assertTrue(True)


class TrafficClassNonZeroIntermediateNodeTestCase(ComplianceTestCase):
    """
    Traffic Class Non-Zero - Intermediate Node (Routers Only)

    Verifies that a router properly proceses the Traffic Class field of
    received packets and generates a valid value in transmitted packets.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.3)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request, with Traffic Class = 32")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), tc=32)/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to receive a ICMPv6 Echo Request (seq: %d)" % (self.seq()))

        if self.ui.ask("Does the RUT support a specific use of the Traffic Class field?"):
            assertGreaterThan(0, r1[0].getlayer(IPv6).tc)
        else:
            assertEqual(32, r1[0].getlayer(IPv6).tc)
            