from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class HopLimitDecrementTestCase(ComplianceTestCase):
    """
    Hop Limit Decrement - Intermediate Node (Routers Only)

    Verifies that a router correctly processes the Hop Limit field of received
    packets and generates a valid value in transmitted packets

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.9)
    """

    def run(self):
        self.logger.info("Sending ICMP echo request, with a hop limit of 15.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()), hlim=15)/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a reply...")
        r1 = self.node(4).received(src=self.node(1).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))

        assertEqual(14, r1[0].getlayer(IPv6).hlim, "expected the ICMPv6 Echo Request to have a hop limit of 14, got %d" % (r1[0].getlayer(IPv6).hlim))
        