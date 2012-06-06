from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class AnycastTestCase(ComplianceTestCase):
    """
    Neighbor Solicitation Processing, Anycast

    Verify that a router properly processes a Neighbor Solicitation for an
    anycast address.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.1.14)
    """

    disabled_nd = True
    disabled_ra = True
    restart_uut = True

    def run(self):
        self.logger.info("Sending a Neighbor Solicitation to the Subnet-Router anycast address...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/
                ICMPv6ND_NS(tgt=str(self.link(2).v6_prefix)))

        self.logger.info("Checking for Neighbor Advertisements...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6ND_NA)

        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive one-or-more Neighbor Advertisements")

        for p in r1:
            assertEqual(self.target(1).ll_addr(), p[ICMPv6ND_NA].tgt, "expected the Target to be the UUT")
            assertEqual(False, p[ICMPv6ND_NA].O, "expected the NA Override flag to be False")
            