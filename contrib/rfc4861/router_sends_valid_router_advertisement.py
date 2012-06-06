from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase
from constants import *

class RouterAdvertisementTestCase(ComplianceTestCase):
    """
    Router Sends Valid Router Advertisement

    Verify that a router sends valid Router Advertisements.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.2.5)
    """

    disabled_nd = True
    disabled_ra = True

    def run(self):
        self.logger.info("Sending a Router Solicitation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1", hlim=254)/\
                ICMPv6ND_RS(tgt="ff02::1"))

        self.logger.info("Checking for replies...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6ND_RA)

        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to send one-or-more Router Advertisements")

        assertEqual(self.target(1).link_local_ip(), r1[0][IPv6].src, "expected the RA source to be UUT link-local IP")
        assertEqual(255, r1[0][IPv6].hlim, "expected the RA hop limit to be 255")
        assertEqual(0, r1[0][ICMPv6ND_RA].code, "expected the RA ICMP code to be 0")
        