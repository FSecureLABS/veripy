from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class RouterSolicitationsTestCase(ComplianceTestCase):
    """
    Router Solicitations

    Verify that a host sends valid Router Solicitations at the appropriate time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.2.1)
    """

    disabled_nd = True
    disabled_ra = True

    def run(self):
        self.ui.ask("Please restart the UUT's interface, and then press Y.")

        self.ui.wait(30)
        self.logger.info("Waiting for a Router Solicitation...")
        r1 = self.router(1).received(iface=1, dst="ff02::2", type=ICMPv6ND_RS)

        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to send at least one Router Solicitation")
        assertLessThanOrEqualTo(MAX_RTR_SOLICITATIONS, len(r1), "expected the UUT to send no more than MAX_RTR_SOLICITATIONS Router Solicitations")

        for p in r1:
            assertTrue(self.target(1).link_local_ip() == p[IPv6].src or "::" == p[IPv6].src, "expected the Router Solicitations to originate from the UUT's link local address or ::")
            if p[IPv6].src == "::":
                assertNotHasLayer(ICMPv6NDOptSrcLLAddr, p, "did not expect a RS sent from :: to contain a Source Link-Layer Address option")

        for i in range(0, len(r1)-2):
            assertGreaterThanOrEqualTo(RTR_SOLICITATION_INTERVAL * 0.8, r1[i+1].time - r1[i].time)
            assertLessThanOrEqualTo(RTR_SOLICITATION_INTERVAL * 1.2, r1[i+1].time - r1[i].time)
            