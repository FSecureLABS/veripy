from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class RouterSolicitationsHelper(ComplianceTestCase):

    disabled_nd = True
    disabled_ra = True

    def set_up(self):
        raise Exception("override #set_up to set #dst")

    def run(self):
        self.logger.info("Sending a Router Solicitation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.dst))/
                ICMPv6ND_RS()/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr))

        self.ui.wait(3)

        self.logger.info("Sending an ICMPv6 Echo Request...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.ui.wait(2)

        self.logger.info("Checking for Neighbor Solicitations from the UUT...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)

        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to transmit one-or-more Neighbor Solicitations")


class AllRouterMulticastDestinationTestCase(RouterSolicitationsHelper):
    """
    Host Ignores Router Solicitations - All-Router Multicast Destination

    Verify that a host sends valid Router Solicitations at the appropriate time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.2.3a)
    """

    def set_up(self):
        self.dst = "ff02::2"


class AllNodesMulticastDestinationTestCase(RouterSolicitationsHelper):
    """
    Host Ignores Router Solicitations - All-Nodes Multicast Destination

    Verify that a host sends valid Router Solicitations at the appropriate time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.2.3b)
    """

    def set_up(self):
        self.dst = "ff02::1"


class LinkLoalUnicastDestinationTestCase(RouterSolicitationsHelper):
    """
    Host Ignores Router Solicitations - Link-local Unicast Destination

    Verify that a host sends valid Router Solicitations at the appropriate time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.2.3c)
    """

    def set_up(self):
        self.dst = self.target(1).link_local_ip()
        