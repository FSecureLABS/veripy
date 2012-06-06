from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase
from constants import *

class InvalidRouterSolicitationHelper(ComplianceTestCase):

    disabled_nd = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.logger.info("Sending the invalid Router Solicitation...")
        self.node(1).send(self.p)

        self.logger.info("Checking for replies...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip(), type=ICMPv6ND_RA)

        assertEqual(0, len(r1), "did not expect the UUT to send a Router Advertisement")


class HopLimitIsNot255TestCase(InvalidRouterSolicitationHelper):
    """
    Router Ignores Invalid Router Solicitations -

    Verify that a router ignores invalid Router Solicitations.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.2.4a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1", hlim=254)/\
                    ICMPv6ND_RS(tgt="ff02::1")


class InvalidICMPChecksumTestCase(InvalidRouterSolicitationHelper):
    """
    Router Ignores Invalid Router Solicitations -

    Verify that a router ignores invalid Router Solicitations.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.2.4b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_RS(cksum=0, tgt="ff02::1")


class InvalidICMPCodeTestCase(InvalidRouterSolicitationHelper):
    """
    Router Ignores Invalid Router Solicitations -

    Verify that a router ignores invalid Router Solicitations.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.2.4c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_RS(code=0, tgt="ff02::1")


class InvalidICMPLengthTestCase(InvalidRouterSolicitationHelper):
    """
    Router Ignores Invalid Router Solicitations -

    Verify that a router ignores invalid Router Solicitations.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.2.4d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1", plen=6)/\
                    ICMPv6ND_RS(tgt="ff02::1")
                    

class UnspecifiedIPSourceAddressWithSLLTestCase(InvalidRouterSolicitationHelper):
    """
    Router Ignores Invalid Router Solicitations -

    Verify that a router ignores invalid Router Solicitations.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.2.4f)
    """

    def set_up(self):
        self.p = IPv6(src="::", dst="ff02::1")/\
                    ICMPv6ND_RS(tgt="ff02::1")/\
                        ICMPv6NDOptSrcLLAddr(ll_addr=self.node(1).iface(0).ll_addr)
                    