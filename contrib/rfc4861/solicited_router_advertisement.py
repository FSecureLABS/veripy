from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ValidRouterSolicitationHelper(ComplianceTestCase):

    disabled_nd = True
    disabled_ra = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.ui.ask("Please restart the UUT's interface, and then press Y.")

        self.logger.info("Waiting for a Router Solicitation...")
        r1 = self.router(1).received(iface=1, dst="ff02::2", type=ICMPv6ND_RS, timeout=30)

        self.logger.info("Responding to the Router Solicitiation with an Advertisement...")
        self.router(1).send(self.p, iface=1)
        
        self.ui.wait(RTR_SOLICITATION_INTERVAL + MAX_RTR_SOLICITATION_DELAY)
        
        self.logger.info("Checking for Router Solicitations...")
        r2 = self.router(1).received(iface=1, dst="ff02::2", type=ICMPv6ND_RS)
        assertEqual(1, len(r2), "expecting the UUT to have sent a single Router Solicitation")
        assertTrue(self.target(1).link_local_ip() == r2[0][IPv6].src or "::" == r2[0][IPv6].src, "expected the Router Solicitation to originate from the UUT or ::")


class InvalidRouterSolicitationHelper(ComplianceTestCase):

    disabled_nd = True
    disabled_ra = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.ui.ask("Please restart the UUT's interface, and then press Y.")

        self.logger.info("Waiting for a Router Solicitation...")
        r1 = self.router(1).received(iface=1, dst="ff02::2", type=ICMPv6ND_RS, timeout=30)

        self.logger.info("Responding to the Router Solicitiation with an Advertisement...")
        self.router(1).send(self.p, iface=1)

        self.ui.wait(RTR_SOLICITATION_INTERVAL + MAX_RTR_SOLICITATION_DELAY)

        self.logger.info("Checking for Router Solicitations...")
        r2 = self.router(1).received(iface=1, dst="ff02::2", type=ICMPv6ND_RS)
        assertGreaterThan(1, len(r2), "expecting the UUT to have sent many Router Solicitations")

        for p in r2:
            assertTrue(self.target(1).link_local_ip() == p[IPv6].src or "::" == p[IPv6].src, "expected the Router Solicitation to originate from the UUT or ::")


class ValidAdvertisementNoSLLTestCase(ValidRouterSolicitationHelper):
    """
    Router Solicitations, Solicited Router Advertisement - Valid Router
    Advertisement, No Source Link-layer Address Option

    Verify that a host sends valid Router Solicitations at the appropriate
    time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.2a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(code=0)


class ValidAdvertisementSLLTestCase(ValidRouterSolicitationHelper):
    """
    Router Solicitations, Solicited Router Advertisement - Valid Router
    Advertisement, Source Link-layer Address Option

    Verify that a host sends valid Router Solicitations at the appropriate
    time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.2b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(code=0)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class InvalidAdvertisementGlobalSourceAddressTestCase(InvalidRouterSolicitationHelper):
    """
    Router Solicitations, Solicited Router Advertisement - Invalid Router
    Advertisement, Global Source Address

    Verify that a host sends valid Router Solicitations at the appropriate
    time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.2c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).global_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(code=0)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class InvalidAdvertisementBadHopLimitTestCase(InvalidRouterSolicitationHelper):
    """
    Router Solicitations, Solicited Router Advertisement - Invalid Router
    Advertisement, Bad Hop Limit

    Verify that a host sends valid Router Solicitations at the appropriate
    time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.2d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=2)/\
                    ICMPv6ND_RA(code=0)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class InvalidAdvertisementBadICMPChecksumTestCase(InvalidRouterSolicitationHelper):
    """
    Router Solicitations, Solicited Router Advertisement - Invalid Router
    Advertisement, Bad ICMP Checksum

    Verify that a host sends valid Router Solicitations at the appropriate
    time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.2e)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(code=0, cksum=0)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class InvalidAdvertisementBadICMPCodeTestCase(InvalidRouterSolicitationHelper):
    """
    Router Solicitations, Solicited Router Advertisement - Invalid Router
    Advertisement, Bad ICMP Code

    Verify that a host sends valid Router Solicitations at the appropriate
    time.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.2f)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1", hlim=255)/\
                    ICMPv6ND_RA(code=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)
                        