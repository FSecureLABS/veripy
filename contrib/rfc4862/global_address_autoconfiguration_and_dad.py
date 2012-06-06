from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import SlaacTestHelper
from veripy.models import IPv6Address

class GlobalAddressAutoConfigHostTestHelper(SlaacTestHelper):

    def base_ra(self):
        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info = ICMPv6NDOptPrefixInfo(preferredlifetime=40, validlifetime=40, prefixlen=self.router(1).iface(0).global_ip().prefix_size, prefix=self.router(1).iface(0).global_ip().network())

        return IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info

    def run(self):
        if self.ui.ask("Is duplicate address detection configured on the device?"):
        # Initialize the Interface
            self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
            self.node(1).clear_received()

            # Send RA
            self.logger.info("Sending Custom RA")
            self.router(1).send(self.ra, iface=1)
            
            # Allow time for UUT to perform SLAAC
            # UUT should perform DAD on tentative global address
            self.logger.info("Waiting for neighbor solicitation for tentative IP")
            self.node(1).received(lbda=lambda p: p.haslayer(ICMPv6ND_NS), timeout=30, dst=self.assigned_ip.solicited_node())
            self.logger.info("Neighbor solicitation received for tentative global IP")

            self.node(1).clear_received()

            # Transmit a DAD NS
            self.send_neighbor_solicitation_from_node_1(dst=str(self.assigned_ip.solicited_node()), target=str(self.assigned_ip))

            # Get an NA in response
            na = self.node(1).received(src=self.assigned_ip, dst="ff02::1", type=ICMPv6ND_NA)
            assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

class GlobalAddressAutoConfigRouterTestHelper(SlaacTestHelper):

    
    def run(self):
        if self.ui.ask("Is duplicate address detection configured on the device?"):
        # Initialize the Interface
            self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
            self.node(1).clear_received()

            # Send RA
            self.ui.ask("PLease configure the router with prefix %s", self.prefix)

            # Allow time for UUT to perform SLAAC
            # UUT should perform DAD on tentative global address
            self.logger.info("Waiting for neighbor solicitation for tentative IP")
            self.node(1).received(lbda=lambda p: p.haslayer(ICMPv6ND_NS), timeout=30, dst=self.assigned_ip.solicited_node())
            self.logger.info("Neighbor solicitation received for tentative global IP")

            self.node(1).clear_received()

            # Transmit a DAD NS
            self.send_neighbor_solicitation_from_node_1(dst=str(self.assigned_ip.solicited_node()), target=str(self.assigned_ip))

            # Get an NA in response
            na = self.node(1).received(src=self.assigned_ip, dst="ff02::1", type=ICMPv6ND_NA)
            assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

class GlobalAddressAutoConfigurationAndDadGlobalHostTestCase(GlobalAddressAutoConfigHostTestHelper):
    
    """
    Global Autoconfiguration and DAD
    Host Part A - Unicast autoconfigured address Global

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.1
    RFC4862 5.4
    """
    def set_up(self):
        self.assigned_ip = self.target(1).global_ip()
        self.ra = self.base_ra()
        self.ra[ICMPv6NDOptPrefixInfo].prefix=self.router(1).iface(0).global_ip().network()
    

class GlobalAddressAutoConfigurationAndDadPrefixEndingInZeroHostTestCase(GlobalAddressAutoConfigHostTestHelper):

    """
    Global Autoconfiguration and DAD
    Host Part B - Unicast autoconfigured address Prefix ending in zero values fields

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.1
    RFC4862 5.4
    """
    def set_up(self):
        self.assigned_ip = IPv6Address("8000:0000::" + in6_mactoifaceid(self.target(1).ll_addr()))
        self.ra = self.base_ra()
        self.ra[ICMPv6NDOptPrefixInfo].prefix="8000:0000::"
        

class GlobalAddressAutoConfigurationAndDadSiteLocalHostTestCase(GlobalAddressAutoConfigHostTestHelper):

    """
    Global Autoconfiguration and DAD
    Host Part C - Unicast autoconfigured address site local

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.1
    RFC4862 5.4
    """
    def set_up(self):
        self.assigned_ip = IPv6Address("FEC0::" + in6_mactoifaceid(self.target(1).ll_addr()))
        self.ra = self.base_ra()
        self.ra[ICMPv6NDOptPrefixInfo].prefix="FEC0::"

class GlobalAddressAutoConfigurationAndDadGlobalRouterTestCase(GlobalAddressAutoConfigRouterTestHelper):

    """
    Global Autoconfiguration and DAD
    Router Part A - Unicast autoconfigured address Global

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.1
    RFC4862 5.4
    """
    def set_up(self):
        self.assigned_ip = self.target(1).global_ip()
        self.prefix = self.router(1).iface(0).global_ip().network()


class GlobalAddressAutoConfigurationAndDadPrefixEndingInZeroRouterTestCase(GlobalAddressAutoConfigRouterTestHelper):

    """
    Global Autoconfiguration and DAD
    Router Part B - Unicast autoconfigured address Prefix ending in zero values fields

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.1
    RFC4862 5.4
    """
    def set_up(self):
        self.assigned_ip = IPv6Address("8000:0000::" + in6_mactoifaceid(self.target(1).ll_addr()))
        self.prefix ="8000:0000::"


class GlobalAddressAutoConfigurationAndDadSiteLocalRouterTestCase(GlobalAddressAutoConfigRouterTestHelper):

    """
    Global Autoconfiguration and DAD
    Router Part C - Unicast autoconfigured address site local

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.1
    RFC4862 5.4
    """
    def set_up(self):
        self.assigned_ip = IPv6Address("FEC0::" + in6_mactoifaceid(self.target(1).ll_addr()))
        self.prefix="FEC0::"