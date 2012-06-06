from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import SlaacTestHelper
from veripy.models import IPv6Address

class PrefixInformationOptionProcessingMultiplePrefixesTestCase(SlaacTestHelper):
    
    disabled_nd = True
    disabled_ra = True
    
    """
    Prefix Information Option Processing HOST ONLY
    Part A multiple prefix options
    
    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def run(self):
        # Step 1 RA with multiple prefix options
        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info_1 = ICMPv6NDOptPrefixInfo(validlifetime=20, preferredlifetime=20, prefixlen=64, prefix=self.prefix_x())
        prefix_info_2 = ICMPv6NDOptPrefixInfo(validlifetime=40, preferredlifetime=40, prefixlen=64, prefix=self.prefix_y())

        self.logger.info("Send RA with multiple prefixes")
        self.router(1).send(IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1", hlim=255)/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info_1/prefix_info_2, iface=1)

        self.ui.wait(4)
        
        # Step 2 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Result 2 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent for prefix x.")
        
        # Step 3 Transmit a DAD NS for address prefix y
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.global_ip_y().solicited_node()), target=str(self.global_ip_y()))

        # Result 3 Get an NA in response
        na = self.node(1).received(src=self.global_ip_y(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent for prefix y.")

        # Step 4 Wait for prefix x to expire
        self.logger.info("Waiting for prefix " + self.prefix_x() + " to expire")
        self.ui.wait(21)

        # step 5 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Result 5 Don't get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "Not expecting a ICMPv6 Neighbor Advertisement to be sent for prefix x.")

        # Step 6 Wait for prefix y to expire
        self.logger.info("Waiting for prefix " + self.prefix_y() + " to expire")
        self.ui.wait(20)

        # Step 7 Transmit a DAD NS for address prefix y
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.global_ip_y().solicited_node()), target=str(self.global_ip_y()))

        # Result 7 Don't get an NA in response
        na = self.node(1).received(src=self.global_ip_y(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "Not expecting a ICMPv6 Neighbor Advertisement to be sent for prefix y.")

        

    def prefix_y(self):
        # This needs to be different to prefix x
        return "2012:7777::"
    
    def global_ip_y(self):
        return  IPv6Address(self.prefix_y() + in6_mactoifaceid(self.target(1).ll_addr()))

    def prefix_x(self):
        return self.router(1).iface(0).global_ip().network()


class PrefixOptionsTestHelper(SlaacTestHelper):
    disabled_nd = True
    disabled_ra = True

    """
    Generic run method for B-I 

    """
    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")

        self.logger.info("Send Test RA")
        self.router(1).send(self.test_ra, iface=1)

        self.ui.wait(4)

        # Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Result Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "Not expected a ICMPv6 Neighbor Advertisement to be sent.")

    def base_ra(self):
        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info = ICMPv6NDOptPrefixInfo(validlifetime=20, preferredlifetime=20, prefixlen=64, prefix=self.router(1).iface(0).global_ip().network())
        return IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1", hlim=255)/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info

class PrefixInformationOptionProcessingAutonomousFlagNotSetTestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part B Autonomous flag not set

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].A = 0
        self.test_ra = p

class PrefixInformationOptionProcessingPrefixLinkLocalTestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part C Prefix is link local prefix

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].prefix = "FE80::"
        self.test_ra = p

class PrefixInformationOptionProcessingPreferredLifetimeGreaterValidLifetimeTestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part D Preffered lifetime greater  valid lifetime

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].preferredlifetime = 30
        self.test_ra = p
        

class PrefixInformationOptionProcessingPrefixLengthGreater128TestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part E Prefix length 128

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].prefixlen = 128
        self.test_ra = p

class PrefixInformationOptionProcessingPrefixLengthLess64TestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part F Prefix Length set to 0

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].prefixlen = 0
        self.test_ra = p

class PrefixInformationOptionProcessingPrefixLengthBetween64And128TestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part G Prefix length between 64 and 128

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].prefixlen = 120
        self.test_ra = p

class PrefixInformationOptionProcessingValidLifetime0TestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part H Valid Lifetime 0

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].validlifetime = 0
        self.test_ra = p

class PrefixInformationOptionProcessingHopLimit254TestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part I Hop Limit 254

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[IPv6].hlim = 254
        self.test_ra = p

class PrefixInformationOptionProcessingValidLifetime0xffffffffTestCase(PrefixOptionsTestHelper):

    """
    Prefix Information Option Processing HOST ONLY
    Part J ValidLifetime 0xffffffff

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def set_up(self):
        p = self.base_ra()
        p[ICMPv6NDOptPrefixInfo].validlifetime = 0xffffffff
        self.test_ra = p

    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")

        self.logger.info("Send Test RA")
        self.router(1).send(self.test_ra, iface=1)

        self.ui.wait(4)

        # Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Result Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "Expected a ICMPv6 Neighbor Advertisement to be sent.")
