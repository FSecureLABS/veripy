from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import SlaacTestHelper


class LifetimePrefixTestHelper(SlaacTestHelper):

    def router_advertisement_a(self):
        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info = ICMPv6NDOptPrefixInfo(L=1, validlifetime=20, preferredlifetime=20, prefixlen=64, prefix=self.router(1).iface(0).global_ip().network())
        nd_ra = ICMPv6ND_RA(routerlifetime=60, reachabletime=600, retranstimer=1)

        return IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1", nh=58)/nd_ra/ll_info/link_mtu_info/prefix_info

class PrefixInformationOptionProcessingLifetimePrefixLifetimeGreaterRemainingLifetimeTestCase(LifetimePrefixTestHelper):
    
    """
    Prefix Information Option Processing Lifetime HOST ONLY
    Part A Prefix Lifetime greater than remaining lifetime
    
    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
        # Step 1 RA 
        self.logger.info("Send RA")
        ra = self.router_advertisement_a()
        ra[ICMPv6NDOptPrefixInfo].validlifetime = 30
        self.router(1).send(ra, iface=1)

        # Step 2
        self.ui.wait(10)

        # Step 3
        self.logger.info("Send Another RA")
        self.router(1).send(IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(validlifetime=60, preferredlifetime=60, prefixlen=64, prefix=self.router(1).iface(0).global_ip().network()), iface=1)

        # Step 4
        self.ui.wait(25)

        # Step 5 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))


        # Result 6 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent for prefix x.")

class PrefixInformationOptionProcessingLifetimePrefixLifetimeGreaterThan2HoursTestCase(LifetimePrefixTestHelper):

    """
    Prefix Information Option Processing Lifetime HOST ONLY
    Part B Prefix Lifetime greater than 2 hours

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
        # Step 7 RA
        self.logger.info("Send RA")
        ra = self.router_advertisement_a()
        ra[ICMPv6NDOptPrefixInfo].validlifetime = 10800
        ra[ICMPv6NDOptPrefixInfo].preferredlifetime = 10800

        self.router(1).send(ra, iface=1)

        self.ui.wait(3)

        # Step 8
        self.logger.info("Send Another RA")
        self.router(1).send(IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(validlifetime=9000, preferredlifetime=9000, prefixlen=64, prefix=self.router(1).iface(0).global_ip().network()), iface=1)

        # Step 9
        self.ui.wait(9900)

        # Step 10 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))


        # Result 11 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "Not expecting ICMPv6 Neighbor Advertisement to be sent for prefix x.")

class PrefixInformationOptionProcessingLifetimePrefixLifetimeLessThanRemainingGreaterThan2HoursTestCase(LifetimePrefixTestHelper):

    """
    Prefix Information Option Processing Lifetime HOST ONLY
    Part c Prefix Lifetime less than remaining lifetime and remainging is greater than 2 hours

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
        # Step 12
        self.logger.info("Send RA")
        ra = self.router_advertisement_a()
        ra[ICMPv6NDOptPrefixInfo].validlifetime = 60
        ra[ICMPv6NDOptPrefixInfo].preferredlifetime = 60
        self.router(1).send(ra, iface=1)

        self.ui.wait(3)

        # Step 13
        self.logger.info("Send Another RA")
        self.router(1).send(IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(validlifetime=30, preferredlifetime=30, prefixlen=64, prefix=self.router(1).iface(0).global_ip().network()), iface=1)

        # Step 14
        self.ui.wait(35)

        # Step 15 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))


        # Result 16 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "Expected ICMPv6 Neighbor Advertisement to be sent for prefix x.")

class PrefixInformationOptionProcessingLifetimePrefixLifetimeLessThan2hoursRemainingGreaterThan2HoursTestCase(LifetimePrefixTestHelper):

    """
    Prefix Information Option Processing Lifetime HOST ONLY
    Part D Prefix Lifetime less than remaining lifetime and remainging is greater than 2 hours

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.4
    RFC4862 5.5.3

    """
    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
        # Step 12
        self.logger.info("Send RA")
        ra = self.router_advertisement_a()
        ra[ICMPv6NDOptPrefixInfo].validlifetime = 9000
        ra[ICMPv6NDOptPrefixInfo].preferredlifetime = 9000
        self.router(1).send(ra, iface=1)

        self.ui.wait(3)

        # Step 13
        self.logger.info("Send Another RA")
        self.router(1).send(IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(validlifetime=10, preferredlifetime=10, prefixlen=64, prefix=self.router(1).iface(0).global_ip().network()), iface=1)

        # Step 14
        self.ui.wait(11)

        # Step 20 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Result Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "Expected ICMPv6 Neighbor Advertisement to be sent for prefix x.")

        # Step 21
        self.ui.wait(7215)

        # Step 22 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))


        # Result 23 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "Not expecting ICMPv6 Neighbor Advertisement to be sent for prefix x.")