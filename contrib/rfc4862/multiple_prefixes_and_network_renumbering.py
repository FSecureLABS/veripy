from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import SlaacTestHelper
from veripy.models import IPv6Address

class MultiplePrefixesAndNetworkRenumberingTestCase(SlaacTestHelper):
    
    
    """
    Multiple Prefixes and Network Renumbering HOST ONLY

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.3
    RFC4862 4.1
    RFC4291 2.1
    RFC4861 6.3.4 6.3.5 12

    """
    def run(self):
        # Test Set Up
        self.logger.info("sending router advertisement with prefix x")
        self.router(1).send(self.router_advertisement_x(), iface=1)

        # Step 2
        self.logger.info("sending router advertisement with prefix y")
        self.router(1).send(self.router_advertisement_y(), iface=1)

        # Step 3
        self.ui.wait(10)

        # Step 4 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()        
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))
       
        # Result 4 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent for prefix x.")

        # Step 5 Transmit a DAD NS for address prefix y
        self.logger.info("Step 5")
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.global_ip_y().solicited_node()), target=str(self.global_ip_y()))

        # Result 5 Get an NA in response
        na = self.node(1).received(src=self.global_ip_y(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent for prefix y.")

        # Step 11
        self.ui.wait(11)

        # Step 7 Transmit a DAD NS for address prefix x
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Result 7 Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "not expected a ICMPv6 Neighbor Advertisement to be sent for prefix x.")

        # Step 8 Transmit a DAD NS for address prefix y
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.global_ip_y().solicited_node()), target=str(self.global_ip_y()))

        # Result 8 Get an NA in response
        na = self.node(1).received(src=self.global_ip_y(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent for prefix y.")

        # Step 9
        self.ui.wait(10)

        # Step 10 Transmit a DAD NS for address prefix y
        self.node(1).clear_received()
        self.send_neighbor_solicitation_from_router_1(dst=str(self.global_ip_y().solicited_node()), target=str(self.global_ip_y()))

        # Result 10 Get an NA in response
        na = self.node(1).received(src=self.global_ip_y(), dst="ff02::1", timeout=1, type=ICMPv6ND_NA)
        assertEqual(0, len(na), "not expected a ICMPv6 Neighbor Advertisement to be sent for prefix y.")

    def router_advertisement_x(self):

        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info = ICMPv6NDOptPrefixInfo(validlifetime=20, preferredlifetime=20, prefixlen=self.router(1).iface(0).global_ip().prefix_size, prefix=self.router(1).iface(0).global_ip().network())

        return IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info

    def prefix_y(self):
        # This needs to be different to prefix x
        return "2012:7777::"

    def global_ip_y(self):
        return  IPv6Address(self.prefix_y() + in6_mactoifaceid(self.target(1).ll_addr()))

    def router_advertisement_y(self):

        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info = ICMPv6NDOptPrefixInfo(validlifetime=30, preferredlifetime=30, prefixlen=64, prefix=self.prefix_y())

        return IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info