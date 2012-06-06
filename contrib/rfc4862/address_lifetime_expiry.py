from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import SlaacTestHelper

class AddressLifetimeExpiryTestCase(SlaacTestHelper):
    
    disabled_nd = True
    disabled_ra = True
    
    """
    Address Lifetime Expiry HOST ONLY

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.2.2
    RFC4862 5.4
    """
    def run(self):
        self.ui.ask("Please re-initialize the interface being tested then press y to continue.")
        self.node(1).clear_received()

        # Send RA
        self.logger.info("Sending RA")
        self.router(1).send(self.test_ra(), iface=1)

        # Allow time for UUT to perform SLAAC
        # UUT should perform DAD on tentative global address
        self.logger.info("Waiting for neighbor solicitation for tentative IP")
        self.node(1).received(lbda=lambda p: p.haslayer(ICMPv6ND_NS), timeout=30, dst=self.target(1).global_ip().solicited_node())
        self.logger.info("Neighbor solicitation received for tentative global IP")

        self.node(1).clear_received()

        # Transmit a DAD NS
        self.send_neighbor_solicitation_from_node_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent.")

        self.ui.wait(30)
        self.node(1).clear_received()

        # Transmit a DAD NS
        self.send_neighbor_solicitation_from_node_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Get an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", type=ICMPv6ND_NA)
        assertEqual(1, len(na), "expected a ICMPv6 Neighbor Advertisement to be sent after 35 seconds.")

        self.ui.wait(15)
        self.node(1).clear_received()

        # Transmit a DAD NS
        self.send_neighbor_solicitation_from_node_1(dst=str(self.target(1).global_ip().solicited_node()), target=str(self.target(1).global_ip()))

        # Expired Don't expect to an NA in response
        na = self.node(1).received(src=self.target(1).global_ip(), dst="ff02::1", type=ICMPv6ND_NA)
        assertEqual(0, len(na), "not expecting a ICMPv6 Neighbor Advertisement to be sent.")




    def test_ra(self):

        ll_info = ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(0).ll_addr)
        link_mtu_info = ICMPv6NDOptMTU(mtu=self.router(1).iface(0).ll_protocol.mtu)
        prefix_info = ICMPv6NDOptPrefixInfo(validlifetime=40, preferredlifetime=40, prefixlen=self.router(1).iface(0).global_ip().prefix_size, prefix=self.router(1).iface(0).global_ip().network())

        return IPv6(src=str(self.router(1).iface(0).link_local_ip()), dst="ff02::1")/ICMPv6ND_RA()/ll_info/link_mtu_info/prefix_info