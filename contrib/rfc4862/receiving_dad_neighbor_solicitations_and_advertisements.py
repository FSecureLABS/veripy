from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import UutReceivesPacketDuringDadAndContinuesTestHelper
from slaac_test_helper import HostUutReceivesPacketDuringDadAndStopsTestHelper
from slaac_test_helper import RouterUutReceivesPacketDuringDadAndStopsTestHelper

class ReceivesDadNsTargetIsNotUutTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Receiving DAD Neighbor Solicitations And Advertisements
    PART A Recieve Dad Neighbor solicitation target is not UUT


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.2
    RFC4862 5.4, 5.4.1, 5.4.3, 5.4.4, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("  NS with Target not UUT.")
        return IPv6(src="::", dst=str(sol_node_multicast), nh=58, hlim=255)/ICMPv6ND_NS(tgt = str(self.node(1).link_local_ip()))


class ReceivesDadNsTargetIsUutHostTestCase(HostUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Receiving DAD Neighbor Solicitations And Advertisements
    PART B Host Recieve Dad Neighbor solicitation target is UUT


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
    Test v6LC.3.1.2
    RFC4862 5.4, 5.4.1, 5.4.3, 5.4.4, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("  NS with Target == UUT.")
        return IPv6(src="::", dst=str(sol_node_multicast), nh=58, hlim=255)/ICMPv6ND_NS(tgt = str(uut_tentative))


class ReceivesDadNaTargetIsNotUutTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Receiving DAD Neighbor Solicitations And Advertisements
    PART C Recieve Dad Neighbor Advertisement target is not UUT 


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.2
    RFC4862 5.4, 5.4.1, 5.4.3, 5.4.4, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("  NA with Target not UUT.")
        return IPv6(src=str(self.target(1).link_local_ip()), dst="FF02::1", nh=58, hlim=255)/ICMPv6ND_NA(R=0, S=0, O=1, tgt=str(self.node(1).link_local_ip()))/ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class ReceivesDadNaTargetIsUutHostTestCase(HostUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Receiving DAD Neighbor Solicitations And Advertisements
    PART D Host Recieve Dad Neighbor Advertisement target is UUT


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.2
    RFC4862 5.4, 5.4.1, 5.4.3, 5.4.4, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("  NA with Target is UUT.")
        return IPv6(src=str(self.target(1).link_local_ip()), dst="FF02::1", nh=58, hlim=255)/ICMPv6ND_NA(R=0, S=0, O=1, tgt=str(uut_tentative))

class ReceivesDadNsTargetIsUutRouterTestCase(RouterUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Receiving DAD Neighbor Solicitations And Advertisements
    PART B Router Recieve Dad Neighbor solicitation target is UUT


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
    Test v6LC.3.1.2
    RFC4862 5.4, 5.4.1, 5.4.3, 5.4.4, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("  NS with Target == UUT.")
        return IPv6(src="::", dst=str(sol_node_multicast), nh=58, hlim=255)/ICMPv6ND_NS(tgt = str(uut_tentative))

class ReceivesDadNaTargetIsUutRouterTestCase(RouterUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Receiving DAD Neighbor Solicitations And Advertisements
    PART D Router Recieve Dad Neighbor Advertisement target is UUT


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.2
    RFC4862 5.4, 5.4.1, 5.4.3, 5.4.4, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("  NA with Target is UUT.")
        return IPv6(src=str(self.target(1).link_local_ip()), dst="FF02::1", nh=58, hlim=255)/ICMPv6ND_NA(R=0, S=0, O=1, tgt=str(uut_tentative))


