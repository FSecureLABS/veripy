from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import UutReceivesPacketDuringDadAndContinuesTestHelper


class ReceivingDadNsForAddrResSrcUnicastTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part A
    Receiving Neighbor solicitations for address resolution
    UUT receives NS src==unicast

    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.5
    RFC4862 5.4.3
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     src unicast")
        return IPv6(src = str(self.node(1).link_local_ip()), dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative))

class ReceivingDadNsForAddrResDstIsUutTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part B
    Receiving Neighbor solicitations for address resolution
    UUT receives NS src==unicast && dst == UUT tent


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.5
    RFC4862 5.4.3
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     src unicast and dst = UUT tentative")
        return IPv6(src = str(self.node(1).link_local_ip()), dst = str(uut_tentative))/ICMPv6ND_NS(tgt = str(uut_tentative))

