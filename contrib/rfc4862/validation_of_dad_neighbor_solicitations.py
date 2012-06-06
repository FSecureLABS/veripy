from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import HostUutReceivesPacketDuringDadAndStopsTestHelper
from slaac_test_helper import RouterUutReceivesPacketDuringDadAndStopsTestHelper
from slaac_test_helper import UutReceivesPacketDuringDadAndContinuesTestHelper

class UutReceiveInvalidDadNsLength16TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part A
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS length < 24


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = sol_node_multicast)/Raw(ICMPv6ND_NS(tgt = str(uut_tentative)).build()[:16])

class UutReceivesInvalidDadNsHopLimit254TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part B
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (HopLimit != 255)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = sol_node_multicast, hlim=254)/ICMPv6ND_NS(tgt = str(uut_tentative))

class UutReceivesInvalidDadNsDstIsUutTentTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part C
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (dst is UUT tentative)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = str(uut_tentative))/ICMPv6ND_NS(tgt = str(uut_tentative))

class UutReceivesInvalidDadNsDstIsAllNodeTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part D
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (dst is All Node)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = "FF02::01")/ICMPv6ND_NS(tgt = str(uut_tentative))
        
class UutReceivesInvalidDadNsICMPCode1TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part E
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (ICMP Code is 1)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative), code=1)

class UutReceivesInvalidDadNsInvalidChecksumTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part F
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (Invalid Checksum)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative), cksum=42)

class UutReceivesInvalidDadNsTargetMulticastTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part G
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (Target is multicast)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        # dst is solicited node multicast
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative))

class UutReceivesInvalidDadNsContainsSLLTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part H
    Validation of DAD Neighbor Solicitations
    UUT Receives Invalid DAD NS (Contains SLL)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        # dst is solicited node multicast
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)

class UutReceivesValidDadNsContainsReservedFieldHostTestCase(HostUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part I
    Validation of DAD Neighbor Solicitations
    Host UUT Receives Invalid DAD NS (Reserved Field)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative), res=0xFFFFFFFF)

class UutReceivesValidDadNsContainsTLLHostTestCase(HostUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part J
    Validation of DAD Neighbor Solicitations
    Host UUT Receives Invalid DAD NS (TLL)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        # dst is solicited node multicast
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative))/ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr)

class UutReceivesValidDadNsContainsReservedFieldRouterTestCase(RouterUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part I
    Validation of DAD Neighbor Solicitations
    Router UUT Receives Invalid DAD NS (Reserved Field)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative), res=0xFFFFFFFF)

class UutReceivesValidDadNsContainsTLLRouterTestCase(RouterUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part J
    Validation of DAD Neighbor Solicitations
    Router UUT Receives Invalid DAD NS (TLL)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.3
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        # dst is solicited node multicast
        return IPv6(src = "::", dst = sol_node_multicast)/ICMPv6ND_NS(tgt = str(uut_tentative))/ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr)
