from scapy.all import *
from veripy.assertions import *
from slaac_test_helper import HostUutReceivesPacketDuringDadAndStopsTestHelper
from slaac_test_helper import RouterUutReceivesPacketDuringDadAndStopsTestHelper
from slaac_test_helper import UutReceivesPacketDuringDadAndContinuesTestHelper


class UutReceiveInvalidDadNaLength16TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part A
    Validation of DAD Neighbor Adertisements
    UUT Receives Invalid DAD NA length < 24


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     length 16")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/Raw(ICMPv6ND_NA(tgt = str(uut_tentative)).build()[:16])

class UutReceiveInvalidDadNaHopLimit254TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part B
    Validation of DAD Neighbor Adertisements
    UUT Receives Invalid DAD NA hoplimit !=255


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     hop limit 254")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1", hlim=254)/ICMPv6ND_NA(tgt = str(uut_tentative))

class UutReceivesInvalidDadNaIcmpCode1TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part C
    Validation of DAD Neighbor Advertisement
    UUT Receives Invalid DAD NA (ICMP code 1)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        # tgt is UUT tentative
        self.logger.info("     icmp code 1")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative), code=1)

class UutReceivesInvalidDadNaInvalidChecksumTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part D
    Validation of DAD Neighbor Advertisement
    UUT Receives Invalid DAD NA (invalid checksum)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     invalid checksum")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative), cksum=42)

class UutReceivesInvalidDadNaSolicitedFlag1TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part E
    Validation of DAD Neighbor Advertisement
    UUT Receives Invalid DAD NA (solicited flag==1)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     NA solicited flag == 1")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative), S=1)

class UutReceivesInvalidDadNaTargetMulticastTestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part F
    Validation of DAD Neighbor Advertisement
    UUT Receives Invalid DAD NA (target is solicited node multicast)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     target is solicited node multicast")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = sol_node_multicast)

class UutReceivesInvalidDadNaOptionLength0TestCase(UutReceivesPacketDuringDadAndContinuesTestHelper):
    """
    Part G
    Validation of DAD Neighbor Advertisement
    UUT Receives Invalid DAD NA (option length 0)


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     opt length 0")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative))/ICMPv6NDOptDstLLAddr(len=0)

class UutReceivesValidDadNaReservedFieldHostTestCase(HostUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Host Part H
    Validation of DAD Neighbor Advertisement
    UUT Receives Invalid DAD NA


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     reserved field is 0x1FFFFFFF")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative), res=0x1FFFFFFF)

class UutReceivesValidDadNaContainsSLLHostTestCase(HostUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part I
    Validation of DAD Neighbor Advertisement
    Host UUT Receives Invalid DAD NA


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     SLL is node 1 iface 0 addr")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)

class UutReceivesValidDadNaReservedFieldRouterTestCase(RouterUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part H
    Validation of DAD Neighbor Advertisement
    Router UUT Receives Invalid DAD NA


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     reserved field is 0x1FFFFFFF")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative), res=0x1FFFFFFF)

class UutReceivesValidDadNaContainsSLLRouterTestCase(RouterUutReceivesPacketDuringDadAndStopsTestHelper):
    """
    Part I
    Validation of DAD Neighbor Advertisement
    Router UUT Receives Invalid DAD NA


    @private
    Source:   IPv6 Ready Phase-1/Phase-2 Test Specification Core
      Test v6LC.3.1.4
    RFC4862 5.4.1, 5.4.5
    """
    def test_case_packet(self, sol_node_multicast, uut_tentative):
        self.logger.info("     SLL is node 1 iface 0 addr")
        return IPv6(src = str(self.target(1).link_local_ip()), dst = "FF02::1")/ICMPv6ND_NA(tgt = str(uut_tentative))/ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)
