from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class DHCPUniqueIdentifierContentsTestCase(DHCPv6Helper):
    """
    DHCP Unique Identifier Contents
    
    Verify that a DHCPv6 server transmits correctly formatted DHCP Unique Indentifiers.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.6)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q1 = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q1)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Reply")
        p1 = r1[0]
        
        duid = None
        if p1[DHCP6OptServerId].haslayer(DUID_EN):
            duid = p1[DHCP6OptServerId][DUID_EN]
            assertNotEqual(0, duid.id, "DUID ID must be non-zero.")
            assertNotEqual(0, duid.enterprisenum, "DUID Enterprise Number is non-zero.")
        elif p1[DHCP6OptServerId].haslayer(DUID_LLT):
            duid = p1[DHCP6OptServerId][DUID_LLT]
            assertEqual(str(self.target(1).ll_addr()), duid.lladdr)
            assertTrue(duid.hwtype in range(1,37) or duid.hwtype == 256)
        elif p1[DHCP6OptServerId].haslayer(DUID_LL):
            duid = p1[DHCP6OptServerId][DUID_LL]
            assertEqual(str(self.target(1).ll_addr()), duid.lladdr)
            assertTrue(duid.hwtype in range(1,37) or duid.hwtype == 256)

        self.logger.info("Sending a second Information Request message from TN1.")

        q2 = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q2)

        self.logger.info("Checking for a second DHCPv6 Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(2, len(r2), "expected to receive a second DHCPv6 Reply")
        p2 = r2[1]

        duid = None
        if p2[DHCP6OptServerId].haslayer(DUID_EN):
            duid = p2[DHCP6OptServerId][DUID_EN]
            assertNotEqual(0, duid.id, "DUID ID must be non-zero.")
            assertNotEqual(0, duid.enterprisenum, "DUID Enterprise Number is non-zero.")
            assertEqual(p1[DHCP6OptServerId][DUID_EN].id, duid.id, "Replies sent by server do not have matching DUID IDs.")
            assertEqual(p1[DHCP6OptServerId][DUID_EN].enterprisenum, duid.enterprisenum, "Replies sent by server do not have matching DUID Enterprise Number.")
        elif p2[DHCP6OptServerId].haslayer(DUID_LLT):
            duid = p2[DHCP6OptServerId][DUID_LLT]
            assertEqual(str(self.target(1).ll_addr()), duid.lladdr)
            assertTrue(duid.hwtype in range(1,37) or duid.hwtype == 256)
            assertEqual(p1[DHCP6OptServerId][DUID_LLT].lladdr, duid.lladdr, "Replies sent by server do not have matching link layer addresses.")
            assertEqual(p1[DHCP6OptServerId][DUID_LLT].hwtype, duid.hwtype, "Replies sent by server do not have matching DUID hardware types.")
        elif p2[DHCP6OptServerId].haslayer(DUID_LL):
            duid = p2[DHCP6OptServerId][DUID_LL]
            assertEqual(str(self.target(1).ll_addr()), duid.lladdr)
            assertTrue(duid.hwtype in range(1,37) or duid.hwtype == 256)
            assertEqual(p1[DHCP6OptServerId][DUID_LL].lladdr, duid.lladdr, "Replies sent by server do not have matching link layer addresses.")
            assertEqual(p1[DHCP6OptServerId][DUID_LL].hwtype, duid.hwtype, "Replies sent by server do not have matching DUID hardware types.")
