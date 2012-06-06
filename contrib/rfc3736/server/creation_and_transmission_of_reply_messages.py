from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class ReplyMessageTransmissionTestCase(DHCPv6Helper):
    """
    Reply Message Transmission
    
    Verify that a DHCPv6 server transmits a proper Reply message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.12)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1), reqopts=[])
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Reply")
        p = r1[0]

        assertEqual(self.node(1).link_local_ip(), p.dst)
        assertEqual(q.trid, p.trid)
        assertHasLayer(DHCP6OptServerId, p)
        assertHasLayer(DHCP6OptClientId, p)

        if p.haslayer(DUID_EN):
            duid = p[DHCP6OptServerId][DUID_EN]
            assertNotEqual(q.duid.id, p.duid.id)
            assertNotEqual(q.duid.enterprisenum, p.duid.enterprisenum)
        elif p.haslayer(DUID_LLT):
            duid = p[DHCP6OptServerId][DUID_LLT]
            assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
            assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)
            assertEqual(q.duid.lladdr, p.duid.lladdr)
        elif p.haslayer(DUID_LL):
            duid = p[DHCP6OptServerId][DUID_LL]
            assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
            assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)


class ReplyMessageTransmissionWithDNSRNSOptionTestCase(DHCPv6Helper):
    """
    Reply Message Transmission With DNS RNS Option
    
    Verify that a DHCPv6 server transmits a proper Reply message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.12)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1), reqopts=[23])
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Reply")
        p = r1[0]

        assertEqual(self.node(1).link_local_ip(), p.dst)
        assertEqual(q.trid, p.trid)
        assertHasLayer(DHCP6OptServerId, p)
        assertHasLayer(DHCP6OptClientId, p)
        assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
        assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)
        assertEqual(q.duid.lladdr, p.duid.lladdr)

        assertHasLayer(DHCP6OptDNSServers, p)
        assertEqual(0, p[DHCP6OptDNSServers].optlen % 16)
        assertEqual(p[DHCP6OptDNSServers].optlen / 16, len(p.dnsservers))

        if p.haslayer(DUID_EN):
            duid = p[DHCP6OptServerId][DUID_EN]
            assertNotEqual(q.duid.id, p.duid.id)
            assertNotEqual(q.duid.enterprisenum, p.duid.enterprisenum)
        elif p.haslayer(DUID_LLT):
            duid = p[DHCP6OptServerId][DUID_LLT]
            assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
            assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)
            assertEqual(q.duid.lladdr, p.duid.lladdr)
        elif p.haslayer(DUID_LL):
            duid = p[DHCP6OptServerId][DUID_LL]
            assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
            assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)


class ReplyMessageTransmissionWithDomainSearchListOptionTestCase(DHCPv6Helper):
    """
    Reply Message Transmission With Domain Search List Option
    
    Verify that a DHCPv6 server transmits a proper Reply message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.12)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1), reqopts=[24])
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Reply")
        p = r1[0]

        assertEqual(self.node(1).link_local_ip(), p.dst)
        assertEqual(q.trid, p.trid)
        assertHasLayer(DHCP6OptServerId, p)
        assertHasLayer(DHCP6OptClientId, p)

        assertHasLayer(DHCP6OptDNSDomains, p)
        assertEqual(p[DHCP6OptDNSDomains].optlen, sum((len(x)+2) for x in p.dnsdomains))

        if p.haslayer(DUID_EN):
            duid = p[DHCP6OptServerId][DUID_EN]
            assertNotEqual(q.duid.id, p.duid.id)
            assertNotEqual(q.duid.enterprisenum, p.duid.enterprisenum)
        elif p.haslayer(DUID_LLT):
            duid = p[DHCP6OptServerId][DUID_LLT]
            assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
            assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)
            assertEqual(q.duid.lladdr, p.duid.lladdr)
        elif p.haslayer(DUID_LL):
            duid = p[DHCP6OptServerId][DUID_LL]
            assertLessThanOrEqualTo(q.duid.timeval+1, p.duid.timeval)
            assertGreaterThanOrEqualTo(q.duid.timeval-1, p.duid.timeval)


class RelayReplyMessageWithoutInterfaceIDTestCase(DHCPv6Helper):
    """
    Relay Reply Message Without Interface ID
    
    Verify that a DHCPv6 server transmits a proper Reply message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.12)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(2))
        q = self.build_dhcpv6_relay_forward(q, self.node(2), self.router(1), with_ifaceid=False)
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.router(1).iface(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Relay Reply")

class RelayReplyMessageWithInterfaceIDTestCase(DHCPv6Helper):
    """
    Relay Reply Message With Interface ID
    
    Verify that a DHCPv6 server transmits a proper Reply message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.12)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(2))
        q = self.build_dhcpv6_relay_forward(q, self.node(2), self.router(1))
        self.router(1).send(IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q, iface=1)

        self.logger.info("Checking for a DHCPv6 Relay Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.router(1).iface(1).link_local_ip()), type=DHCP6_RelayReply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Relay Reply")
