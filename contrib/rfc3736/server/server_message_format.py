from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *
from veripy.models import IPv6Address


class ClientServerMessageFormatTestCase(DHCPv6Helper):
    """
    Client/Server Message Format
    
    Verify that a server transmits a DHCPv6 message wtih the proper format.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.4)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Reply")
        p = r2[0]

        self.logger.info("Checking that DHCPv6 Reply is properly formatted.")
        assertNotEqual(0, p.trid, "DHCPv6 Reply has a transaction ID of zero.")
        assertHasLayer(DHCP6OptClientId, p)
        assertHasLayer(DHCP6OptServerId, p)
        assertHasLayer(DHCP6OptDNSServers, p)
        assertHasLayer(DHCP6OptDNSDomains, p)


class RelayAgentServerMessageFormatTestCase(DHCPv6Helper):
    """
    Relay Agent/Server Message Format
    
    Verify that a server transmits a DHCPv6 message wtih the proper format.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.4)
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
        p = r2[0]

        self.logger.info("Checking that DHCPv6 Relay Reply is properly formatted.")
        assertEqual(q.hopcount, p.hopcount, "DHCPv6 Relay Reply has an incorrect hop count.")
        assertEqual(IPv6Address(q.peeraddr), p.peeraddr, "DHCPv6 Relay Reply has an incorrect peer address.")
        assertEqual(IPv6Address(q.linkaddr), p.linkaddr, "DHCPv6 Relay Reply has an incorrect link address.")
        assertHasLayer(DHCP6OptRelayMsg, p)
