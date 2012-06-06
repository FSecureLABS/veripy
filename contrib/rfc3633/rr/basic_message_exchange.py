from contrib.rfc3315.constants import *
from contrib.rfc3633.dhcpv6_pd import DHCPv6PDHelper
from scapy.all import *
from veripy.assertions import *
from veripy.models import IPAddress


class BasicMessageExchangeTestCase(DHCPv6PDHelper):
    """
    DHCPv6-PD Basic Message Exchange

    Verify that a device can properly interoperate while using DHCPv6-PD

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 4.1)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Waiting for a DHCPv6 Solicit message, with a IA for Prefix Delegation...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Solicit)

        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive one-or-more DHCPv6 Solicit messages")
        assertHasLayer(DHCP6OptIA_PD, r1[0], "expected the DHCPv6 Solicit message to contain an IA for Prefix Delegation")

        self.logger.info("Sending a DHCPv6 Advertise message, offering a prefix...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                UDP(sport=DHCPv6DestPort, dport=DHCPv6SourcePort)/
                    self.build_dhcpv6_pd_advertise(r1[0], self.node(1), self.target(1), T1=50, T2=80))

        self.logger.info("Checking for a DHCPv6 Request message...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Request)
        assertGreaterThanOrEqualTo(1, len(r2), "expected to receive a DHCPv6 Request message")
        assertHasLayer(DHCP6OptIA_PD, r2[0], "expected the DHCPv6 Request to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r2[0], "expected the DHCPv6 Request to contain an IA Prefix")
        assertEqual(IPAddress.identify(self.node(1).iface(0).link.v6_prefix), r2[0][DHCP6OptIAPrefix].prefix, "expected the requested Prefix to match the advertised one")
        assertEqual(self.node(1).iface(0).link.v6_prefix_size, r2[0][DHCP6OptIAPrefix].plen, "expected the requested Prefix Length to match the advertised one")

        self.logger.info("Sending a DHCPv6 Reply message, with the offered IA for Prefix Delegation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                UDP(sport=DHCPv6DestPort, dport=DHCPv6SourcePort)/
                    self.build_dhcpv6_pd_reply(r2[0], self.node(1), self.target(1)))

        self.ui.wait(50)

        self.node(1).clear_received()
        self.logger.info("Waiting for a DHCPv6 Renew message, with a IA for Prefix Delegation...")
        r3 = self.node(1).received(src=self.target(1).link_local_ip(), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Renew)
        assertGreaterThanOrEqualTo(1, len(r3), "expected to receive one-or-more DHCPv6 Renew messages")
        assertHasLayer(DHCP6OptIA_PD, r3[0], "expected the DHCPv6 Renew to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r3[0], "expected the DHCPv6 Renew to contain an IA Prefix")
        assertEqual(r2[0][DHCP6OptIAPrefix].prefix, r3[0][DHCP6OptIAPrefix].prefix, "expected the original prefix to be renewed")
        