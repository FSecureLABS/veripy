from contrib.rfc3315.constants import *
from contrib.rfc3633.dhcpv6_pd import DHCPv6PDHelper
from scapy.all import *
from veripy.assertions import *


class BasicMessageExchangeTestCase(DHCPv6PDHelper):
    """
    DHCPv6-PD Basic Message Exchange

    Verify that a device can properly interoperate while using DHCPv6-PD

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 4.1)
    """

    def run(self):
        self.logger.info("Sending a DHCPv6 Solicit message, with a IA for Prefix Delegation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(AllDHCPv6RelayAgentsAndServers))/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    self.build_dhcpv6_pd_solicit(self.node(1)))

        self.logger.info("Checking for a DHCPv6 Advertise message...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=DHCP6_Advertise)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Advertise message")

        assertHasLayer(DHCP6OptIA_PD, r1[0], "expected the DHCPv6 Advertise to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r1[0], "expected the DHCPv6 Advertise to contain an IA Prefix")

        self.logger.info("Sending a DHCPv6 Request message, with the offered IA for Prefix Delegation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(AllDHCPv6RelayAgentsAndServers))/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    self.build_dhcpv6_pd_request(r1[0], self.target(1), self.node(1)))

        self.logger.info("Checking for a DHCPv6 Reply message...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), type=DHCP6_Reply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Reply message")

        assertHasLayer(DHCP6OptIA_PD, r2[0], "expected the DHCPv6 Reply to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r2[0], "expected the DHCPv6 Reply to contain an IA Prefix")

        self.ui.wait(50)

        self.node(1).clear_received()
        self.logger.info("Sending a DHCPv6 Renew message, with the offered IA for Prefix Delegation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(AllDHCPv6RelayAgentsAndServers))/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    self.build_dhcpv6_pd_renew(r2[0], self.target(1), self.node(1)))

        self.logger.info("Checking for a DHCPv6 Reply message...")
        r3 = self.node(1).received(src=self.target(1).link_local_ip(), type=DHCP6_Reply)
        assertEqual(1, len(r3), "expected to receive a DHCPv6 Reply message")

        assertHasLayer(DHCP6OptIA_PD, r3[0], "expected the DHCPv6 Reply to contain an IA for Prefix Delegation")
        assertHasLayer(DHCP6OptIAPrefix, r3[0], "expected the DHCPv6 Reply to contain an IA Prefix")

        assertEqual(r2[0][DHCP6OptIAPrefix].prefix, r3[0][DHCP6OptIAPrefix].prefix, "expected the prefix to be renewed")
    