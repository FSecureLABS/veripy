from contrib.rfc3315.constants import *
from contrib.rfc3633.dhcpv6_pd import DHCPv6PDHelper
from scapy.all import *
from veripy.assertions import *


class NoPrefixAvailTestCase(DHCPv6PDHelper):
    """
    Delegating Router Initiated: Advertise Message Status NoPrefixAvail

    Verify that a device can properly interoperate while using DHCPv6-PD

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 4.5)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Waiting for a DHCPv6 Solicit message, with a IA for Prefix Delegation...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Solicit)

        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive one-or-more DHCPv6 Solicit messages")
        assertHasLayer(DHCP6OptIA_PD, r1[0], "expected the DHCPv6 Solicit message to contain an IA for Prefix Delegation")

        self.logger.info("Sending a DHCPv6 Advertise message, with a Status Code of NoPrefixAvail...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                UDP(sport=DHCPv6DestPort, dport=DHCPv6SourcePort)/
                    self.build_dhcpv6_pd_advertise(r1[0], self.node(1), self.target(1), T1=50, T2=80, ias=False)/
                        DHCP6OptStatusCode(statuscode=6, statusmsg="No prefixes available for this interface."))

        self.logger.info("Checking for a DHCPv6 Request message...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Request)
        assertGreaterThanOrEqualTo(0, len(r2), "did not expect to receive a DHCPv6 Request message")
        