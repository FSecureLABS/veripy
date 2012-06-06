from contrib.rfc3315.constants import *
from contrib.rfc3633.dhcpv6_pd import DHCPv6PDHelper
from scapy.all import *
from veripy.assertions import *


class NoPrefixAvailTestCase(DHCPv6PDHelper):
    """
    Delegating Router Initiated: Advertise Message Status NoPrefixAvail

    Verify that a device can properly interoperate while using DHCPv6-PD

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 4.4)
    """

    def set_up(self):
        self.ui.tell("Please configure the UUT to have no prefixes available for allocation.")
        assertTrue(self.ui.ask("Press Y when ready."))

    def tear_down(self):
        self.ui.tell("Please configure the UUT to have prefixes available for allocation.")
        assertTrue(self.ui.ask("Press Y when ready."))

    def run(self):
        client, server = self.node(1), self.target(1)
        
        self.logger.info("Sending a DHCPv6 Solicit message, with a IA for Prefix Delegation...")
        client.send(
            IPv6(src=str(client.link_local_ip()), dst=str(AllDHCPv6RelayAgentsAndServers))/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    self.build_dhcpv6_pd_solicit(client))

        self.logger.info("Checking for a DHCPv6 Advertise message...")
        r1 = client.received(src=server.link_local_ip(), type=DHCP6_Advertise)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Advertise message")

        assertNotHasLayer(DHCP6OptIAPrefix, r1[0], "did not expect the DHCPv6 Reply to contain an IA Prefix")

        assertHasLayer(DHCP6OptStatusCode, r1[0], "expected the DHCPv6 Reply to contain a Status Code")
        assertEqual(6, r1[0][DHCP6OptStatusCode].statuscode, "expected status code to be NoPrefixAvail")
        assertEqual("No prefixes available for this interface.", r1[0][DHCP6OptStatusCode].statusmsg)
        