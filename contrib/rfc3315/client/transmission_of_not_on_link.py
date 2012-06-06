from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class TransmissionOfNotOnLinkTestCase(DHCPv6Helper):
    """
    Server Initiated: Transmission of Reply Messages with NotOnLink

    Verify a client properly handles Reply messages with NotOnLink.

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.8)
    """

    def run(self):
        self.do_dhcpv6_handshake_as_server(self.node(1), self.target(1))

        self.ui.tell("Disconnect the UUT until it registers a lost connection. Then reconnect it.")
        assertTrue(self.ui.ask("Has the UUT reconfigured its interface?"))

        self.logger.info("Checking for a DHCPv6 Confirm message...")
        r4 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Confirm)
        assertEqual(1, len(r4), "expected to receive a DHCPv6 Confirm")

        assertHasLayer(DHCP6OptIA_NA, r4[0], "expected the DHCPv6 Confirm message to have an IA")
        assertHasLayer(DHCP6OptIAAddress, r4[0], "expected the IA to contain an Address")
        assertEqual(self.target(1).global_ip(), q[DHCP6OptIAAddress].addr, "expected the DHCPv6 Client to request the IP address previously assigned")

        self.logger.info("Building a DHCPv6 Reply for the client")
        a = self.build_dhcpv6_reply(r4[0], self.node(1), self.target(1), ias=False)
        self.logger.info("Adding a Status Code of 0x0004 (NotOnLink)")
        a = a/DHCP6OptStatusCode(statuscode=0x0004)

        self.node(1).clear_received()
        self.logger.info("Sending the DHCPv6 Reply message, indicating NotOnLink...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=s.dport, dport=s.sport)/a)
        
        self.logger.info("Checking for a DHCPv6 Solicit Message...")
        r1 = server.received(src=str(client.link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Solicit)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a DHCPv6 Solicit message")
        