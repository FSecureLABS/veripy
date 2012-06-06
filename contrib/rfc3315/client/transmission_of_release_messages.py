from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class TransmissionOfReleaseMessagesTestCase(DHCPv6Helper):
    """
    Transmission of Release Messages

    Verify a client transmits properly formatted Release messages to release
    IPv6 addresses configured by a server.

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.5)
    """

    def run(self):
        self.do_dhcpv6_handshake_as_server(self.node(1), self.target(1))

        self.ui.tell("Please configure the UUT's network interface to release the IPv6 address it was allocated.")
        assertTrue(self.ui.ask("Has the interface released its address?"))

        self.logger.info("Expecting the client to have sent a DHCPv6 Release message...")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers, type=DHCP6_Release)

        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a DHCPv6 Release message")

        r = r1[0]

        assertHasLayer(DHCP6OptIA_NA, r, "expected the DHCPv6 Rebnd message to have an IA")
        assertHasLayer(DHCP6OptIAAddress, r, "expected the IA to contain an Address")
        assertEqual(self.target(1).global_ip(), r[DHCP6OptIAAddress].addr, "expected the DHCPv6 Client to release the IP address previously assigned")

        self.logger.info("Waiting for the UUT to configure its interface...")
        self.ui.wait(5)

        self.node(1).clear_received()
        self.logger.info("Sending an ICMPv6 Echo Request to the UUT's released address...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an ICMPv6 Echo Reply from the UUT...")
        r2 = self.node(1).received(src=str(self.target(1).global_ip()), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r2), "did not expect to receive an ICMPv6 Echo Reply")
