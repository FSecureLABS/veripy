from contrib.rfc3315.builder import *
from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class ReceiptOfDeclineMessagesTestCase(DHCPv6Helper):
    """
    Receipt of Decline Messages

    Verify a client and server device properly handles Decline messages.

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.6)
    """

    def run(self):
        ip, p = self.do_dhcpv6_handshake_as_client(self.target(1), self.node(1))

        T1 = p[DHCP6OptIAAddress].preflft
        T2 = p[DHCP6OptIAAddress].validlft

        self.logger.info("Acquired the IP %s from the DHCPv6 Server. T1=%d, T2=%d." % (ip, T1, T2))

        self.node(1).clear_received()
        self.logger.info("Building a DHCPv6 Decline message to send to the server...")
        d = self.build_dhcpv6_decline(p, self.target(1), self.node(1))
        
        self.logger.info("Sending the DHCPv6 Decline message to the server...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()),dst=AllDHCPv6RelayAgentsAndServers)/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    d)
        
        self.logger.info("Checking for a DHCPv6 Reply message...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=DHCP6_Reply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Reply message")
        p = r1[0]

        assertHasLayer(DHCP6OptStatusCode, p, "expected the DHCPv6 Reply to contain an Status Code")
        assertEqual(0x000, p[DHCP6OptStatusCode].statuscode, "expected the DHCPv6 Status Code to be Success (0x0000)")
        