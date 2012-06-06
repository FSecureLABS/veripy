from contrib.rfc3315.builder import *
from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class ReplyMessagesWithNotOnLinkTestCase(DHCPv6Helper):
    """
    Tranmission of Reply messages with NotOnLink

    Verify a client and server device properly generates Reply messages
    with a status code of 4 (NotOnLink).

    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.8)
    """

    def run(self):
        self.logger.info("Building a DHCPv6 Confirm message, for an off-link address...")
        c = self.build_dhcpv6_confirm(self.target(1), self.node(1), str(self.node(2).global_ip()))

        self.logger.info("Sending the DHCPv6 Confirm message...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    c)

        self.logger.info("Checking for a Reply message...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=DHCP6_Reply)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to find one-or-more Reply messages")
        r = r1[-1]

        assertHasLayer(DHCP6OptStatusCode, r, "expected the DHCPv6 Reply to contain an Status Code")
        assertEqual(0x004, r[DHCP6OptStatusCode].statuscode, "expected the DHCPv6 Status Code to be NotOnLink (0x0004)")
        