from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class BasicMessageExchangeTestCase(DHCPv6Helper):
    """
    Basic Message Exchange
    
    Verify that a device can properly handle the reception of DHCPv6 messages during
    a basic message exchange.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.1)
    """
    
    def run(self):
        if not self.ui.ask("Is the NUT configured to provide a DNS recursive Name Server option?", True):
            fail("Cannot run unit test since DHCPv6 is not configured to provide DNS recursive Name Server option.")
            return

        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r2), "expected to receive a DHCPv6 Reply")
        p = r2[0]

        self.logger.info("Checking that DHCPv6 Reply is properly formatted.")
        assertHasLayer(DHCP6OptClientId, p)
        assertHasLayer(DHCP6OptServerId, p)
        assertHasLayer(DHCP6OptDNSServers, p)
        assertHasLayer(DHCP6OptDNSDomains, p)
