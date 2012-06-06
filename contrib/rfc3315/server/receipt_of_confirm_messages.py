from contrib.rfc3315.builder import *
from contrib.rfc3315.constants import *
from contrib.rfc3315.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *

class ReceiptOfConfirmMessagesTestCase(DHCPv6Helper):
    """
    Receipt of Confirm Messages
    
    Verify a client and server device properly handles Confirm message.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 1.2)
    """
    
    def run(self):
        ip, p = self.do_dhcpv6_handshake_as_client(self.target(1), self.node(1))

        self.logger.info("Acquired the IP %s from the DHCPv6 Server." % (ip))
        
        self.node(1).clear_received()
        self.logger.info("Building a DHCPv6 Confirm message...")
        c = self.build_dhcpv6_confirm(self.target(1), self.node(1), ip=ip)

        self.ui.wait(10)
        self.logger.info("Sending the DHCPv6 Confirm message...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/
                UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/
                    c)

        self.logger.info("Waiting for the UUT to respond to the DHCPv6 Confirm...")
        r1 = self.node(1).received(src=str(self.target(1).link_local_ip()), type=DHCP6_Reply)
        assertEqual(1, len(r1), "expected to receive a DHCPv6 Reply")
        p = r1[0]

        assertHasLayer(DHCP6OptIA_NA, p, "expected the DHCPv6 Reply to contain an IA")
        assertHasLayer(DHCP6OptIAAddress, p, "expected the IA to contain an Address")
        assertEqual(ip, p[DHCP6OptIAAddress].addr, "expected the DHCPv6 Reply to include the already assigned IP")
        