from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class NoServerIdentifierOptionTestCase(DHCPv6Helper):
    """
    No Server Identifier Option
    
    Verify that a client properly handles the reception of invalid Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.7)
    """
    
    def run(self):
        self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Checking for a DHCPv6 Information Request message...")
        r1 = self.node(1).received(dst=AllDHCPv6RelayAgentsAndServers, src=str(self.target(1).link_local_ip()), type=DHCP6_InfoRequest)
        assertEqual(1, len(r1), "Expected to receive a DHCPv6 Information Request.")
        q = r1[0]

        self.logger.info("Building a DHCPv6 Reply message...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False, server_id=False)

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=q.dport, dport=q.sport)/p)

        self.ui.ask("Please send an echo request from the NUT to \"DHCPv6.TEST.EXAMPLE.COM\". Enter 'y' and press enter when you have done this.")
        r2 = self.node(3).received(src=self.target(1).link_local_ip(), dst=str(self.node(3).global_ip()),
            type=DNS)
        assertEqual(0, len(r2), "Did not expect to receive a DNS Standard Query.")


class TransactionIDMismatchTestCase(DHCPv6Helper):
    """
    Transaction ID Mismatch
    
    Verify that a client properly handles the reception of invalid Reply messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.6)
    """
    
    def run(self):
        self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Checking for a DHCPv6 Information Request message...")
        r1 = self.node(1).received(dst=AllDHCPv6RelayAgentsAndServers, src=str(self.target(1).link_local_ip()), type=DHCP6_InfoRequest)
        assertEqual(1, len(r1), "Expected to receive a DHCPv6 Information Request.")
        q = r1[0]

        self.logger.info("Building a DHCPv6 Reply message...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1), trid=0x21, ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False)

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=q.dport, dport=q.sport)/p)

        self.ui.ask("Please send an echo request from the NUT to \"DHCPv6.TEST.EXAMPLE.COM\". Enter 'y' and press enter when you have done this.")
        r2 = self.node(3).received(src=self.target(1).link_local_ip(), dst=str(self.node(3).global_ip()),
            type=DNS)
        assertEqual(0, len(r2), "Did not expect to receive a DNS Standard Query.")
