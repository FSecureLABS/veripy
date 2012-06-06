from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class ValidUDPPortTestCase(DHCPv6Helper):
    """
    ValidUDPPort
    
    Verify that a device sends DHCPv6 messages using the correct port number.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.3)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=DHCPv6DestPort)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r2 = self.node(1).received(src=str(self.target(1).link_local_ip()), dst=str(self.node(1).link_local_ip()), type=DHCP6_Reply, 
            lbda=lambda p: p.dport==DHCPv6SourcePort)
        assertEqual(1, len(r2), "Expected to receive a DHCPv6 Reply with UDP destination port of 547.")


class InvalidUDPPortTestCase(DHCPv6Helper):
    """
    InvalidUDPPort
    
    Verify that a device properly handles DHCPv6 messages using an incorrect port number.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 8.1.3)
    """
    
    def run(self):
        #self.ui.ask("Restart DHCPv6 on the NUT. Enter 'y' and press enter when you have done this.")
        self.logger.info("Sending an Information Request message from TN1.")

        q = self.build_dhcpv6_information_request(self.node(1))
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=AllDHCPv6RelayAgentsAndServers)/UDP(sport=DHCPv6SourcePort, dport=33536)/q)

        self.logger.info("Checking for a DHCPv6 Reply message.")
        r2 = self.node(1).iface(0).received(src=str(self.target(1).link_local_ip()))
        assertEqual(0, len(r2), "Did not expect to receive any packets.")
