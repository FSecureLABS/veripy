from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class MulticastAddressesTestCase(DHCPv6Helper):
    """
    MulticastAddresses
    
    Verify that the client transmits an Information Request message with a 
    destination address of FF02::1:2.

    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.2)
    """
    
    def run(self):
    	self.restart_and_wait_for_information_request(self.node(1), self.target(1))


class ValidUDPPortTestCase(DHCPv6Helper):
    """
    Valid UDP Port
    
    Verify that the client transmits and accepts messages with a UDP port of 547.

    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.2)
    """
    
    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        self.logger.info("Building a DHCPv6 Reply message...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], dns_domains=["example.com"], pref=False)

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=q.dport, dport=q.sport)/p)

        self.confirm_dns(self.node(3), self.target(1))


class InvalidUDPPortTestCase(DHCPv6Helper):
    """
    Invalid UDP Port
    
    Verify that the client correctly processes an invalid DHCPv6 UDP port of 33536.

    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.2)
    """
    
    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        self.logger.info("Building a DHCPv6 Reply message...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], dns_domains=["example.com"], pref=False)

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=q.dport, dport=33536)/p)

        r2 = self.node(1).received(src=self.target(1).link_local_ip(), lbda=lambda p: p.code==4)
        assertEqual(1, len(r2), "Expected to receive an ICMPv6 Destination Unreachable message")
