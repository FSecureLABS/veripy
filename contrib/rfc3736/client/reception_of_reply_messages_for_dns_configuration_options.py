from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class DNSRecursiveNameServerOptionTestCase(DHCPv6Helper):
    """
    DNS Recursive Name Server Option
    
    Verify that a client properly handles the reception of Reply messages for DNS
    configuration options after initiating an exchange.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.6)
    """
    
    def run(self):
    	q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        self.logger.info("Building a DHCPv6 Reply message...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], pref=False)

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=q.dport, dport=q.sport)/p)

        self.confirm_dns(self.node(3), self.target(1))


class DomainSearchListOptionTestCase(DHCPv6Helper):
    """
    Domain Search List Option
    
    Verify that a client properly handles the reception of Reply messages for DNS
    configuration options after initiating an exchange.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.6)
    """
    
    def run(self):
    	q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        self.logger.info("Building a DHCPv6 Reply message...")
        p = self.build_dhcpv6_reply(q, self.node(1), self.target(1), ias=False, dns_servers=[str(self.node(3).global_ip())], dns_domains=["example.com"], pref=False)

        self.logger.info("Sending the DHCPv6 Reply message...")
        self.node(1).send(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/UDP(sport=q.dport, dport=q.sport)/p)

        r = self.confirm_dns(self.node(3), self.target(1))
        
        assertEqual("dhcpv6.test.example.com.", r[DNSQR].qname.lower(), "expected the DNS query to be for dhcpv6.test.example.com")
        