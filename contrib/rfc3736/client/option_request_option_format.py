from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class DNSRecursiveNameServerOptionTestCase(DHCPv6Helper):
    """
    DNS Recursive Name Server Option
    
    Verify that a client transmits the correct Option Request Option format.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.4)
    """
    
    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        assertHasLayer(DHCP6OptOptReq, q, "expected the DHCPv6 Information Request to contain an Option Request Option")
        assertTrue(23 in q[DHCP6OptOptReq].reqopts, "expected the Option Request Option to include a DNS Recursive Name Server option")


class DomainSearchListOptionTestCase(DHCPv6Helper):
    """
    Domain Search List Option
    
    Verify that a client transmits the correct Option Request Option format.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.4)
    """
    
    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        assertHasLayer(DHCP6OptOptReq, q, "expected the DHCPv6 Information Request to contain an Option Request Option")
        assertTrue(24 in q[DHCP6OptOptReq].reqopts, "expected the Option Request Option to include a Domain Search List option")
        