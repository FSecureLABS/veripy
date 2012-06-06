from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class ClientMessageFormatTestCase(DHCPv6Helper):
    """
    Client Message Format
    
    Verify that a client transmits a DHCPv6 message with the proper format.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.3)
    """
    
    def run(self):
        q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        assertNotEqual(0, q.trid, "did not expect the DHCPv6 Transaction ID to be 0")
        