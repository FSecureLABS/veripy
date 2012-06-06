from contrib.rfc3736.builder import *
from contrib.rfc3736.constants import *
from contrib.rfc3736.dhcpv6 import DHCPv6Helper
from scapy.all import *
from veripy.assertions import *


class ReliabilityOfDHCPv6RetransmissionTestCase(DHCPv6Helper):
    """
    Reliability Of DHCPv6 Retransmission
    
    Verify that a client properly transmits Information Request messages.
    
    @private
    Source:         IPv6 Ready DHCPv6 Interoperability Test Suite (Section 7.1.5)
    """
    
    def run(self):
    	q = self.restart_and_wait_for_information_request(self.node(1), self.target(1))

        self.node(1).clear_received()
        self.logger.info("Expecting a second Information Request to be sent...")
        p = self.wait_for_information_request(self.node(1), self.target(1), timeout=30)
        