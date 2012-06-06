from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UDPPortUnreachableTestCase(ComplianceTestCase):
    """
    Error Condition With Multicast Destination - UDP Port Unreachable
    
    Verify that a node properly handles the reception of an error condition
    caused by a packet with a Multicast Destination Address.


    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.10a

    """

    def run(self):
        assertFalse(self.ui.ask("Is the NUT listening on port 9000?", True), "cannot test, NUT is listening on port 9000")
        
        self.logger.info("Sending UDP packet to link multicast")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::1")/
                UDP(dport = 9000))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6DestUnreach)
        
        assertEqual(0, len(r1), "Expecting not to have received a reply")

        
class EchoRequestReassemblyTimeoutTestCase(ComplianceTestCase):
    """
    Error Condition With Multicast Destination - Echo Request Reassembly
    Timeout

    Verify that a node properly handles the reception of an error condition
    caused by a packet with a Multicast Destination Address.



    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.10b

    """
    
    def run(self):
        self.logger.info("Sending fragmented echo request to link multicast")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::1")/
                IPv6ExtHdrFragment(offset=0, m=1)/
                    ICMPv6EchoRequest())
        
        self.ui.wait(55)
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6TimeExceeded)
        
        assertEqual(0, len(r1), "Expecting not to have received a reply")
        