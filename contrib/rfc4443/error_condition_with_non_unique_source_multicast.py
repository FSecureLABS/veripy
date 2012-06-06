from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase
from veripy import util


class NonUniqueSourceMulticastUDPPortUnreachableTestCase(ComplianceTestCase):
    """
    Error Condition With Non-Unique Source - Multicast - UDP Port Unreachable
    
    Verify that a node properly handles the reception of an error condition
    caused by a packet with a source address that does not uniquely identify
    a single node.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.12a)

    """
    def run(self):
        assertFalse(self.ui.ask("Is the NUT listening on port 9000?", True), "cannot test, NUT is listening on port 9000")
        
        self.logger.info("Sending UDP packet to nut")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip().solicited_node()), dst=str(self.target(1).global_ip()))/
                UDP(dport = 9000))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6DestUnreach)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Destination Unreachable message")


class NonUniqueSourceMulticastEchoRequestTooBigTestCase(ComplianceTestCase):
    """
    Error Condition With Non-Unique Source - Multicast - Echo Request Too
    Big

    Verify that a node properly handles the reception of an error condition
    caused by a packet with a source address that does not uniquely identify
    a single node.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.12b)
    """

    def run(self):
        # TODO: configure the RUT's link MTU on link C to be 1280, the minimum
        #       IPv6 MTU
        self.logger.info("Sending large echo request to nut")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip().solicited_node()), dst=str(self.node(4).global_ip()))/
                    ICMPv6EchoRequest(), 1500, True, False))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6PacketTooBig)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Packet Too Big message")


class NonUniqueSourceMulticastReassemblyTimeoutTestCase(ComplianceTestCase):
    """
    Error Condition With Non-Unique Source - Multicast - Echo Request
    Reassembly Timeout
    
    Verify that a node properly handles the reception of an error condition
    caused by a packet with a source address that does not uniquely identify
    a single node.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.12c)
    """

    def run(self):
        self.logger.info("Sending large echo request to nut")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip().solicited_node()), dst=str(self.target(1).global_ip()))/
                    IPv6ExtHdrFragment(offset=0, m=1)/
                        ICMPv6EchoRequest(seq=self.next_seq()), 1500, True, False))
        
        self.ui.wait(55)
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6TimeExceeded)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Time Exceeded message")
                
                
class NonUniqueSourceMulticastInvalidDestinationOptionsTestCase(ComplianceTestCase):
    """
    Error Condition With Non-Unique Source - Multicast - Echo Request
    with Unknown Option in Destination Options
    
    Verify that a node properly handles the reception of an error condition
    caused by a packet with a source address that does not uniquely identify
    a single node.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.12d)
    """

    def run(self):
        self.logger.info("Sending invalid destination options to nut")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip().solicited_node()), dst=str(self.target(1).global_ip()))/
                    IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=135,optlen=4)])/
                        ICMPv6EchoRequest(seq=self.next_seq()), 1500, True, False))

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(type=ICMPv6ParamProblem)
        
        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Parameter Problem message")
