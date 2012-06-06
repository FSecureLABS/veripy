from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class FlowLabelNonZeroTestCase(ComplianceTestCase):
    """
    Flow Label Non-Zero
    
    Verifies that a node properly processes the Flow Label field of received
    packets and generates a valid value in transmitted packets.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.3a)
    """
    
    def run(self):
        self.logger.info("Sending ICMP echo request, with a flow label of 0x34567.")
	self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), fl=214375)/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply, got %d (seq: %d)" % (len(r1), self.seq()))
        
        if r1[0].fl > 0:
            self.logger.info("Flow Label in reply was non-Zero.")
            
            self.ui.tell("Flow Label Non-Zero Test Case: the UUT responded with a Non-Zero flow label.")
            assertTrue(self.ui.ask("Does the UUT support a specific use of the Flow Label field?"), "expected to receive an ICMPv6EchoReply with a flow label of zero")
        else:
            assertTrue(True)

class FlowLabelNonZeroIntermediateNodeTestCase(ComplianceTestCase):
    """
    Flow Label Non-Zero - RUT forwards Non-Zero Flow Label
    
    Verify that a node properly processes the Flow Label field of received
    packets and generates a valid value in transmitted packets.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.4b)
    """
    
    def run(self):
        self.logger.info("Sending ICMP echo request, with a flow label of 0x34567.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()), fl=0x34567)/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a forwarded message...")
        r1 = self.node(4).received(src=self.node(1).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)
        
        assertEqual(1, len(r1), "expected the ICMPv6 Echo Request to be forwarded (seq: %d)" % (self.seq()))
        
        if self.ui.ask("Does the RUT support the use of the Flow Label field?"):
            assertTrue(True)
        else:
            assertEqual(0x34567, r1[0].fl, "expecting Flow Label of 0x34567")
            