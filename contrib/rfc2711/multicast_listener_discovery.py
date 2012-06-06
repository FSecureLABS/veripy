from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class MulticastListenerDiscoveryTestCase(ComplianceTestCase):
    """
    Router Alert - Multicast Listener Discovery Protocol
    
    Verify that a router observes the router alert header and carries out
    required processing on packet.
    
    @private
    Test Procedure:     1) TN1 sends an ICMPv6 Echo Request to the multicast
	                   group ff02::3.
	                2) Observe the packets sent by the RUT.
	                3) TN4 sends a MLD Report for the multicast group
	                   ff02::3.
	                4) TN1 sends an ICMPv6 Echo Request to the multicast
	                   group ff02::3.
	                5) Observe the packets sent by the RUT.
	                6) TN4 sends an ICMPv6 Echo Reply to TN1.
	                7) Observe the packets sent by the RUT.

    Expected Result:    2) The RUT should not forward the Echo Request to TN4.
	                5) The RUT should forward the Echo Request to TN4.
	                7) TN4 should send an ICMPv6 Echo Reply to TN1, using
	                   one of its IP addresses.

    Possible Problems:  The RUT may not support MLD.
    """

    def run(self):
        self.logger.info("Sending an Echo Request from TN1 to the multicast group ff02::3...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::3")/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a forwarded request...")
        r1 = self.node(4).received(src=self.node(1).global_ip(), dst="ff02::3", seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expect the RUT to forward the Echo Request to TN4")

        self.logger.info("Sending an MLD Report from TN4 for the group ff02::3...")
        self.node(4).send( \
            IPv6(src=str(self.node(4).link_local_ip()), dst="ff02::3", hlim=1)/
                IPv6ExtHdrHopByHop(options=[RouterAlert(value=1)])/
                    ICMPv6MLReport(mladdr="ff02::3"))
        self.logger.info("TN4 should be subscribed to the multicast group ff02::3.")
        
        self.logger.info("Sending an Echo Request from TN1 to the multicast group ff02::3...")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::3")/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a forwarded request...")
        r1 = self.node(4).received(src=self.node(1).global_ip(), dst="ff02::3", seq=self.seq(), type=ICMPv6EchoRequest)
        
        assertEqual(1, len(r1), "expected the RUT to forward the Echo Request to TN4")
        
        self.logger.info("Sending an Echo Reply from TN4 to TN1...")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()))/
                ICMPv6EchoReply(seq=r1[0].getlayer(ICMPv6EchoRequest).seq))
        
        self.logger.info("Checking for a forwarded reply...")
        r2 = self.node(1).received(src=self.node(4).global_ip(), seq=r1[0].getlayer(ICMPv6EchoRequest).seq, type=ICMPv6EchoReply)

        assertEqual(1, len(r2), "expected the RUT to forward the Echo Reply to TN1")
        