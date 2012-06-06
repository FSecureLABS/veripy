from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UnrecognizedValueTestCase(ComplianceTestCase):
    """
    Router Alert - Unrecognized Option
    
    Verify that a router discards a router alert option, with an invalid
    option.
    
    @private
    Test Procedure:     1) TN4 sends an MLD Report for the multicast group
	                   ff02::4, with an invalid Router Alert option.
	                2) TN1 sends an ICMPv6 Echo Request to the multicast
	                   group.
	                3) Observe the packets forwarded by the RUT.
    
    Expected Result:    3) The RUT should silently discard the Echo Request.
    
    Possible Problems:  The RUT may not support MLD.
    """
    
    def run(self):
        self.logger.info("Sending an MLD Report from TN4 for the group ff02::4...")
        self.node(4).send( \
            IPv6(src=str(self.node(4).link_local_ip()), dst="ff02::4", hlim=1)/
                IPv6ExtHdrHopByHop(options=[RouterAlert(value=88)])/
                    ICMPv6MLReport(mladdr="ff02::4"))
        self.logger.info("TN2 should *not* be subscribed to the multicast group ff02::4.")
        
        self.logger.info("Sending an Echo Request from TN1 to ff02::4")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::4")/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a forwarded request...")
        r1 = self.node(4).received(src=self.node(1).global_ip(), dst="ff02::4", seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "expected to receive a forwarded ICMPv6 Echo Request")
        