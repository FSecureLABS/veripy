from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class NoNextHeaderAfterExtensionHeaderEndNodeTestCase(ComplianceTestCase):
    """
    No Next Header After Extension Header
    
    Verify proper behavior of a node when it encounters a Next Header value
    of 59 (no next header).
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.2a)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet with an extension header that has a Next Header of 59.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=60)/
                IPv6ExtHdrDestOpt(nh=59, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(0, len(r1), "did not expect to receive a reply")


class NoNextHeaderAfterExtensionHeaderIntermediateNodeTestCase(ComplianceTestCase):
    """
    No Next Header After Extension Header

    Verify proper behavior of a router when it encounters a Next Header value
    of 59 (no next header).

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.2b)
    """

    def run(self):
        p = IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=60)/\
                IPv6ExtHdrDestOpt(nh=59, len=0, options=[PadN(otype='PadN', optlen=4)])/\
                    ICMPv6EchoRequest(seq=self.next_seq())
                    
        self.logger.info("Sending an IPv6 packet with an extension header that has a Next Header of 59.")
        self.node(4).send(p)
                    
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected the Echo Request to be forwarded (seq: %d)" % (self.seq()))
        
        assertEqual(p.getlayer(ICMPv6EchoRequest), r1[0].getlayer(ICMPv6EchoRequest))
