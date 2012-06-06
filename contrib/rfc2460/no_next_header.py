from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class NoNextHeaderTestCase(ComplianceTestCase):
    """
    No Next Header after IPv6 Header
    
    Verifies proper behavior of a node when it encounters a Next Header
    value of 59 (no next header).
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.6a)
    """
    
    def run(self):
        self.logger.info("Sending an ICMP echo request, with Next Header of 59.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=59)/ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(0, len(r1), "did not expect to receive a response to an ICMP Echo Request with no next header")


class RUTForwardsNoNextHeader(ComplianceTestCase):
    """
    No Next Header after IPv6 Header - RUT Forwards No Next Header

    Verifies proper behavior of a node when it encounters a Next Header
    value of 59 (no next header).

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.6b)
    """

    def run(self):
        p = IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=59)/ICMPv6EchoRequest(seq=self.next_seq())

        self.logger.debug("Sending ICMPv6 echo-request, with Next Header = 59 (no next header)")
        self.node(4).send(p)

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected the Echo Request to be forwarded (seq: %d)" % (self.seq()))

        assertEqual(p.getlayer(ICMPv6EchoRequest), r1[0].getlayer(ICMPv6EchoRequest))
