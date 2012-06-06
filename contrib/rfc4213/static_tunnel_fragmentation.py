from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class StaticTunnelFragmentationHelper(ComplianceTestCase):

    def send_fragments(self):
        self.logger.info("Sending ICMPv6 Echo Request fragments through IPv6-IPv4 tunnel.")
        u1, u2, u3 = fragment6( \
                        util.pad( \
                            IPv6(src=str(self.node(1).ip(type="6in4")), dst=str(self.target(1).ip(type="6in4")))/
                                IPv6ExtHdrFragment()/
                                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True), 600)
        e1, e2, e3 = map(lambda f: IP(src=str(self.node(1).ip(type="v4")), dst=str(self.target(1).ip(type="v4")))/f, [u1, u2, u3])
        
        self.node(1).send(e1)
        self.node(1).send(e2)
        self.node(1).send(e3)


class ReassemblesTo1500TestCase(StaticTunnelFragmentationHelper):
    """
    Static Tunnel Fragmentation - Reassembles to 1500
    
    Verifies that a node performing encapsulation can reassemble a fragmented
    IPv6 packet as large as 1500 bytes.
    
    @private
    Source:         RFC 4213 Page 8 Paragraph 2
    """

    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")

        self.send_fragments()
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).ip(type="v4"))

        assertEqual(3, len(r1), "expected to receive an ICMPv6 Echo Reply")

        p = util.reassemble(r1, ICMPv6EchoReply)
        
        assertEqual(1500, len(p), "expected the fragmented reply to reassembly to 1500 octets, god %d" % (len(p)))
        assertEqual('A'*1452, p.getlayer(ICMPv6EchoReply).data, "expected 0x414141... in the data of the ICMPv6 Echo Reply")
	

class DontFragmentBitNotSetTestCase(StaticTunnelFragmentationHelper):
    """
    Static Tunnel Fragmentation - Don't Fragment Bit Not Set
    
    Verifies that a node performing encapsulation does not set the Don't
    Fragment bit in an encapsulating IPv4 header.
    
    @private
    Source:         RFC 4213 Page 8 Paragraph 7
    """

    def run(self):
        if len(self.target(1).ip(type='6in4', offset='*')) == 0 or len(self.node(1).ip(type='6in4', offset='*')) == 0:
            fail("Cannot Test. This test requires the UUT and TN1 to have IPv4-mapped addresses.")
            
        self.send_fragments()

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).ip(type="v4"))

        assertEqual(3, len(r1), "expected to receive an ICMPv6 Echo Reply")
        for r in r1:
            assertEqual(0, r.getlayer(IP).flags, "did not expect the Don't Fragment bit to be set")
        