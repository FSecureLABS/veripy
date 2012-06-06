from scapy.all import *
from veripy.assertions import *
from veripy import util
from veripy.models import ComplianceTestCase

class PayloadLengthHelper(ComplianceTestCase):

    def set_up(self):
        raise Exception('must override set_up() to define #plen')
    
    def run(self):
        self.logger.info("Sending ICMP echo request, with a Payload Length of %s." % self.plen)
        self.node(1).send(util.pad(IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/ICMPv6EchoRequest(seq=self.next_seq()), self.plen - 8, False))

        self.logger.info("Checking for a reply...")
	r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        
        assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply, got %d (seq: %d)" % (len(r1), self.seq()))

class PayloadLengthOddTestCase(PayloadLengthHelper):
	"""
	Payload Length (Payload Length Odd)

	Verifies that a node properly processes the Payload Length field of
	received packets.

	@private
	Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.5a)
	"""
	def set_up(self):
            self.plen = 51


class RUTForwardsPayloadLengthOddTestCase(ComplianceTestCase):
    """
    Payload Length - RUT forwards Payload Length Odd

    Verify that a router properly processes the Payload Length field

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.5b)
    """

    def run(self):
        self.logger.debug("Sending ICMPv6 echo-request, with Payload Length = 0x33")
        self.node(4).send( \
            util.pad( \
                IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), plen=0x33, nh=58)/
                    ICMPv6EchoRequest(seq=self.next_seq()), 51 - 8, False))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to receive a ICMPv6 Echo Request (seq: %d)" % (self.seq()))


class PayloadLengthEvenTestCase(PayloadLengthHelper):
	"""
	Payload Length (Payload Length Even)

	Verifies that a node properly processes the Payload Length field of
	received packets.

	@private
	Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.1.5c)
	"""
	def set_up(self):
            self.plen = 50
