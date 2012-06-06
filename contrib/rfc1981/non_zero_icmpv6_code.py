from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class NonZeroICMPv6CodeTestCase(ComplianceTestCase):
    """
    Non-zero ICMPv6 Code
    
    Verifies that a node properly process a Packet Too Big message with a
    non-zero ICMPv6 Code field.

    @private:
    Source:         IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.3)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Forwarding ICMPv6 echo request from TN2 to NUT")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive a ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertNotFragmented(r1[0])

        self.logger.info("Sending Packet Too Big message to NUT for Echo Reply for TN2")
        self.node(2).send( \
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1280, code=0xFF)/
                    Raw(load=r1[0].build()[:(1280-48)]))

        self.node(2).clear_received()
         
        self.logger.info("Forwarding ICMPv6 echo request from TN2 to NUT")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))
        
        self.logger.info("Checking for fragmented replies...")
        r2 = self.node(2).received(src=self.target(1).global_ip())

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r2[0], self.node(2).received(), count=2, size=1280, reassemble_to=1500)
        