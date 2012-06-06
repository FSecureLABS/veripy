from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ReducePMTUOffLinkTestCase(ComplianceTestCase):
    """
    Reduce PMTU Off-link
    
    Verifies that a node properly reduces its estimate of the MTU for a path
    due to a Packet Too big message indicating a reduction in the Path MTU for
    a global destination.

    @private
    Source          IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.5)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Forwarding ICMPv6 echo request from TN2 to NUT from TR1")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertNotFragmented(r1[0])
        
        self.logger.info("Sending a Packet Too Big message to NUT...")
        self.router(1).send( \
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1400)/
                    Raw(load=r1[0].build()[:(1400-48)]), iface=1)

        self.node(2).clear_received()
        self.logger.info("Forwarding another ICMPv6 echo request from TN2 to NUT...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r2[0], self.node(2).received(), count=2, size=1400, reassemble_to=1500)

        self.logger.info("Sending Packet Too Big message to NUT...")
        self.router(1).send( \
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1280)/
                    Raw(load=r2[0].build()[:(1280-48)]), iface=1)

        self.node(2).clear_received()
        self.logger.info("Forwarding another ICMPv6 echo request from TN2 to NUT...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r3 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r3[0], self.node(2).received(), count=2, size=1280, reassemble_to=1500)
        