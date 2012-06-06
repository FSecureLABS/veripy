from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ReducePMTUOnLinkLinkLocalTestCase(ComplianceTestCase):
    """
    Reduce PMTU On-link - Link-Local address

    Verifies that a node properly processes a Packet Too Big message indicating
    a reduction in Path MTU for an on-link destination

    @private
    Source:         IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.4)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Transmitting ICMPv6 echo request from TR1 to NUT")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive a ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertNotFragmented(r1[0])
        
        self.logger.info("Sending Packet Too Big message to NUT for Echo Reply")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6PacketTooBig(mtu=1280)/
                    Raw(load=r1[0].build()[:(1280-48)]))

        self.node(1).clear_received()
        self.logger.info("Transmitting another ICMPv6 echo request (but fragmented) from TR1 to NUT")
        for p in fragment6(util.pad(IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/ICMPv6EchoRequest(seq=self.next_seq()), 1500, True), 1280):
            self.node(1).send(p)
        
        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r2[0], self.node(1).received(), count=2, size=1280, reassemble_to=1500)


class ReducePMTUOnLinkGlobalTestCase(ComplianceTestCase):
    """
    Reduce PMTU On-link - Global address

    Verifies that a node properly processes a Packet Too Big message indicating
    a reduction in Path MTU for an on-link destination

    @private
    Source:         IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.4)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Transmitting ICMPv6 echo request from TR1 to NUT")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive a ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        self.logger.info("Sending Packet Too Big message to NUT for Echo Reply")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1280)/
                    Raw(load=r1[0].build()[:(1280-48)]))

        self.node(1).clear_received()
        self.logger.info("Transmitting another ICMPv6 echo request (but fragmented) from TR1 to NUT")
        for p in fragment6(util.pad(IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/ICMPv6EchoRequest(seq=self.next_seq()), 1500, True), 1280):
            self.node(1).send(p)

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r2[0], self.node(1).received(), count=2, size=1280, reassemble_to=1500)
        