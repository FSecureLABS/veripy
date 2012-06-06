from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ReceivingMTUBelowIPv6MinimumHelper(ComplianceTestCase):

    def set_up(self):
        raise Exception("must override #set_up() to define #mtu")

    def run(self):
        self.logger.info("Forwarding ICMPv6 echo request from TN2 to NUT...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1280, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertNotFragmented(r1[0])

        self.logger.info("Sending Packet Too Big message to NUT for Echo Reply with MTU set to %d" % (self.mtu))
        self.router(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=56)/
                    Raw(load=r1[0].build()[:(56-48)]), iface=1)

        self.node(2).clear_received()
        self.logger.info("Forwarding another ICMPv6 echo request from TN2 to NUT...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1280, True))

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertHasLayer(IPv6ExtHdrFragment, r2[0], "expected the Echo Reply to contain a fragment header")


class MTUEqualTo56TestCase(ReceivingMTUBelowIPv6MinimumHelper):
    """
    Receiving MTU Below IPv6 Minimum Link MTU - MTU equal to 56

    Verifies that a node does not reduce its estimate of the Path MTU below the
    IPv6 minimum link MTU.

    @private
    Source:         IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.6a)
    """

    restart_uut = True

    def set_up(self):
        self.mtu = 56


class MTUEqualTo1279TestCase(ReceivingMTUBelowIPv6MinimumHelper):
    """
    Receiving MTU Below IPv6 Minimum Link MTU - MTU equal to 1279

    Verifies that a node does not reduce its estimate of the Path MTU below the
    IPv6 minimum link MTU.

    @private
    Source:         IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.6b)
    """

    restart_uut = True

    def set_up(self):
        self.mtu = 1279
