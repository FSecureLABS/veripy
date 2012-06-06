from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouterAdvertisementWithMTUOptionTestCase(ComplianceTestCase):
    """
    Router Advertisement with MTU Option

    Verifies that a host properly processes a Router Advertisement with an MTU
    option and reduces its estimate.

    @private
    Source          IPv6 Ready Logo Program Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.4.1.8)
    """

    restart_uut = True

    def run(self):
        self.logger.info("Forwarding ICMPv6 echo request from TN2 to NUT...")
        self.node(2).send( \
            util.pad( \
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True))

        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertNotFragmented(r1[0])
        
        self.logger.info("Sending Router Advertisement from TR1, with the MTU option set to 1280")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff01::2")/
                ICMPv6ND_RA()/
                    ICMPv6NDOptMTU(mtu=1280), iface=1)

        self.logger.info("Forwarding another ICMPv6 echo request from TN2 to NUT...")
        for f in fragment6(util.pad(IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/ICMPv6EchoRequest(seq=self.next_seq()), 1500, True), 1280):
            self.node(2).send(f)

        self.ui.wait(5)
        self.logger.info("Checking for replies...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))
        assertFragmented(r2[0], self.node(1).received(), count=2, size=1280, reassemble_to=1500)
        