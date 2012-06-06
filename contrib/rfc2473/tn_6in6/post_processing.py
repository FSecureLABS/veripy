from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class HopLimitExceededAfterTunnelTestCase(ComplianceTestCase):
    """
    Hop Limit Exceeded After Tunnel

    Verifies a hop limit exceeded message is sent back through the tunnel
    when it occurs after tunneling.

    @private
    Source:         RFC 2473 Section 8.2
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel...")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()), hlim=0)/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that destination unreachable message was sent back to TN2.")
        r1 = self.router(1).received(iface=1, type=ICMPv6TimeExceeded)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Time Exceeded message")

        assertEqual(0x00, r1[0][ICMPv6TimeExceeded].code, "expected the Hop Limit Exceeded to have a Code field = 0")
        
        assertHasLayer(ICMPv6EchoRequest, r1[0], "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(self.seq(), r1[0][ICMPv6EchoRequest].seq, "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(ICMPv6EchoRequest, r1[0][ICMPv6TimeExceeded][2].__class__, "did not expect the error message to include the tunnel frame")


class UnreachableNodeAfterTunnelTestCase(ComplianceTestCase):
    """
    Unreachable Node After Tunnel

    Verifies an unreachable destination message is sent back through the tunnel
    when it occurs after tunneling.

    @private
    Source:         RFC 2473 Section 8.2
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel...")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                IPv6(src=str(self.node(2).global_ip()), dst="8000::1")/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that destination unreachable message was sent back to TN2.")
        r1 = self.router(1).received(iface=1, type=ICMPv6DestUnreach)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Destination Unreachable message")

        assertHasLayer(ICMPv6EchoRequest, r1[0], "expected the Destination Unreachable message to contain the original Echo Request")
        assertEqual(self.seq(), r1[0][ICMPv6EchoRequest].seq, "expected the Destination Unreachable message to contain the original Echo Request")
        assertEqual(ICMPv6EchoRequest, r1[0][ICMPv6DestUnreach][2].__class__, "did not expect the error message to include the tunnel frame")
        