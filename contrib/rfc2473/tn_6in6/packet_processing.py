from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class EncapsulatingHopLimitDecrementedTestCase(ComplianceTestCase):
    """
    Encapsulating Hop Limit Decremented (6in6)

    Verifies that an intermediate node decrements the hop limit of the
    encapsulating packet, not the hop limit of the encapsulated IPv6 packet.

    @private
    Source:         RFC 2473 Section 3.2
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN1, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), hlim=30)/
                IPv6(src="8000::1", dst="8001::1", hlim=60)/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TR1")

        assertEqual(IPv6, r1[0][0].__class__, "expected an encapsulating IPv6 layer")
        assertEqual(IPv6, r1[0][1].__class__, "expected an encapsulated IPv6 layer")
        assertNotEqual(IPv6, r1[0][2].__class__, "did not expect a second layer of encapsulation")

        assertEqual(29, r1[0][0].hlim, "expected the Hop Limit of the encapsulating packet to be decremented")
        assertEqual(60, r1[0][1].hlim, "did not expect the Hop Limit of the encapsulated packet to be decremented")


class HopLimitExceededWithinTunnelTestCase(ComplianceTestCase):
    """
    Hop Limit Exceeded Within Tunnel

    Verifies a hop limit exceeded message is handled correctly when it occurs
    within a tunnel.

    @private
    Source:         RFC 2473 Section 8.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for the ICMPv6 Echo Request forwarded to TR1...")
        r1 = self.router(1).received(iface=1, seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected the Echo Request to be tunnelled to TR1")

        self.logger.info("Sending Hop Limit Exceeded message from TR1 to RUT...")
        self.router(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6TimeExceeded(code=0)/
                    r1[0], iface=1)

        self.logger.info("Checking that the RUT has sent an ICMPv6 Unreachable Node error to TN4...")
        r2 = self.node(4).received(type=ICMPv6DestUnreach)
        assertEqual(1, len(r2), "expected the RUT to send an ICMPv6 Unreachable Node error to TN4")
        assertEqual(0x03, r2[0][ICMPv6DestUnreach].code, "expected the Unreachable Node to have a Code field = 3 (Address Unreachable)")

        assertHasLayer(ICMPv6EchoRequest, r2[0], "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(self.seq(), r2[0][ICMPv6EchoRequest].seq, "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(ICMPv6EchoRequest, r2[0][ICMPv6DestUnreach][2].__class__, "did not expect the error message to include the tunnel frame")


class UnreachableNodeWithinTunnelTestCase(ComplianceTestCase):
    """
    Unreachable Node Within Tunnel

    Verifies an unreachable node message is handled correctly when it occurs
    within a tunnel.

    @private
    Source:         RFC 2473 Section 8.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for the ICMPv6 Echo Request forwarded to TR1...")
        r1 = self.router(1).received(iface=1, seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected the Echo Request to be tunnelled to TR1")

        self.logger.info("Sending Unreachable Node message from TR1 to RUT...")
        self.router(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6DestUnreach()/
                    r1[0], iface=1)

        self.logger.info("Checking that the RUT has sent an ICMPv6 Unreachable Node error to TN4...")
        r2 = self.node(4).received(type=ICMPv6DestUnreach)
        assertEqual(1, len(r2), "expected the RUT to send an ICMPv6 Unreachable Node error to TN4")
        assertEqual(0x03, r2[0][ICMPv6DestUnreach].code, "expected the Unreachable Node to have a Code field = 3 (Address Unreachable)")

        assertHasLayer(ICMPv6EchoRequest, r2[0], "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(self.seq(), r2[0][ICMPv6EchoRequest].seq, "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(ICMPv6EchoRequest, r2[0][ICMPv6DestUnreach][2].__class__, "did not expect the error message to include the tunnel frame")


class PacketTooBigWithinTunnelTestCase(ComplianceTestCase):
    """
    Packet Too Big Within Tunnel

    Verifies a packet too big message is handled correctly when it occurs
    within a tunnel.

    @private
    Source:         RFC 2473 Section 8.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            util.pad(IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()), 1360, True))

        self.logger.info("Checking for the ICMPv6 Echo Request forwarded to TR1...")
        r1 = self.router(1).received(iface=1, seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected the Echo Request to be tunnelled to TR1")

        self.logger.info("Sending packet too big message from TR1 to RUT.")
        self.node(1).send((
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6PacketTooBig(mtu=1280)/
                    r1[0])[0:1280])

        self.logger.info("Checking that RUT has forwarded a Packet Too Big message to TN4...")
        r2 = self.node(4).received(type=ICMPv6PacketTooBig)
        assertEqual(1, len(r2), "expected the RUT to forward a Packet Too Big message to TN4")
        assertEqual(0x00, r2[0][ICMPv6PacketTooBig].code, "expected the Unreachable Node to have a Code field = 0")

        assertHasLayer(ICMPv6EchoRequest, r2[0], "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(self.seq(), r2[0][ICMPv6EchoRequest].seq, "expected the Hop Limit Exceeded message to contain the original Echo Request")
        assertEqual(ICMPv6EchoRequest, r2[0][ICMPv6PacketTooBig][2].__class__, "did not expect the error message to include the tunnel frame")
        