from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class EncapsulatingHopLimitDecrementedWithIPv4EncapsulatedTestCase(ComplianceTestCase):
    """
    Encapsulating Hop Limit Decremented With IPv4 Encapsulated

    Verifies that an intermediate node decrements the hop limit of the encapsulating packet,
    not the TTL of the encapsulated IPv4 packet.

    @private
    Source:         RFC 2473 Section 3.2
    """

    def run(self):
        self.logger.info("Sending ICMP echo request from TN4 to TN2, via 4in6 tunnel.")
        self.node(4).send(
            IPv6(nh=4, src=str(self.node(4).global_ip()), dst=str(self.router(1).global_ip(iface=1)), hlim=30)/
                IP(src=str(self.node(4).ip(type='v4')), dst=str(self.node(2).ip(type='v4')), ttl=60)/
                    ICMP(id=0x2474, seq=1))

        self.logger.info("Checking to see if the packet was forwarded...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expecting the ICMP request to be forwarded through TR1")

        assertEqual(29, r1[0][IPv6].hlim, "expected the Hop Limit of the encapsulating packet to be decremented")
        assertEqual(60, r1[0][IP].ttl, "did not expect the TTL of the encapsulated packet to be decremented")



class HopLimitExceededWithinTunnelTestCase(ComplianceTestCase):
    """
    Hop Limit Exceeded Within Tunnel IPv4

    Verifies a hop limit exceeded message is handled correctly when it occurs
    within a 4in6 tunnel.

    @private
    Source:         RFC 2473 Section 8.1
    """

    def run(self):
        self.logger.info("Sending an ICMP echo request from TN4 to TN2, via 4in6 tunnel.")
        self.node(4).send(
            IP(src=str(self.node(4).ip(type="v4")), dst=str(self.node(2).ip(type="v4")), ttl=60, flags=2)/
                ICMP(seq=self.next_seq()))

        self.logger.info("Checking to see if the packet was forwarded...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expecting the ICMP request to be forwarded through TR1")

        self.logger.info("Sending Hop Limit Exceeded message from TR1 to RUT...")
        self.router(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(2).global_ip()))/
                ICMPv6TimeExceeded(code=0)/
                    r1[0], iface=1)

        self.logger.info("Checking that the RUT forwarded an ICMP Time Exceeded packet to TN4...")
        r2 = self.node(4).received(type=ICMP)
        assertEqual(1, len(r2), "expected an ICMP packet to be delivered to TN4")

        assertEqual(11, r2[0][ICMP].type, "expected the ICMP packet to be type 11 (time-exceeded)")
        assertEqual(0, r2[0][ICMP].code, "expected the ICMP packet to be code 0 (ttl-zero-during-transit)")
        assertHasLayer(ICMPerror, r2[0], "expected the ICMP packet to contain the original message as the error")


class UnreachableNodeWithinTunnelIPv4TestCase(ComplianceTestCase):
    """
    Unreachable Node Within Tunnel IPv4

    Verifies an unreachable node message is handled correctly when it occurs
    within a 4in6 tunnel.

    @private
    Source:         RFC 2473 Section 8.1
    """

    def run(self):
        self.logger.info("Sending an ICMP echo request from TN4 to TN2, via 4in6 tunnel.")
        self.node(4).send(
            IP(src=str(self.node(4).ip(type="v4")), dst=str(self.node(2).ip(type="v4")), ttl=60, flags=2)/
                ICMP(seq=self.next_seq()))

        self.logger.info("Checking to see if the packet was forwarded...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expecting the ICMP request to be forwarded through TR1")

        self.logger.info("Sending Hop Limit Exceeded message from TR1 to RUT...")
        self.node(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(2).global_ip()))/
                ICMPv6DestUnreach()/
                    r1[0])

        self.logger.info("Checking that the RUT forwarded an ICMP Time Exceeded packet to TN4...")
        r2 = self.node(4).received(type=ICMP)
        assertEqual(1, len(r2), "expected an ICMP packet to be delivered to TN4")

        assertEqual(3, r2[0][ICMP].type, "expected the ICMP packet to be type 3 (dest-unreach)")
        assertEqual(1, r2[0][ICMP].code, "expected the ICMP packet to be code 1 (host-unreachable)")
        assertHasLayer(ICMPerror, r2[0], "expected the ICMP packet to contain the original message as the error")


class PacketTooBigWithinTunnelIPv4TestCase(ComplianceTestCase):
    """
    Packet Too Big Within Tunnel IPv4

    Verifies a packet too big message is handled correctly when it occurs
    within a 4in6 tunnel.

    @private
    Source:         RFC 2473 Section 8.1
    """

    def run(self):
        self.logger.info("Sending an ICMP echo request from TN4 to TN2, via 4in6 tunnel.")
        self.node(4).send(
            util.pad(IP(src=str(self.node(4).ip(type="v4")), dst=str(self.node(2).ip(type="v4")), ttl=60, flags=2)/
                ICMP(seq=self.next_seq()), 1360, True))

        self.logger.info("Checking to see if the packet was forwarded...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expecting the ICMP request to be forwarded through TR1")

        self.logger.info("Sending Hop Limit Exceeded message from TR1 to RUT...")
        self.node(1).send(IPv6(
            (IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(2).global_ip()))/
                ICMPv6PacketTooBig(mtu=1280)/
                    r1[0]).build()[0:1280]))

        self.logger.info("Checking that the RUT forwarded an ICMP Time Exceeded packet to TN4...")
        r2 = self.node(4).received(type=ICMP)
        assertEqual(1, len(r2), "expected an ICMP packet to be delivered to TN4")

        assertEqual(3, r2[0][ICMP].type, "expected the ICMP packet to be type 3 (dest-unreach)")
        assertEqual(4, r2[0][ICMP].code, "expected the ICMP packet to be code 4 (fragmentation-needed)")
        assertHasLayer(ICMPerror, r2[0], "expected the ICMP packet to contain the original message as the error")
        