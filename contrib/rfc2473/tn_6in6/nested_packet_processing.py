from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class EncapsulatingHopLimitDecrementedWithIPv6EncapsulatedTestCase(ComplianceTestCase):
    """
    Nested Tunnels: Encapsulating Hop Limit Decremented With IPv6 Payload

    Verifies that an intermediate node decrements the hop limit of the
    encapsulating packet, not the hop limit of the encapsulated IPv6 packet.

    @private
    Source:         RFC 2473 Section 3.2
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), hlim=30)/
                IPv6(src="8000::1", dst="8001::2", hlim=63)/
                    IPv6(src="9000::1", dst="9001::1", hlim=62)/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TR1")

        assertEqual(IPv6, r1[0][0].__class__, "expected an encapsulating IPv6 layer")
        assertEqual(IPv6, r1[0][1].__class__, "expected an encapsulated IPv6 layer")
        assertEqual(IPv6, r1[0][2].__class__, "expected a second encapsulated IPv6 layer")
        assertNotEqual(IPv6, r1[0][3].__class__, "did not expect a third layer of encapsulation")

        assertEqual(29, r1[0][0].hlim, "expected the Hop Limit of the outermost header to be decremented by 1")
        assertEqual(63, r1[0][1].hlim, "did not expect the Hop Limit of the second IPv6 header to be decremented")
        assertEqual(62, r1[0][2].hlim, "did not expect the Hop Limit of the third IPv6 header to be decremented")


class EncapsulatingHopLimitDecrementedWithIPv4EncapsulatedTestCase(ComplianceTestCase):
    """
    Nested Tunnels: Encapsulating Hop Limit Decremented With IPv4 Payload

    Verifies that an intermediate node decrements the hop limit of the
    encapsulating packet, not the TTL of the encapsulated IPv4 packet.

    @private
    Source:         RFC 2473 Section 3.2
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), hlim=30)/
                IPv6(src="8000::1", dst="8001::2", hlim=63, nh=4)/
                    IP(src="192.168.200.97", dst="192.168.201.98", ttl=62)/
                        ICMP(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).iface(1).received(type=ICMP)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TR1")

        assertEqual(IPv6, r1[0][0].__class__, "expected an encapsulating IPv6 layer")
        assertEqual(IPv6, r1[0][1].__class__, "expected an encapsulated IPv6 layer")
        assertEqual(IP, r1[0][2].__class__, "expected an encapsulated IP layer")
        assertNotEqual(IP, r1[0][3].__class__, "did not expect a third layer of encapsulation")
        assertNotEqual(IPv6, r1[0][3].__class__, "did not expect a third layer of encapsulation")

        assertEqual(29, r1[0][0].hlim, "expected the Hop Limit of the outermost header to be decremented by 1")
        assertEqual(63, r1[0][1].hlim, "did not expect the Hop Limit of the second IPv6 header to be decremented")
        assertEqual(62, r1[0][2].ttl, "did not expect the TTL of the IPv4 header to be decremented")
        