from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class HopLimitDecrementedTestCase(ComplianceTestCase):
    """
    Nested Tunnels: Hop Limit Decremented

    Verifies that the hop limit on an already encapsulated IPv6 packet is
    decremented by 1 when it is sent through a 6in6 tunnel, within a 6in6
    tunnel.

    @private
    Source:         RFC 2473 Section 3.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).ip()), dst=str(self.node(2).global_ip()), hlim=64)/
                IPv6(src="8000::1", dst="8001::2", hlim=63)/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TR1")

        assertEqual(IPv6, r1[0][0].__class__, "expected an encapsulating IPv6 layer")
        assertEqual(IPv6, r1[0][1].__class__, "expected an encapsulated IPv6 layer")
        assertEqual(IPv6, r1[0][2].__class__, "expected a second encapsulated IPv6 layer")

        assertEqual(63, r1[0][1].hlim, "expected the Hop Limit of the original encapsulating packet to be decremented by 1")
        assertEqual(63, r1[0][2].hlim, "did not expect the Hop Limit of the original encapsulating packet to be decremented")


class EntryPointAddressTestCase(ComplianceTestCase):
    """
    Nested Tunnels: Entry Point Address

    Verifies that the source address on an IPv6-encapsulated packet is
    equal to the tunnel entry point address, within a 6in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).ip()), dst=str(self.node(2).global_ip()), hlim=64)/
                IPv6(src="8000::1", dst="8001::2", hlim=63)/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TR1")

        assertEqual(self.target(2).global_ip(), r1[0][0].src, "expected the Source Address of the encapsulating packet to be the tunnel entry point")


class EndPointAddressTestCase(ComplianceTestCase):
    """
    Nested Tunnels: End Point Address

    Verifies that the destination address on an IPv6-encapsulated packet is
    equal to the tunnel end point address, within a 6in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).ip()), dst=str(self.node(2).global_ip()), hlim=64)/
                IPv6(src="8000::1", dst="8001::2", hlim=63)/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TR1")

        assertEqual(self.router(1).global_ip(iface=1), r1[0][0].dst, "expected the Destination Address of the encapsulating packet to be the tunnel exit point")
        