from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class AllEncapsulatedOptionsRemovedTestCase(ComplianceTestCase):
    """
    All Encapsulated Options Removed

    Verifies that all of the options on the encapsulating IPv6 packet are removed
    when an encapsulated packet leaves a 6in6 tunnel (and undergoes decapsulation).

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                IPv6ExtHdrHopByHop()/
                IPv6ExtHdrDestOpt()/
                    IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()))/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.node(4).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TN4")

        assertEqual(IPv6, r1[0][0].__class__, "expected the encapsulated IPv6 layer")
        assertNotHasLayer(IPv6, r1[0][1], "did not expect an encapsulating IPv6 layer")

        self.logger.info("Checking that no options from the encapsulating packet remain...")
        assertNotHasLayer(IPv6ExtHdrDestOpt, r1[0], "expected the destination options extension header to be removed")
        assertNotHasLayer(IPv6ExtHdrHopByHop, r1[0], "expected the hop-by-hop options extension header to be removed")


class NextHeaderIsIPv6WithEncapsulatedIPv6HeaderTestCase(ComplianceTestCase):
    """
    Next Header Is IPv6 With Encapsulated IPv6 Header

    Verifies an IPv6 encapsulating header with a next header of IPv6
    is correctly processed with an encapsulated IPv6 packet.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                    IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()))/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.node(4).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be tunnelled to TN4")

        assertEqual(IPv6, r1[0][0].__class__, "expected the encapsulated IPv6 layer")
        assertNotHasLayer(IPv6, r1[0][1], "did not expect an encapsulating IPv6 layer")


class NextHeaderIsIPv4WithEncapsulatedIPv6HeaderTestCase(ComplianceTestCase):
    """
    Next Header Is IPv4 With Encapsulated IPv6 Header

    Verifies an IPv6 encapsulating header with a next header of IPv4
    is correctly processed with an encapsulated IPv6 packet.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()), nh=4)/
                    IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()))/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.node(4).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(0, len(r1), "did not expect a packet to be tunnelled to TN4")


class NextHeaderIsIPv6WithEncapsulatedIPv4HeaderTestCase(ComplianceTestCase):
    """
    Next Header Is IPv6 With Encapsulated IPv4 Header

    Verifies an IPv6 encapsulating header with a next header of IPv6
    is correctly processed with an encapsulated IPv4 packet.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()), nh=6)/
                    IP(src="192.168.200.97", dst="192.168.201.98")/
                        ICMP(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.node(4).received(type=ICMP)
        assertEqual(0, len(r1), "did not expect a packet to be tunnelled to TN4")
        