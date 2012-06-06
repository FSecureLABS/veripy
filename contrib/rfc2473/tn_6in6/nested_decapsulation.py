from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class AllEncapsulatedOptionsRemovedTestCase(ComplianceTestCase):
    """
    Nested Tunnels: All Encapsulated Options Removed

    Verifies that all of the options on the encapsulating IPv6 packet are removed
    when an encapsulated packet leaves a 6in6 tunnel (and undergoes decapsulation),
    while inside another 6in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from 8000::1 to 8000::2, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                IPv6ExtHdrHopByHop()/
                IPv6ExtHdrDestOpt()/
                    IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()))/
                        IPv6ExtHdrHopByHop()/
                        IPv6ExtHdrDestOpt()/
                            IPv6(src="8000::1", dst="8001::2")/
                                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that no options remain on decapsulated packet.")
        r1 = self.node(4).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be forwarded to TN4")
        
        assertEqual(IPv6, r1[0][0].__class__, "expected the encapsulated IPv6 layer")
        assertEqual(IPv6ExtHdrHopByHop, r1[0][1].__class__, "expected the encapsulating packet HbH options to persist")
        assertEqual(IPv6ExtHdrDestOpt, r1[0][3].__class__, "expected the encapsulating packet HbH options to persist")
        assertEqual(IPv6, r1[0][5].__class__, "expected the original IPv6 layer")
        assertEqual(ICMPv6EchoRequest, r1[0][6].__class__, "expected ICMPv6 Echo Request")


class NextHeaderIsIPv6WithEncapsulatedIPv6HeaderTestCase(ComplianceTestCase):
    """
    Nested Tunnels: Next Header Is IPv6 With Encapsulated IPv6 Header

    Verifies an IPv6 encapsulating header with a next header of IPv6
    is correctly processed with an encapsulated IPv6 packet, within a
    6in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from 8000::1 to 8000::2, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()))/
                    IPv6(src="8000::1", dst="8001::2")/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a decapsulated packet...")
        r1 = self.node(4).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected a packet to be forwarded to TN4")


class NextHeaderIsIPv4WithEncapsulatedIPv6HeaderTestCase(ComplianceTestCase):
    """
    Nested Tunnels: Next Header Is IPv4 With Encapsulated IPv6 Header

    Verifies an IPv6 encapsulating header with a next header of IPv4
    is correctly processed with an encapsulated IPv6 packet, within a
    6in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from 8000::1 to 8000::2, via 6in6 tunnel.")
        self.router(1).iface(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()), nh=4)/
                IPv6(src=str(self.node(2).global_ip()), dst=str(self.node(4).global_ip()))/
                    IPv6(src="8000::1", dst="8001::2")/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a decapsulated packet...")
        r1 = self.node(4).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(0, len(r1), "did not expect a packet to be forwarded to TN4")
