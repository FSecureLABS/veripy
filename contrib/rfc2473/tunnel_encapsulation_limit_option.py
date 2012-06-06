from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class TunnelEncapsulationLimitOptionOf0TestCase(ComplianceTestCase):
    """
    Tunnel Encapsulation Limit Option Of 0

    Verifies the tunnel encapsulation limit option is correctly processed
    when encapsulating a packet. 

    @private
    Source:         RFC 2473 Section 4.1.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optlen=1, optdata="\x00")])/
                    IPv6(src="8000::1", dst="8001::2")/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that the packet was not forwarded into the tunnel...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(0, len(r1), "did not expect the packet to be forwarded into the tunnel")

        self.logger.info("Checking that TN4 received a Parameter Problem message...")
        r2 = self.node(4).received(type=ICMPv6ParamProblem)
        assertEqual(1, len(r2), "expected the tunnel node to return a Parameter Problem message to TN4")
        
        assertEqual(0, r2[0].code, "expected the Parameter Problem message to have a Code field = 0")
        assertEqual(0x2c, r2[0].ptr, "expected the Parameter Problem message to have a Pointer field = 0x2c")


class TunnelEncapsulationLimitOptionOf4TestCase(ComplianceTestCase):
    """
    Tunnel Encapsulation Limit Option Of 4

    Verifies the tunnel encapsulation limit option is correctly processed
    when encapsulating a packet. 

    @private
    Source:         RFC 2473 Section 4.1.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optlen=1, optdata="\x04")])/
                    IPv6(src="8000::1", dst="8001::2")/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that the packet was forwarded into the tunnel...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected the packet to be forwarded into the tunnel")

        self.logger.info("Checking that TN4 did not receive a Parameter Problem message...")
        r2 = self.node(4).received(type=ICMPv6ParamProblem)
        assertEqual(0, len(r2), "expected the tunnel node to return a Parameter Problem message to TN4")


class TunnelEncapsulationLimitOptionOf255TestCase(ComplianceTestCase):
    """
    Tunnel Encapsulation Limit Option Of 255

    Verifies the tunnel encapsulation limit option is correctly processed
    when encapsulating a packet. 

    @private
    Source:         RFC 2473 Section 4.1.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optlen=1, optdata="\xff")])/
                    IPv6(src="8000::1", dst="8001::2")/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that the packet was forwarded into the tunnel...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(1, len(r1), "expected the packet to be forwarded into the tunnel")

        self.logger.info("Checking that TN4 did not receive a Parameter Problem message...")
        r2 = self.node(4).received(type=ICMPv6ParamProblem)
        assertEqual(0, len(r2), "expected the tunnel node to return a Parameter Problem message to TN4")


class NotEncapsulatedHeaderTestCase(ComplianceTestCase):
    """
    Not Encapsulated Header

    Verifies the tunnel encapsulation limit option is correctly processed
    when a not-yet-encapsulated packet is processed with that option.

    @private
    Source:         RFC 2473 Section 4.1.1
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN4 to TN2, via 6in6 tunnel.")
        self.node(4).send(
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(2).global_ip()))/
                IPv6ExtHdrDestOpt(options=[HBHOptUnknown(otype=4, optlen=1, optdata="\x00")])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking that the packet was not forwarded into the tunnel...")
        r1 = self.router(1).iface(1).received(seq=self.seq(), type=ICMPv6EchoRequest)
        assertEqual(0, len(r1), "did not expect the packet to be forwarded into the tunnel")

        self.logger.info("Checking that TN4 received a Parameter Problem message...")
        r2 = self.node(4).received(type=ICMPv6ParamProblem)
        assertEqual(1, len(r2), "expected the tunnel node to return a Parameter Problem message to TN4")

        assertEqual(0, r2[0].code, "expected the Parameter Problem message to have a Code field = 0")
        assertEqual(0x2c, r2[0].ptr, "expected the Parameter Problem message to have a Pointer field = 0x2c")
