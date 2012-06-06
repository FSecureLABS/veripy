from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouteUnreachableTestCase(ComplianceTestCase):
    """
    Destination Unreachable Message Generation - Router Unreachable

    Verify that a node generates valid destination unreachable packets

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.3a
    """
    
    def run(self):
        self.ui.tell("Please remove any default routes from RUT's Routing Table...")
        assertTrue(self.ui.ask("Press Y when this is done"), "Could not test. RUT has default routes.")

        self.logger.info("Sending packet to off link address with prefix that doesn't exist")
        self.node(1).send(IPv6(src=str(self.node(1).global_ip()), dst="1234::1")/ICMPv6EchoRequest(seq=self.next_seq()))

        r1 = self.node(1).received(type=ICMPv6DestUnreach)

        assertEqual(1, len(r1), "expected to receive a Destination Unreachable message (seq: %d)" % (self.seq()))

        self.logger.info("Checking src is correct")
        assertTrue(r1[0].getlayer(IPv6).src in self.target(1).ip(offset='*', scope='*'))

        self.logger.info("Checking code is correct")
        assertEqual(0, r1[0].getlayer(ICMPv6DestUnreach).code, "Expecting code to equal 0")

        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r1[0]), "Expecting MTU of received packet not to exceed 1280")


class AddressUnreachableTestCase(ComplianceTestCase):
    """
    Destination Unreachable Message Generation - Address Unreachable

    Verify that a node generates valid destination unreachable packets

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.3b
    """

    def run(self):
        dst_address = self.link(1).prefix + "abba:affa"

        self.logger.info("Sending packet to unknown address")
        self.node(1).send(IPv6(src=str(self.node(1).global_ip()), dst=dst_address)/ICMPv6EchoRequest(seq=self.next_seq()))

        r1 = self.node(1).received(type=ICMPv6DestUnreach)

        assertEqual(1, len(r1), "expected to receive a Destination Unreachable message (seq: %d)" % (self.seq()))

        self.logger.info("Checking src is correct")
        assertTrue(r1[0].getlayer(IPv6).src in self.target(1).ip(offset='*', scope='*'))

        self.logger.info("Checking code is correct")
        assertEqual(3, r1[0].getlayer(ICMPv6DestUnreach).code, "Expecting code to equal 3")

        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r1[0]), "Expecting MTU of received packet not to exceed 1280")


class PortUnreachableLinkLocalTestCase(ComplianceTestCase):
    """
    Destination Unreachable Message Generation - Port Unreachable, Link
    Local Address
    
    Verify that a node generates valid destination unreachable packets

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.3c
    """

    def run(self):
        assertFalse(self.ui.ask("Is the NUT listening on port 9000?", True), "cannot test, NUT is listening on port 9000")
        
        self.logger.info("Sending UDP packet to port 9000")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                UDP(dport=9000))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6DestUnreach)

        assertEqual(1, len(r1), "expected to receive a Destination Unreachable message")
        
        self.logger.info("Checking code is correct")
        assertEqual(4, r1[0].getlayer(ICMPv6DestUnreach).code, "Expecting code to equal 4")
        
        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r1[0]), "Expecting MTU of received packet not to exceed 1280")

    
class PortUnreachableGlobalTestCase(ComplianceTestCase):
    """
    Destination Unreachable Message Generation - Port Unreachable, Global
    Address
    
    Verify that a node generates valid destination unreachable packets

    @private
    Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core
                      Test v6LC.5.1.3: Destination Unreachable Message Generation

    """

    def run(self):
        assertFalse(self.ui.ask("Is the NUT listening on port 9000?", True), "cannot test, NUT is listening on port 9000")
        
        self.logger.info("Sending UDP packet to port 9000")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                UDP(dport=9000))
        
        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6DestUnreach)

        assertEqual(1, len(r1), "expected to receive a Destination Unreachable message")
        
        self.logger.info("Checking code is correct")
        assertEqual(4, r1[0].getlayer(ICMPv6DestUnreach).code, "Expecting code to equal 4")

        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r1[0]), "Expecting MTU of received packet not to exceed 1280")
        
        
class BeyondScopeOfSourceAddressTestCase(ComplianceTestCase):
    """
    Destination Unreachable Message Generation - Beyond Scope of Source
    Address

    Verify that a node generates valid destination unreachable packets

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test v6LC.5.1.3d
    """

    def run(self):
    
        self.logger.info("Sending packet to TN4's link local address")
        self.node(1).send( \
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.node(4).link_local_ip()))/
                ICMPv6EchoRequest())

        self.logger.info("Checking for reply")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6DestUnreach)

        assertEqual(1, len(r1), "expected to receive a Destination Unreachable message")

        self.logger.info("Checking code is correct")
        assertEqual(2, r1[0].getlayer(ICMPv6DestUnreach).code, "Expecting code to equal 2")

        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r1[0]), "Expecting MTU of received packet not to exceed 1280")
