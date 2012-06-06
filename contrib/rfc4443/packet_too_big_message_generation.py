from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase
from veripy import util


class UnicastDestinationTestCase(ComplianceTestCase):
    """
    Packet Too Big Message Generation - Unicast Destination
    
    Verify that a router properly generates Packet Too Big Messages.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.4a)
    """

    def run(self):
        # TODO: configure the RUT's link MTU on link C to be 1280, the minimum
        #       IPv6 MTU
        self.logger.info("Sending packet from TN1 to TN4")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()))/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True, False))

        self.logger.info("Checking for a forwarded ICMPv6 Echo Request...")
        r1 = self.node(4).received(type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded to TN4")

        self.logger.info("Checking for an ICMPv6 Packet Too Big message...")
        r2 = self.node(1).received(type=ICMPv6PacketTooBig)

        assertEqual(1, len(r2), "expected to receive an ICMPv6 Packet Too Big message")
        
        self.logger.info("Checking MTU of PacketTooBig is set to 1280")
        assertEqual(1280, r2[0].getlayer(ICMPv6PacketTooBig).mtu, "Expecting mtu of packet too big error to equal 1280")
        
        self.logger.info("Checking src is correct")
        assertTrue(r2[0].getlayer(IPv6).src in self.target(1).ip(offset='*', scope='*'))
        
        self.logger.info("Checking code is correct")
        assertEqual(0, r2[0].getlayer(ICMPv6PacketTooBig).code, "Expecting code to equal 0")
        
        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r2[0]), "Expecting MTU of received packet not to exceed 1280")


class MulticastDestinationTestCase(ComplianceTestCase):
    """
    Packet Too Big Message Generation - Multicast Destination

    Verify that a router properly generates Packet Too Big Messages.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.4b)
    """

    def run(self):
        assertTrue(self.ui.ask("Does the RUT support multicast routing?", True))

        # TODO: configure the RUT's link MTU on link C to be 1280, the minimum
        #       IPv6 MTU
        self.logger.info("Sending packet from TN1 to TN2")
        self.node(1).send( \
            util.pad( \
                IPv6(src=str(self.node(1).global_ip()), dst="ff1e::1:2")/
                    ICMPv6EchoRequest(seq=self.next_seq()), 1500, True, False))
        
        self.logger.info("Checking for a forwarded ICMPv6 Echo Request...")
        r1 = self.node(4).received(type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expect the ICMPv6 Echo Request to be forwarded to TN4")

        self.logger.info("Checking for an ICMPv6 Packet Too Big message...")
        r2 = self.node(1).received(type=ICMPv6PacketTooBig)

        assertEqual(1, len(r2), "expected to receive an ICMPv6 Packet Too Big message")
        
        self.logger.info("Checking MTU of PacketTooBig is set to 1280")
        assertEqual(1280, r2[0].getlayer(ICMPv6PacketTooBig).mtu, "Expecting mtu of packet too big error to equal 1280")
        
        self.logger.info("Checking src is correct")
        assertTrue(r2[0].getlayer(IPv6).src in self.target(1).ip(offset='*', scope='*'))
        
        self.logger.info("Checking code is correct")
        assertEqual(0, r2[0].getlayer(ICMPv6PacketTooBig).code, "Expecting code to equal 0")
        
        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r2[0]), "Expecting MTU of received packet not to exceed 1280")
                                