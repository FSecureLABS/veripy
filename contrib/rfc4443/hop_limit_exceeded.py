from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class ReceiveHopLimit0TestCase(ComplianceTestCase):
    """
    Hop Limit Exceeded (Time Exceeded Generation) - Receive Hop Limit 0
    
    Verify that a node properly generates Time Exceeded messages if the Hop
    Limit was exceeded in transit.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.5a)
    """

    def run(self):
        self.logger.info("Sending packet to TN2 with hop limit of 0")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()), hlim=0)/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking the ICMPv6 Echo Request was not forwarded to TN4...")
        r1 = self.node(4).received(type=ICMPv6EchoRequest, seq=self.seq())

        assertEqual(0, len(r1), "did not expect the RUT to forward the Echo Request to TN4")

        self.logger.info("Checking for an ICMPv6 Time Exceeded message sent to TN1...")
        r2 = self.node(1).received(type=ICMPv6TimeExceeded)

        assertEqual(1, len(r2), "expected the RUT to send an ICMPv6 Time Exceeded message to TN1")
        
        self.logger.info("Checking src is correct")
        assertTrue(r2[0].getlayer(IPv6).src in self.target(1).ip(offset='*', scope='*'))
        
        self.logger.info("Checking code is correct")
        assertEqual(0, r2[0].getlayer(ICMPv6TimeExceeded).code, "expected the ICMPv6 Time Exceeded message code = 0")
        
        self.logger.info("Checking unused is 0")
        assertEqual(0, r2[0].getlayer(ICMPv6TimeExceeded).unused, "expected the ICMPv6 Time Exceeded message unused = 0")
        
        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r2[0]), "expecting MTU of received packet not to exceed 1280")


class DecrementHopLimitTo0TestCase(ComplianceTestCase):
    """
    Hop Limit Exceeded (Time Exceeded Generation) - Decrement Hop Limit to 0

    Verify that a node properly generates Time Exceeded messages if the Hop
    Limit was exceeded in transit.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Test (v6LC.5.1.5b)
    """

    def run(self):
        self.logger.info("Sending packet to TN2 with hop limit of 0")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.node(4).global_ip()), hlim=1)/ICMPv6EchoRequest())
        
        self.logger.info("Checking the ICMPv6 Echo Request was not forwarded to TN4...")
        r1 = self.node(4).received(type=ICMPv6EchoRequest, seq=self.seq())

        assertEqual(0, len(r1), "did not expect the RUT to forward the Echo Request to TN4")

        self.logger.info("Checking for an ICMPv6 Time Exceeded message sent to TN1...")
        r2 = self.node(1).received(type=ICMPv6TimeExceeded)

        assertEqual(1, len(r2), "expected the RUT to send an ICMPv6 Time Exceeded message to TN1")
        
        self.logger.info("Checking src is correct")
        assertTrue(r2[0].getlayer(IPv6).src in self.target(1).ip(offset='*', scope='*'))

        self.logger.info("Checking code is correct")
        assertEqual(0, r2[0].getlayer(ICMPv6TimeExceeded).code, "expected the ICMPv6 Time Exceeded message code = 0")

        self.logger.info("Checking unused is 0")
        assertEqual(0, r2[0].getlayer(ICMPv6TimeExceeded).unused, "expected the ICMPv6 Time Exceeded message unused = 0")

        self.logger.info("Checking MTU of packet does not exceed minimum MTU")
        assertLessThan(1281, len(r2[0]), "expecting MTU of received packet not to exceed 1280")
        