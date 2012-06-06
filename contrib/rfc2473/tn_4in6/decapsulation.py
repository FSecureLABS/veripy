from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class AllEncapsulatedOptionsRemovedIPv4TestCase(ComplianceTestCase):
    """
    All Encapsulated Options Removed IPv4

    Verifies that all of the options on the encapsulating IPv6 packet are removed 
    when an encapsulated IPv4 packet leaves a 4in6 tunnel (and undergoes decapsulation).

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending an ICMP echo request from TN2 to TN4, via 4in6 tunnel...")
        self.router(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()))/
                IPv6ExtHdrHopByHop()/
                IPv6ExtHdrDestOpt(nh=4)/
                    IP(src=str(self.node(2).ip(type="v4")), dst=str(self.node(4).ip(type="v4")))/
                        ICMP(seq=self.next_seq()), iface=1)
        
        self.logger.info("Checking to see if the packet was decapsulated...")
        r1 = self.node(4).received(type=ICMP)
        assertEqual(1, len(r1), "expecting the ICMP request to be forwarded to TN4")

        assertNotHasLayer(IPv6, r1[0], "expected all encapsulating headers to be removed")
        assertNotHasLayer(IPv6ExtHdrDestOpt, r1[0], "expected all encapsulating headers to be removed")
        assertNotHasLayer(IPv6ExtHdrHopByHop, r1[0], "expected all encapsulating headers to be removed")


class NextHeaderIsIPv4WithEncapsulatedIPv4HeaderTestCase(ComplianceTestCase):
    """
    Next Header Is IPv4 With Encapsulated IPv4 Header

    Verifies an IPv6 encapsulating header with a next header of IPv4
    is correctly processed with an encapsulated IPv4 packet.

    @private
    Source:         RFC 2473 Section 3.3
    """

    def run(self):
        self.logger.info("Sending an ICMP echo request from TN2 to TN4, via 4in6 tunnel...")
        self.router(1).send(
            IPv6(src=str(self.router(1).iface(1).global_ip()), dst=str(self.target(2).global_ip()), nh=4)/
                    IP(src=str(self.node(2).ip(type="v4")), dst=str(self.node(4).ip(type="v4")))/
                        ICMP(seq=self.next_seq()), iface=1)

        self.logger.info("Checking to see if the packet was decapsulated...")
        r1 = self.node(4).received(type=ICMP)
        assertEqual(1, len(r1), "expecting the ICMP request to be forwarded to TN4")
        