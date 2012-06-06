from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class TTLDecrementedTestCase(ComplianceTestCase):
    """
    TTL Decremented

    Verifies that the TTL on an IPv4 packet is decremented by 1 when it
    is sent through a 4in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.1
    """

    def run(self):
        self.logger.info("Sending ICMP Echo Request from TN4 to TN2, via 4in6 tunnel...")
        self.node(4).send(
            IP(src=str(self.node(4).ip(type="v4")), dst=str(self.node(2).ip(type="v4")), ttl=64)/
                ICMP(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expected the ICMP Echo Request to be tunnelled through TR1")

        assertEqual(IPv6, r1[0][0].__class__, "expected an IPv6 tunnel header to have been added")
        assertEqual(IP, r1[0][1].__class__, "expected an IP header in the tunnelled packet")

        assertEqual(63, r1[0][1].ttl, "expected the TTL of the tunnelled packet to be decremented")


class EntryPointAddressTestCase(ComplianceTestCase):
    """
    Entry Point Address

    Verifies that the source address on an encapsulating packet is 
    equal to the tunnel entry point address, when it is sent through
    a 4in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.1
    """

    def run(self):
        self.logger.info("Sending ICMP Echo Request from TN4 to TN2, via 4in6 tunnel...")
        self.node(4).send(
            IP(src=str(self.node(4).ip(type="v4")), dst=str(self.node(2).ip(type="v4")), ttl=64)/
                ICMP(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expected the ICMP Echo Request to be tunnelled through TR1")

        assertEqual(self.target(2).global_ip(), r1[0][IPv6].src, "expected the IPv6 Source Address to be the tunnel entry point")


class EndPointAddressTestCase(ComplianceTestCase):
    """
    End Point Address

    Verifies that the destination address on an encapsulating packet is 
    equal to the tunnel end point address, when it is sent through
    a 4in6 tunnel.

    @private
    Source:         RFC 2473 Section 3.1
    """

    def run(self):
        self.logger.info("Sending ICMP Echo Request from TN4 to TN2, via 4in6 tunnel...")
        self.node(4).send(
            IP(src=str(self.node(4).ip(type="v4")), dst=str(self.node(2).ip(type="v4")), ttl=64)/
                ICMP(seq=self.next_seq()))

        self.logger.info("Checking for a tunnelled packet...")
        r1 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r1), "expected the ICMP Echo Request to be tunnelled through TR1")

        assertEqual(self.router(1).global_ip(iface=1), r1[0][IPv6].dst, "expected the IPv6 Destination Address to be the tunnel exit point")
        