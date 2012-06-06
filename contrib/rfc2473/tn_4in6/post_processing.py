from scapy.all import *
from veripy import util
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class TTLExceededAfterTunnelTestCase(ComplianceTestCase):
    """
    TTL Exceeded After Tunnel

    Verifies a time exceeded message is sent back through the tunnel
    when the TTL on a packet is exceeded after tunneling.

    @private
    Source:         RFC 2473 Section 8.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel.")
        self.router(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(2).global_ip()), nh=4)/
                IP(src=str(self.node(2).ip(type="v4")), dst=str(self.node(4).ip(type="v4")), ttl=0)/
                    ICMP(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for ICMP Echo Requests delivered to TN4...")
        r1 = self.node(4).received(type=ICMP)
        assertEqual(0, len(r1), "did not expect the ICMP Echo Request to be delivered to TN4")

        self.logger.info("Checking for ICMP problems delivered to TN2...")
        r2 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r2), "expected an ICMP problem to be delivered to TN2")

        assertEqual(11, r2[0][ICMP].type, "expected the ICMP problem to have type=11")
        assertEqual(0, r2[0][ICMP].code, "expected the ICMP problem to have type=0")


class UnreachableNodeAfterTunnelTestCase(ComplianceTestCase):
    """
    Unreachable Node After Tunnel

    Verifies an unreachable destination message is sent back through the tunnel
    when it occurs after tunneling.

    @private
    Source:         RFC 2473 Section 8.3
    """

    def run(self):
        self.logger.info("Sending ICMPv6 echo request from TN2 to TN4, via 6in6 tunnel.")
        self.router(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(2).global_ip()), nh=4)/
                IP(src=str(self.node(2).ip(type="v4")), dst="8.8.8.8")/
                    ICMP(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for ICMP Echo Requests delivered to TN4...")
        r1 = self.node(4).received(type=ICMP)
        assertEqual(0, len(r1), "did not expect the ICMP Echo Request to be delivered to TN4")

        self.logger.info("Checking for ICMP problems delivered to TN2...")
        r2 = self.router(1).received(iface=1, type=ICMP)
        assertEqual(1, len(r2), "expected an ICMP problem to be delivered to TN2")

        assertEqual(11, r2[0][ICMP].type, "expected the ICMP problem to have type=11")
        assertEqual(1, r2[0][ICMP].code, "expected the ICMP problem to have type=1")
        