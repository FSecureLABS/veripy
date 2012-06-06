from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RedirectedTwiceTestCase(ComplianceTestCase):
    """
    Redirected Twice

    Verify that a host properly processes valid Redirect messages twice for the
    same destination.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.7)
                    
    We are going to pretend that TN2 is on Link B, using Redirect messages.
    """

    restart_uut = True

    def run(self):
        self.ui.wait(2)
        self.logger.info("Forwarding an Echo Request from TN1, using an off-link global IP...")
        self.router(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=254)/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r1 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        assertEqual(self.node(2).global_ip(), r1[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r1[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r1[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")

        self.logger.info("Sending a Redirect message, identifying TR2 as the target...")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/
                ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(2).link_local_ip(iface=1))), iface=1)

        self.router(2).clear_received()
        self.logger.info("Forwarding an Echo Request from TN2, using an off-link global IP...")
        self.router(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=254)/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r3 = self.router(2).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        assertEqual(self.node(2).global_ip(), r3[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r3[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(2).iface(1).ll_addr, r3[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent via TR2")

        self.logger.info("Sending a Redirect message, identifying TR3 as the target...")
        self.router(1).send(
            IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/
                ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(3).link_local_ip(iface=1))), iface=1)

        self.router(3).clear_received()
        self.logger.info("Forwarding an Echo Request from TN2, using an off-link global IP...")
        self.router(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=254)/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r3 = self.router(3).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        assertEqual(self.node(2).global_ip(), r3[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r3[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(3).iface(1).ll_addr, r3[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent via TR2")