from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouterInUseFailsTestCase(ComplianceTestCase):
    """
    Default Router Switch

    Verify that a host maintains at least two routers in its Default Router List
    and will switch routers when the router in use fails.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.11)
    """
    
    disabled_ra = True
    restart_uut = True

    def run(self):
        self.logger.info("Sending Router Advertisement from TR1...")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(routerlifetime=45, reachabletime=10, retranstimer=1)/
                    ICMPv6NDOptPrefixInfo(L=True, prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix), iface=1)

        self.logger.info("Sending an Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an Echo Reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply at TN2 (seq: %d)" % (self.seq()))

        self.logger.info("Grabbing the Echo Reply before TR1 forwarded it...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)

        assertEqual(self.node(2).global_ip(), r2[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r2[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r2[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")

        self.logger.info("Sending Router Advertisement from TR2...")
        self.router(1).send(
            IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(routerlifetime=45, reachabletime=10, retranstimer=1)/
                    ICMPv6NDOptPrefixInfo(L=True, prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix), iface=1)

        self.logger.info("Sending an Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an Echo Reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply at TN2 (seq: %d)" % (self.seq()))

        self.logger.info("Grabbing the Echo Reply before TR1 forwarded it...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)

        assertEqual(self.node(2).global_ip(), r2[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r2[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r2[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")
        
        self.ui.wait(20)

        self.logger.info("Sending an Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an Echo Reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply at TN2")

        self.logger.info("Grabbing the Echo Reply before TR2 forwarded it...")
        r2 = self.router(2).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)

        assertEqual(self.node(2).global_ip(), r2[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r2[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(2).iface(1).ll_addr, r2[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR2")