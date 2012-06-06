from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class IsRouterFlagHelper(ComplianceTestCase):

    disabled_nd = True
    restart_uut = True

    def set_up(self):
        raise Exception("override #set_up to set #p")

    def run(self):
        self.logger.info("Sending a Neighbor solicitation from TR1...")
        self.router(1).send(self.p, iface=1)

        self.logger.info("Sending an ICMPv6 Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for ICMPv6 Echo Reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r1), "expected the UUT to send an ICMPv6 Echo Reply to TN2 (seq: %d)" % (self.seq()))

        self.logger.info("Grabbing the Echo Reply before TR1 forwarded it...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        
        assertEqual(self.node(2).global_ip(), r2[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r2[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r2[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")


class UnicastNeighborSolicitationWithoutSLLATestCase(IsRouterFlagHelper):
    """
    Neighbor Solicitation Processing, IsRouterFlag - Unicast Neighbor
    Solicitation without SLLA

    Verify that a host does not modify the isRouter flag after receiving a
    Neighbor Solicitation.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.13a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))


class UnicastNeighborSolicitationWithSLLATestCase(IsRouterFlagHelper):
    """
    Neighbor Solicitation Processing, IsRouterFlag - Unicast Neighbor
    Solicitation with a SLLA

    Verify that a host does not modify the isRouter flag after receiving a
    Neighbor Solicitation.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.13b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)

class MulticastNeighborSolicitationWithDifferentSLLATestCase(IsRouterFlagHelper):
    """
    Neighbor Solicitation Processing, IsRouterFlag - Multicast Neighbor
    Solicitation with a different SLLA

    Verify that a host does not modify the isRouter flag after receiving a
    Neighbor Solicitation.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.13c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(2).iface(1).ll_addr)
                        