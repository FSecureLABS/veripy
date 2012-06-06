from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouterAdvertisementHelper(ComplianceTestCase):

    disabled_nd = True
    disabled_ra = True
    restart_uut = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.logger.info("Sending an Echo Request from TR1 to the UUT...")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for Neighbor Solicitations from the UUT...")
        r1 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive Neighbor Solicitations for TR1")

        self.logger.info("Replying to Neighbor Solicitations")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/
                ICMPv6ND_NA(tgt=str(self.router(1).link_local_ip(iface=1)), R=False, S=True, O=True)/
                    ICMPv6NDOptDstLLAddr(lladdr=self.router(1).iface(1).ll_addr), iface=1)

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r2 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        self.logger.info("Sending a Router Advertisement from TR1...")
        self.router(1).send(self.p, iface=1)

        self.logger.info("Waiting for the UUT to complete DAD...")
        self.ui.wait(10)

        self.logger.info("Sending an Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r3 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        self.logger.info("Grabbing the Echo Reply before TR1 forwarded it...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)

        assertEqual(self.node(2).global_ip(), r2[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r2[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r2[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")


class RAWithoutSLLTestCase(RouterAdvertisementHelper):
    """
    Router Advertisement Processing, IsRouter flag - RA without Source
    Link-layer option

    Verify that a host properly updates the IsRouter flag in its Neighbor Cache
    upon receipt of a Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.17a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/\
                    ICMPv6ND_RA(prf=1)/\
                        ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/\
                        ICMPv6NDOptPrefixInfo(prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix)


class RAWithSameSLLAsCachedTestCase(RouterAdvertisementHelper):
    """
    Router Advertisement Processing, IsRouter flag - RA with same Source
    Link-layer option as cached

    Verify that a host properly updates the IsRouter flag in its Neighbor Cache
    upon receipt of a Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.17b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/\
                    ICMPv6ND_RA(prf=1)/\
                        ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/\
                        ICMPv6NDOptPrefixInfo(prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class RAWithDifferentSLLAsCachedTestCase(RouterAdvertisementHelper):
    """
    Router Advertisement Processing, IsRouter flag - RA with different Source
    Link-layer option as cached

    Verify that a host properly updates the IsRouter flag in its Neighbor Cache
    upon receipt of a Router Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.17c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/\
                    ICMPv6ND_RA(prf=1)/\
                        ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/\
                        ICMPv6NDOptPrefixInfo(prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(2).iface(1).ll_addr)
