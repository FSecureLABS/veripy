from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RbitChangeHelper(ComplianceTestCase):

    disabled_nd = True
    disabled_ra = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.router(1).send_ra()
        
        self.logger.info("Sending an ICMPv6 Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

#        self.logger.info("Checking for Neighbor Solicitations for TR1 (the default router)...")
#        r1 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(1).link_local_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
#        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to send one-or-more Neighbor Solicitations")
#        for p in r1:
#            assertEqual(self.router(1).link_local_ip(iface=1), p[ICMPv6ND_NS].tgt, "expected Neighbor Solicitations to be for TR1's link local address")
#
#        self.logger.info("Sending a Neighbor Advertisement from TR1...")
#        self.router(1).respond_to_neighbour_solicitation(r1[0], self.router(1).iface(1))

        self.logger.info("Checking for an Echo Reply for TN2...")
        r2 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r2), "expected the UUT to send an ICMPv6 Echo Reply to TN2 (seq: %d)" % (self.seq()))

        self.logger.info("Grabbing the Echo Reply before TR1 forwarded it...")
        r3 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)

        assertEqual(self.node(2).global_ip(), r3[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r3[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r3[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")

        self.logger.info("Sending Neighbor Advertisement from TR1, with R-bit clear...")
        self.router(1).send(self.p, iface=1)

        self.node(1).clear_received()
        self.logger.info("Sending another ICMPv6 Echo Request from TN2...")
        self.node(2).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for an Echo Reply for TN2...")
        r4 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(0, len(r4), "did not expect the UUT to send an ICMPv6 Echo Reply to TN2 (seq: %d)" % (self.seq()))


class FlagsSet0x011TestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change -

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=1, O=1, tgt=str(self.router(1).iface(1).link_local_ip()))


class FlagsSet0x000TestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change -

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=0, O=0, tgt=str(self.router(1).iface(1).link_local_ip()))


class FlagsSet0x001TestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=0, O=1, tgt=str(self.router(1).iface(1).link_local_ip()))


class FlagsSet0x010TestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=1, O=0, tgt=str(self.router(1).iface(1).link_local_ip()))


class FlagsSet0x011TLLTestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21e)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=1, O=1, tgt=str(self.router(1).iface(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class FlagsSet0x000TLLTestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21f)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=0, O=0, tgt=str(self.router(1).iface(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class FlagsSet0x001TLLTestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21g)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=0, O=1, tgt=str(self.router(1).iface(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)


class FlagsSet0x010TLLTestCase(RbitChangeHelper):
    """
    Neighbor Advertisement Processing, R-bit Change

    Verify that a host takes appropriate actions when a neighbor who is a
    router starts transmitting Neighbor Advertisements with the Router flag
    clear.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.21h)
    """
    pass

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).iface(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=0, S=1, O=0, tgt=str(self.router(1).iface(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)
                        