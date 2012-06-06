from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RedirectionHelper(ComplianceTestCase):
    """
    We are going to pretend that TN2 is on Link B, using Redirect messages.
    """

    disabled_ra = True
    restart_uut = True

    def run(self):
        self.router(1).send_ra()
        
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

        self.logger.info("Sending a Redirect message, identifying TN1 as the target...")
        self.router(1).send(self.p, iface=1)
        
        self.ui.wait(3)
        self.logger.info("Sending an Echo Request from TR2")
        self.router(2).send(
            IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for Neighbor Solicitations...")
        r2 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), dst=self.router(2).link_local_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r2), "expected to receive multicast Neighbor Solicitations for TR2")

        assertEqual(self.router(2).link_local_ip(iface=1), r2[0][ICMPv6ND_NS].tgt, "expected the target of Neighbor Solicitations to be TR2's link local address")


class RedirectSourceAddressIsGlobalTestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - Redirect Source Address
    is Global

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.node(2).global_ip()))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class RedirectSourceIsNotFirstHopRouterTestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - Redirect Source Address is
    not the current first-hop router

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class HopLimitIsNot255TestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - Hop Limit is not 255

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=254)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class ICMPCodeIsNot0TestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - ICMPv6 Code is not 0

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(code=1, dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class ICMPChecksumInvalid(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - ICMPv6 Checksum is invalid

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15e)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(cksum=0, dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class ICMPDestinationIsMulticastTestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - ICMPv6 Destination Address
    is Multicast

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15f)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst="ff02::1", tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class TargetAddressIsMulticastTestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - Target Address is
    Multicast

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15g)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt="ff02::1")/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class ICMPLengthIsLessThan40OctetsTestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - ICMPv6 length is less
    than 40 Octets

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15h)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255, plen=39)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class OptionHasZeroLengthTestCase(RedirectionHelper):
    """
    Invalid Redirect does not Update Neighbor Cache - Option has Length Zero

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.15i)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(len=0, lladdr=self.router(2).iface(1).ll_addr)
