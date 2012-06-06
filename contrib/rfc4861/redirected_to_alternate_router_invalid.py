from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RedirectionHelper(ComplianceTestCase):
    """
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

        self.logger.info("Sending a Redirect message, identifying TN1 as the target...")
        self.router(1).send(self.p, iface=1)

        self.router(1).clear_received()
        self.logger.info("Forwarding an Echo Request from TN2, using an off-link global IP...")
        self.router(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=254)/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.logger.info("Checking for Neighbor Solicitations...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip().solicited_node(), type=ICMPv6ND_NS)

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r1 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        assertEqual(self.node(2).global_ip(), r1[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r1[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(1).iface(1).ll_addr, r1[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent through TR1")


class RedirectSourceAddressIsGlobalTestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - Redirect Source Address is Global

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.node(2).global_ip()))


class RedirectSourceIsNotFirstHopRouterTestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - Redirect Source Address is not the current
    first-hop router

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))


class HopLimitIsNot255TestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - Hop Limit is not 255

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=254)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))


class ICMPCodeIsNot0TestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - ICMPv6 Code is not 0

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(code=1, dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))


class ICMPChecksumInvalid(RedirectionHelper):
    """
    Redirected On-link: Invalid - ICMPv6 Checksum is invalid

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3e)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(cksum=0, dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))


class ICMPDestinationIsMulticastTestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - ICMPv6 Destination Address is Multicast

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3f)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst="ff02::1", tgt=str(self.router(1).link_local_ip(iface=1)))


class TargetAddressIsMulticastTestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - Target Address is Multicast

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3g)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt="ff02::1")


class ICMPLengthIsLessThan40OctetsTestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - ICMPv6 length is less than 40 Octets

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3h)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255, plen=39)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))


class OptionHasZeroLengthTestCase(RedirectionHelper):
    """
    Redirected On-link: Invalid - Option has Length Zero

    Verify that a host properly processes invalid Redirect messages when
    redirected on-link.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.3i)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(1).link_local_ip(iface=1)))/\
                        ICMPv6NDOptDstLLAddr(len=0)
                        