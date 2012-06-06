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
        self.router(1).send(self.p(r1[0]), iface=1)

        self.router(2).clear_received()
        self.logger.info("Forwarding an Echo Request from TN2, using an off-link global IP...")
        self.router(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), hlim=254)/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        if not self.tlla:
            self.logger.info("Checking for Neighbor Solicitations...")
            r2 = self.router(2).received(iface=1, src=self.target(1).global_ip(), dst=[self.router(2).link_local_ip(iface=1), self.router(2).link_local_ip(iface=1).solicited_node()], type=ICMPv6ND_NS)

            assertGreaterThanOrEqualTo(1, len(r2), "expected one-or-more Neighbor Solicitations for TR2's link-local IP")
            assertEqual(self.router(2).link_local_ip(iface=1), r2[0][ICMPv6ND_NS].tgt)

            self.router(2).send(
                IPv6(src=str(self.router(2).link_local_ip(iface=1)), dst=str(self.target(1).global_ip()))/
                    ICMPv6ND_NA(tgt=str(self.router(2).link_local_ip(iface=1)), R=False, S=True, O=True)/
                        ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr), iface=1)
        else:
            self.logger.info("Checking for Neighbor Solicitations...")
            r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.router(2).link_local_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)

            assertEqual(0, len(r2), "did not expect any Neighbor Solicitations for TN2's on-link global IP")

        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r3 = self.router(2).received(iface=1, src=self.target(1).global_ip(), dst=self.node(2).global_ip(), seq=self.seq(), type=ICMPv6EchoReply, raw=True)
        assertEqual(1, len(r3), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        assertEqual(self.node(2).global_ip(), r3[0][IPv6].dst, "expected the ICMPv6 Echo Reply dst to be TN2's global address")
        assertEqual(self.target(1).ll_addr(), r3[0][Ether].src, "expected the ICMPv6 Echo Reply Ethernet src to be the UUT")
        assertEqual(self.router(2).iface(1).ll_addr, r3[0][Ether].dst, "expected the ICMPv6 Echo Reply to be sent via TR2")


class NoTLLANoRedirectTestCase(RedirectionHelper):
    """
    Redirected to Alternate Router: Valid - No TLLA, No Redirect

    Verify that a host properly processes invalid Redirect messages when
    redirected to alternate router.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.4a)
    """

    def set_up(self):
        self.tlla = False

    def p(self, p):
        return IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(2).link_local_ip(iface=1)))


class NoTLLARedirectTestCase(RedirectionHelper):
    """
    Redirected to Alternate Router: Valid - No TLLA, Redirect

    Verify that a host properly processes invalid Redirect messages when
    redirected to alternate router.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.4b)
    """

    def set_up(self):
        self.tlla = False

    def p(self, p):
        return IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(2).link_local_ip(iface=1)))/\
                    ICMPv6NDOptRedirectedHdr(pkt=p.build()[0:1280-84])


class TLLANoRedirectTestCase(RedirectionHelper):
    """
    Redirected to Alternate Router: Valid - TLLA, No Redirect

    Verify that a host properly processes invalid Redirect messages when
    redirected to alternate router.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.4c)
    """

    def set_up(self):
        self.tlla = True

    def p(self, p):
        return IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(2).link_local_ip(iface=1)))/\
                    ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)


class TLLARedirectTestCase(RedirectionHelper):
    """
    Redirected to Alternate Router: Valid - TLLA, Redirect

    Verify that a host properly processes invalid Redirect messages when
    redirected to alternate router.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.3.4d)
    """

    def set_up(self):
        self.tlla = True

    def p(self, p):
        return IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                ICMPv6ND_Redirect(dst=str(self.node(2).global_ip()), tgt=str(self.router(2).link_local_ip(iface=1)))/\
                    ICMPv6NDOptDstLLAddr(lladdr=self.router(2).iface(1).ll_addr)/\
                    ICMPv6NDOptRedirectedHdr(pkt=p.build()[0:1280-84])
                