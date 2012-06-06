from constants import *
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class RouterAdvertisementHelper(ComplianceTestCase):

    restart_uut = True

    def set_up(self):
        raise Exception("override #set_up to define #cur_hop_limit")

    def run(self):
        self.logger.info("Sending an ICMPv6 Echo Request from TN1...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for the Echo Reply...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        self.logger.info("Sending a Router Advertisement, with Cur Hop Limit = %d" % (self.cur_hop_limit))
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(prf=1, chlim=self.cur_hop_limit)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)/
                    ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/
                    ICMPv6NDOptPrefixInfo(prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix), iface=1)


        self.logger.info("Sending an ICMPv6 Echo Request from TN1...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for the Echo Reply...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r2), "expected to receive an ICMPv6 Echo Reply (seq: %d)" % (self.seq()))

        if self.cur_hop_limit == 0:
            assertEqual(r1[0][IPv6].hlim, r2[0][IPv6].hlim, "expected the hlim to be the same")
        else:
            assertEqual(self.cur_hop_limit, r2[0][IPv6].hlim, "expected the hlim to be the same")


class UnspecifiedTestCase(RouterAdvertisementHelper):
    """
    Router Advertisement Processing, Cur Hop Limit - Unspecified

    Verify that a host properly processes the Cur Hop Limit field of a Router
    Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.13a)
    """

    def set_up(self):
        self.cur_hop_limit = 0


class NonZeroTestCase(RouterAdvertisementHelper):
    """
    Router Advertisement Processing, Cur Hop Limit - Non Zero

    Verify that a host properly processes the Cur Hop Limit field of a Router
    Advertisement.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.2.13b)
    """

    def set_up(self):
        self.cur_hop_limit = 15
    