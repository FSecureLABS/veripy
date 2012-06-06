from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class InvalidNeighborAdvertisementHelper(ComplianceTestCase):

    disabled_nd = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.logger.info("Sending an ICMPv6 Echo Request from TN1...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for Neighbor Solicitations...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to send one-or-more Neighbor Solicitations")
        for p in r1:
            assertEqual(self.node(1).link_local_ip(), p[ICMPv6ND_NS].tgt, "expected Neighbor Solicitations to be for TN1's link local address")

        self.logger.info("Sending an invalid Neighbor Advertisement to the UUT...")
        self.node(1).send(self.p)

        self.ui.wait(5)
        self.logger.info("Checking for an ICMPv6 Echo Reply...")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r2), "did not expect to receive an ICMPv6 Echo Reply")


class SolicitedFlagIsSetTestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (Solicited Flag == 1)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=False, S=True, O=True, tgt=str(self.node(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class HopLimitIs254TestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (Hop Limit == 254)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15b)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1", hlim=254)/\
                    ICMPv6ND_NA(R=False, S=False, O=True, tgt=str(self.node(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class InvalidChecksumTestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (Invalid Checksum)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15c)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=False, S=False, O=True, tgt=str(self.node(1).link_local_ip()), cksum=0)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class InvalidICMPCodeTestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (ICMP code != zero)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=False, S=False, O=True, tgt=str(self.node(1).link_local_ip()), code=1)/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class InvalidICMPLengthTestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (ICMP length < 24 octets)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15e)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1", plen=23)/\
                    ICMPv6ND_NA(R=False, S=False, O=True, tgt=str(self.node(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class TargetIsMulticastTestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (target == multicast address)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15f)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=False, S=False, O=True, tgt=str(self.node(1).link_local_ip().solicited_node()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=self.node(1).iface(0).ll_addr)


class OptionLengthIsZeroTestCase(InvalidNeighborAdvertisementHelper):
    """
    Invalid Neighbor Advertisement Handling - NUT receives invalid NA
    (option length == zero)

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Advertisement.

    @private
    Source          IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.15g)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst="ff02::1")/\
                    ICMPv6ND_NA(R=False, S=False, O=True, tgt=str(self.node(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(len=0, lladdr=self.node(1).iface(0).ll_addr)
