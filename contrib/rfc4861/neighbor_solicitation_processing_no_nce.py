from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase, IPAddress
from constants import *

class NeighborSolicitationProcessingHelper(ComplianceTestCase):

    disabled_nd = True
    restart_uut = True

    def set_up(self):
        raise Exception("override #set_up to define #dst")

    def run(self):
        self.logger.info("Sending a Neighbor Solicitation to the UUT...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.dst))/
                ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/
                    ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr)))

        self.logger.info("Sending an ICMPv6 Echo Request to the UUT...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for Neighbor Advertisements received...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6ND_NA)
        assertEqual(1, len(r1), "expected to receive a Neighbor Advertisement")

        self.logger.info("Checking for ICMPv6 Echo Replies received...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from the UUT")

        self.logger.info("Waiting for DELAY_FIRST_PROBE_TIME.")
        self.ui.wait(DELAY_FIRST_PROBE_TIME)

        self.logger.info("Checking for Neighbor Solicitation Probes")
        r2 = self.node(1).received(src=self.target(1).link_local_ip(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r2), "expecting the UUT to have sent Neighbor Solitication probes")

        assertGreaterThanOrEqualTo(DELAY_FIRST_PROBE_TIME, r2[0].time - r1[0].time, "expected the UUT to wait DELAY_FIRST_PROBE_TIME before sending probes")


class UnicastTestCase(NeighborSolicitationProcessingHelper):
    """
    Neighbor Solicitation Processing, No NCE - Unicast Neighbor Solicitation
         
    Verify that a node properly updates its neighbor cache upon receipt of
    neighbor solicitations when there is no NCE exists for that neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.1.8a)
    """

    def set_up(self):
        self.dst = self.target(1).link_local_ip()


class MulticastTestCase(NeighborSolicitationProcessingHelper):
    """
    Neighbor Solicitation Processing, No NCE - Multicast Neighbor Solicitation
         
    Verify that a node properly updates its neighbor cache upon receipt of
    neighbor solicitations when there is no NCE exists for that neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.1.8b)
    """

    def set_up(self):
        self.dst = self.target(1).link_local_ip().solicited_node()


class UnicastNoSLLTestCase(ComplianceTestCase):
    """
    Neighbor Solicitation Processing, No NCE - Unicast Neighbor Solicitation
    without SLL
         
    Verify that a node properly updates its neighbor cache upon receipt of
    neighbor solicitations when there is no NCE exists for that neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.1.8c)
    """
    
    disabled_nd = True
    restart_uut = True

    def run(self):
        self.logger.info("Sending a Neighbor Solicitation to the UUT...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip())))

        self.logger.info("Sending an ICMPv6 Echo Request to the UUT...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for Neighbor Advertisements received...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expected the UUT to send multicast Neighbor Solicitations for TN1")

        self.logger.info("Checking for ICMPv6 Echo Replies received...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(0, len(r1), "did not expect to receive any ICMPv6 Echo Replies from the UUT")
        