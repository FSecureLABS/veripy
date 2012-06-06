from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase
from constants import *

class InvalidNeighborSolicitationHandlingHelper(ComplianceTestCase):

    disabled_nd = True

    def set_up(self):
        raise Exception("override #set_up to define #p")

    def run(self):
        self.logger.info("Sending the invalid Neighbor Solicitation...")
        self.node(1).send(self.p)

        self.logger.info("Checking for replies...")
        r1 = self.node(1).received(src=self.target(1).ip(scope='*', offset='*'), dst=self.node(1).link_local_ip(), type=ICMPv6ND_NA)

        assertEqual(0, len(r1), "did not expect the UUT to send a Neighbor Advertisement")

        self.logger.info("Verifying the UUT still responds to a valid Neighbor Solicitation...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                    ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr)))

        self.logger.info("Checking for replies...")
        r2 = self.node(1).received(src=self.target(1).ip(scope='*', offset='*'), dst=self.node(1).link_local_ip(), type=ICMPv6ND_NA)

        assertGreaterThanOrEqualTo(1, len(r2), "expected the UUT to send a Neighbor Advertisement")


class InvalidTargetAddressTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid Target Address
         
    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7a)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_NS(tgt="ff02::1")/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class InvalidDestinationAddressTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid Destination Address

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7b)
    """

    def set_up(self):
        self.p = IPv6(src="::", dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class InvalidSourceLinkLayerAddressOptionTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid Source Link-Layer Address Option

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7c)
    """

    def set_up(self):
        self.p = IPv6(src="::", dst=str(self.target(1).link_local_ip().solicited_node()), hlim=255)/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class InvalidHopLimitTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid Hop Limit

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7d)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=254)/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class InvalidChecksumTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid Checksum

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7e)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_NS(cksum=0, tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class InvalidICMPCodeTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid ICMP code

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7f)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_NS(code=1, tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class InvalidICMPLengthTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Invalid ICMP Length

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7g)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=255, plen=16)/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(lladdr=str(self.node(1).iface(0).ll_addr))


class OptionOfLengthZeroTestCase(InvalidNeighborSolicitationHandlingHelper):
    """
    Invalid Neighbor Solicitation Handling - Option of Length 0

    Verify that a node takes the proper actions upon receipt of an invalid
    Neighbor Solicitation.

    @private
    Source:       IPv6 Ready Phase-1/Phase-2 Test Specification Core
                  Protocols (Test v6LC.2.1.7h)
    """

    def set_up(self):
        self.p = IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()), hlim=255)/\
                    ICMPv6ND_NS(tgt=str(self.target(1).link_local_ip()))/\
                        ICMPv6NDOptSrcLLAddr(len=0, lladdr=str(self.node(1).iface(0).ll_addr))
                        