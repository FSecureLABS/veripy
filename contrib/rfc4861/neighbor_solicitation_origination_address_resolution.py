from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class RetransmitIntervalHelper(ComplianceTestCase):
    
    disabled_nd = True
    disabled_ra = True
    restart_uut = True
    
    def set_up(self):
        raise Exception("override #set_up to define #retranstimer, #echo_src and #echo_dst")
        
    def run(self):
        self.logger.info("Sending Router Advertisement (Retransmit Timer of %d seconds)..." % self.retranstimer)
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(O=True, routerlifetime=100, reachabletime=10,retranstimer=self.retranstimer)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)/
                    ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/
                    ICMPv6NDOptPrefixInfo(prefixlen=self.link(2).v6_prefix_size, prefix=self.link(2).v6_prefix, validlifetime=20, preferredlifetime=20), iface=1)

        self.logger.info("Sending ICMP Echo Request ...")
        self.node(1).send( \
            IPv6(src=str(self.echo_src), dst=str(self.echo_dst))/
                ICMPv6EchoRequest())

        self.ui.wait(self.retranstimer * 4)
        self.logger.info("Checking for Neighbor Solicitation from HUT...")
        r1 = self.node(1).received(src=self.echo_dst, dst=self.echo_src.solicited_node(), type=ICMPv6ND_NS)

        assertEqual(3, len(r1), "expected to receive 3 Neighbor Solicitations, got %d" % (len(r1)))

        self.logger.info("Checking the retransmit interval...")
        for i in range(0, len(r1) - 2):
            assertHasLayer(ICMPv6NDOptSrcLLAddr, r1[i], "expected each Neighbor Solicitation to contain a Source Link-Layer Address option")
            assertEqual(r1[i][ICMPv6NDOptSrcLLAddr].lladdr, self.target(1).ll_addr(), "expected the Source Link-Layer address to be of the UUT")
            assertHasLayer(ICMPv6NDOptSrcLLAddr, r1[i+1], "expected each Neighbor Solicitation to contain a Source Link-Layer Address option")
            assertEqual(r1[i+1][ICMPv6NDOptSrcLLAddr].lladdr, self.target(1).ll_addr(), "expected the Source Link-Layer address to be of the UUT")

            delta = r1[i+1].time - r1[i].time

            assertGreaterThanOrEqualTo(self.retranstimer * 0.8, delta, "expected retransmit interval to be between %.2f and %.2f seconds, got %.2f" % (self.retranstimer * 0.8, self.retranstimer * 1.2, delta))
            assertLessThanOrEqualTo(self.retranstimer * 1.2, delta, "expected retransmit interval to be between %.2f and %.2f seconds, %.2f" % (self.retranstimer * 0.8, self.retranstimer * 1.2, delta))


class LinkLocalRetransmitInterval1TestCase(RetransmitIntervalHelper):
    """
    Neighbor Solicitation Origination, Address Resolution - Target Address
    Being Link-local (restransmit interval = 1)
     
    Verify that a node properly originates Neighbor Solicitations when trying
    to resolve the address of a neighbor.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.5a)
    """

    def set_up(self):
        self.retranstimer = 1

        self.echo_src = self.node(1).link_local_ip()
        self.echo_dst = self.target(1).link_local_ip()


class LinkLocalRetransmitInterval5TestCase(RetransmitIntervalHelper):
    """
    Neighbor Solicitation Origination, Address Resolution - Target Address
    Being Link-local (restransmit interval = 5)

    Verify that a node properly originates Neighbor Solicitations when trying
    to resolve the address of a neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.5a)
    """

    def set_up(self):
        self.retranstimer = 5

        self.echo_src = self.node(1).link_local_ip()
        self.echo_dst = self.target(1).link_local_ip()

            
class GlobalRetransmitInterval1TestCase(RetransmitIntervalHelper):
    """
    Neighbor Solicitation Origination, Address Resolution - Target Address
    Being Global (restransmit interval = 1)
     
    Verify that a node properly originates Neighbor Solicitations when trying
    to resolve the address of a neighbor.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.5b)
    """

    def set_up(self):
        self.retranstimer = 1

        self.echo_src = self.node(1).global_ip()
        self.echo_dst = self.target(1).global_ip()


class GlobalRetransmitInterval5TestCase(RetransmitIntervalHelper):
    """
    Neighbor Solicitation Origination, Address Resolution - Target Address
    Being Global (restransmit interval = 5)

    Verify that a node properly originates Neighbor Solicitations when trying
    to resolve the address of a neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.5b)
    """

    def set_up(self):
        self.retranstimer = 5

        self.echo_src = self.node(1).global_ip()
        self.echo_dst = self.target(1).global_ip()
        