from constants import *
import math
from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class ReachabilityConfigurationHelper(ComplianceTestCase):

    disabled_nd = True
    disabled_ra = True
    restart_uut = True

    def set_up(self):
        raise Exception("override #set_up to define #src and #dst")

    def run(self):
        self.logger.info("Sending NRA (Override Flag set, Retransmit Timer of 1 second, Reachable Time of 30 seconds) ...")  
        self.router(1).send( \
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst=str(self.target(1).link_local_ip()))/
                ICMPv6ND_RA(O=True, retranstimer=1, reachabletime=0.5)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)/
                    ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/
                    ICMPv6NDOptPrefixInfo(prefixlen=self.router(1).global_ip(iface=1).prefix_size, prefix=self.router(1).global_ip(iface=1).network()), iface=1)

        # Step 1 ###############################################################
        self.logger.info("Sending ICMP Echo Request from TN1 to NUT...")
        self.node(1).send( \
            IPv6(src=str(self.src), dst=str(self.dst))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        # Step 2 ###############################################################
        self.logger.info("Waiting for the NUT to send Neighbor Solicitations...")
        self.ui.wait(3)
        r1 = self.node(1).received(src=self.dst, dst=self.src.solicited_node(), type=ICMPv6ND_NS)
        
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a Neighbor Solicitation for TN1")
        assertLessThanOrEqualTo(3, len(r1), "did not expect to receive more than three Neighbor Solicitations for TN1")

        self.logger.info("Checking the retransmit interval...")
        for i in range(0, len(r1) - 2):
            assertHasLayer(ICMPv6NDOptSrcLLAddr, r1[i], "expected each Neighbor Solicitation to contain a Source Link-Layer Address option")
            assertEqual(r1[i][ICMPv6NDOptSrcLLAddr].lladdr, self.target(1).ll_addr(), "expected the Source Link-Layer address to be of the UUT")
            assertHasLayer(ICMPv6NDOptSrcLLAddr, r1[i+1], "expected each Neighbor Solicitation to contain a Source Link-Layer Address option")
            assertEqual(r1[i+1][ICMPv6NDOptSrcLLAddr].lladdr, self.target(1).ll_addr(), "expected the Source Link-Layer address to be of the UUT")

            delta = r1[i+1].time - r1[i].time

            assertGreaterThanOrEqualTo(0.8, delta, "expected retransmit interval to be between %.2f and %.2f seconds, got %.2f" % (0.8, 1.2, delta))
            assertLessThanOrEqualTo(1.2, delta, "expected retransmit interval to be between %.2f and %.2f seconds, %.2f" % (0.8, 1.2, delta))

        self.logger.info("Sending a Neighbor Advertisement...")
        self.node(1).send(
            IPv6(src=str(self.src), dst=str(self.dst))/
                ICMPv6ND_NA(tgt=str(self.src), R=False, S=True, O=True)/
                    ICMPv6NDOptDstLLAddr(lladdr=self.node(1).iface(0).ll_addr))
            
        self.logger.info("Checking for Echo Reply...")
        r1 = self.node(1).received(src=self.dst, seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from the NUT, got %d" % (len(r1)))
             
        # Step 3 # Wait for the NUT's NCE for TN1 to become STALE ##############
        self.ui.wait(int(math.ceil(MAX_RANDOM_FACTOR*0.5)))

        self.node(1).clear_received()
        # Step 4 ###############################################################
        self.logger.info("Sending ICMP Echo Request from TN1 to NUT...")
        self.node(1).send( \
            IPv6(src=str(self.src), dst=str(self.dst))/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        # Step 5 ###############################################################
        self.logger.info("Checking for an Echo Reply...")
        r1 = self.node(1).received(src=self.dst, seq=self.seq(), type=ICMPv6EchoReply)
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply from the NUT, got %d" % (len(r1)))
        
        # Step 6 # Wait for the NUT's NCE for TN1 to become PROBE ##############
        self.ui.wait(DELAY_FIRST_PROBE_TIME)

        self.node(1).clear_received()
        self.ui.wait(3)
        # Step 7 ###############################################################
        r1 = self.node(1).received(src=self.dst, dst=self.src.solicited_node(), type=ICMPv6ND_NS)

        assertGreaterThanOrEqualTo(1, len(r1), "expected UUT to start probing for TN1")
        assertLessThanOrEqualTo(3, len(r1), "did not expect to receive more than three Neighbor Solicitations for TN1")
        
        self.logger.info("Checking the retransmit interval...")
        for i in range(0, len(r1) - 2):
            assertHasLayer(ICMPv6NDOptSrcLLAddr, r1[i], "expected each Neighbor Solicitation to contain a Source Link-Layer Address option")
            assertEqual(r1[i][ICMPv6NDOptSrcLLAddr].lladdr, self.target(1).ll_addr(), "expected the Source Link-Layer address to be of the UUT")
            assertHasLayer(ICMPv6NDOptSrcLLAddr, r1[i+1], "expected each Neighbor Solicitation to contain a Source Link-Layer Address option")
            assertEqual(r1[i+1][ICMPv6NDOptSrcLLAddr].lladdr, self.target(1).ll_addr(), "expected the Source Link-Layer address to be of the UUT")

            delta = r1[i+1].time - r1[i].time

            assertGreaterThanOrEqualTo(0.8, delta, "expected retransmit interval to be between %.2f and %.2f seconds, got %.2f" % (0.8, 1.2, delta))
            assertLessThanOrEqualTo(1.2, delta, "expected retransmit interval to be between %.2f and %.2f seconds, %.2f" % (0.8, 1.2, delta))


class LinkLocalToLinkLocalTestCase(ReachabilityConfigurationHelper):
    """
    Neighbor Solicitation Origination Reachability Configuration - Link-local
    to Link-local

    Verify that a node properly originates Neighbor Solicitations when trying
    to confirm the reachability of a neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.6a)
    """

    def set_up(self):
        self.src = self.node(1).link_local_ip()
        self.dst = self.target(1).link_local_ip()
        

class GlobalToGlobalTestCase(ReachabilityConfigurationHelper):
    """
    Neighbor Solicitation Origination Reachability Configuration - Global
    to Global

    Verify that a node properly originates Neighbor Solicitations when trying
    to confirm the reachability of a neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.6b)
    """

    def set_up(self):
        self.src = self.node(1).global_ip()
        self.dst = self.target(1).global_ip()
        
                
class LinkLocalToGlobalTestCase(ReachabilityConfigurationHelper):
    """
    Neighbor Solicitation Origination Reachability Configuration - Link-local
    to Global

    Verify that a node properly originates Neighbor Solicitations when trying
    to confirm the reachability of a neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.6c)
    """

    def set_up(self):
        self.src = self.node(1).link_local_ip()
        self.dst = self.target(1).global_ip()
        
                
class GlobalToLinkLocalTestCase(ReachabilityConfigurationHelper):
    """
    Neighbor Solicitation Origination Reachability Configuration - Global
    to Link-local

    Verify that a node properly originates Neighbor Solicitations when trying
    to confirm the reachability of a neighbor.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.6d)
    """

    def set_up(self):
        self.src = self.node(1).global_ip()
        self.dst = self.target(1).link_local_ip()
