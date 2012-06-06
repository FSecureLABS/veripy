from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase

class PrefixInformationOptionProcessingTestCase(ComplianceTestCase):
    """
    Prefix Information Option Processing, On-link Flag (Hosts Only)
     
    Verify that a host properly processes the on-link flag of a Prefix
    Information Option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (Test v6LC.2.1.3)
    """

    disabled_nd = True
    disabled_ra = True
    restart_uut = True
    
    def run(self):
        self.logger.info("Sending Router Advertisment from TR1, with on-link flag set... ")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(routerlifetime=100, reachabletime=10, retranstimer=1, O=True)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)/
                    ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/
                    ICMPv6NDOptPrefixInfo(L=True, validlifetime=0x14 , preferredlifetime=0x14 , prefixlen=self.link(2).v6_prefix_size, prefix=str(self.link(2).v6_prefix)), iface=1)
        
        self.logger.info("Sending Echo Request from TR1...")
        self.router(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.ui.wait(10)
        self.logger.info("Checking for Neighbor Solicitatons...")
        r1 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.router(1).global_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
        
        assertEqual(3, len(r1), "expected to receive 3 Neighbor Solicitations")

        for p in r1:
            assertEqual(self.router(1).global_ip(iface=1), p.getlayer(ICMPv6ND_NS).tgt, "expected all Neighbor Solicitations to have a target of %s" % (self.router(1).global_ip(iface=1)))
        
        self.router(1).clear_received()
        self.logger.info("Sending Router Advertisment from TR1, with on-link flag clear... ")
        self.router(1).send(
            IPv6(src=str(self.router(1).link_local_ip(iface=1)), dst="ff02::1")/
                ICMPv6ND_RA(routerlifetime=100, reachabletime=10, retranstimer=1, O=True)/
                    ICMPv6NDOptSrcLLAddr(lladdr=self.router(1).iface(1).ll_addr)/
                    ICMPv6NDOptMTU(mtu=self.router(1).iface(1).ll_protocol.mtu)/
                    ICMPv6NDOptPrefixInfo(L=False, validlifetime=0x14 , preferredlifetime=0x14 , prefix=str(self.link(2).v6_prefix)), iface=1)
        
        self.logger.info("Sending Echo Request from TR1...")
        self.router(1).send(
            IPv6(src=str(self.router(1).global_ip(iface=1)), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()), iface=1)

        self.ui.wait(10)
        self.logger.info("Checking for Neighbor Solicitatons...")
        r2 = self.router(1).received(iface=1, src=self.target(1).global_ip(), dst=self.router(1).global_ip(iface=1).solicited_node(), type=ICMPv6ND_NS)
        
        assertEqual(3, len(r2), "expected to receive 3 Neighbor Solicitations")
        
        for p in r2:
            assertEqual(self.router(1).global_ip(iface=1), p.getlayer(ICMPv6ND_NS).tgt, "expected all Neighbor Solicitations to have a target of %s" % (self.router(1).global_ip(iface=1)))
            