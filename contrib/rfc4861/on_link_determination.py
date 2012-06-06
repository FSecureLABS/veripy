from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase, IPAddress

class OnLinkDeterminationLinkLocalTestCase(ComplianceTestCase):
    """
    On Link Determination - Link Local
     
    Verify that a node correctly determines that a destination is on-link.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.1a)
    """

    def run(self):
        self.logger.info("Sending ICMP Echo Request, to UUT's Link Local address...")
        self.node(1).send(
            IPv6(src=str(self.node(1).link_local_ip()), dst=str(self.target(1).link_local_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a reply ...")
        r1 = self.node(1).received(src=self.target(1).link_local_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a Neighbor Solicitation")
        
        assertEqual(self.node(1).link_local_ip(), IPAddress.identify(r1[0].getlayer(ICMPv6ND_NS).tgt))


class OnLinkDeterminationGlobalTestCase(ComplianceTestCase):
    """
    On Link Determination - Global Address, On-link Prefix covers TN1
     
    Verify that a node correctly determines that a destination is on-link.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.1b)
    """

    def run(self):
        self.logger.info("Sending ICMP Echo Request, to UUT's global address...")
        self.node(1).send(
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply ...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), dst=self.node(1).link_local_ip().solicited_node(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1, len(r1), "expected to receive a Neighbor Solicitation")

        assertEqual(self.node(1).global_ip(), IPAddress.identify(r1[0].getlayer(ICMPv6ND_NS).tgt))


class OnLinkDeterminationGlobalAddressTestCase(ComplianceTestCase):
    """
    On Link Determination - Global Address, On-link Prefix does not cover TN2
     
    Verify that a node correctly determines that a destination is on-link.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.2.1.1c)
    """

    def run(self):
        self.logger.info("Sending ICMP Echo Request, with UUT's global address...")
        self.node(1).send(
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()))/
                ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply ...")
        r1 = self.router(1).received(iface=1, src=self.target(1).link_local_ip(), type=ICMPv6ND_NS)
        assertGreaterThanOrEqualTo(1,len(r1), "expected to receive Neighbor Solicitation")

        assertEqual(self.router(1).link_local_ip(iface=1), IPAddress.identify(r1[0].getlayer(ICMPv6ND_NS).tgt))
        