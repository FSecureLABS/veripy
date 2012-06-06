from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class UnrecognisedRoutingTypeHelper(ComplianceTestCase):

    def set_up(self):
        raise Exception('must override set_up() to define #rt')
    
    def run(self):
        self.logger.info("Sending IPv6 packet header with a Routing Type of %d.", self.rt)
        self.node(2).send( \
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), nh=43)/
                IPv6ExtHdrRouting(nh=58, len=6, type=self.rt, segleft=0, addresses=[str(self.node(2).global_ip()), str(self.node(3).global_ip()), str(self.router(1).global_ip())])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
                    
        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")


class UnrecognisedRoutingTypeType33TestCase(UnrecognisedRoutingTypeHelper):
    """
    Unrecognized Routing Type (End Node) - Unrecognised Routing Type 33
    
    Verify that a node properly processes an IPv6 packet destined for it
    that contains a Routing header with an unrecognized Routing Type
    value.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.9a)
    """
    
    def set_up(self):
        self.rt = 33


class UnrecognisedRoutingTypeType0TestCase(UnrecognisedRoutingTypeHelper):
    """
    Unrecognized Routing Type (End Node) - Unrecognised Routing Type 0
    
    Verify that a node properly processes an IPv6 packet destined for it
    that contains a Routing header with an unrecognized Routing Type
    value.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.9b)
    """

    def set_up(self):
        self.rt = 0


class UnrecognisedRoutingTypeIntermediateNodeHelper(ComplianceTestCase):

    def set_up(self):
        raise Exception('must override set_up() to define #rt')
    
    def run(self):
        self.logger.info("Sending IPv6 packet header with a Routing Type of %d.", self.rt)
        self.node(2).send( \
            IPv6(src=str(self.node(2).global_ip()), dst=str(self.target(1).global_ip()), nh=43)/
                IPv6ExtHdrRouting(nh=58, len=6, type=self.rt, segleft=0, addresses=[str(self.node(2).global_ip()), str(self.node(3).global_ip()), str(self.router(1).global_ip())])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
                    
        self.logger.info("Checking for a reply...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive an ICMPv6 Echo Reply")

        self.logger.info("Checking for a parameter problem...")
        r1 = self.node(2).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")
        assertEqual(0x2a, r1[0].getlayer(ICMPv6ParamProblem).ptr)
        assertEqual(0, r1[0].getlayer(ICMPv6ParamProblem).code)


class UnrecognisedRoutingTypeType33IntermediateNodeTestCase(UnrecognisedRoutingTypeIntermediateNodeHelper):
    """
    Unrecognized Routing Type - Type 33

    Verify that a node properly processes an IPv6 packet as the intermediate
    node that contains a Routing header with an unrecognized Routing Type
    value.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.10a)
    """

    def set_up(self):
        self.rt = 33


class UnrecognisedRoutingTypeType0IntermediateNodeTestCase(UnrecognisedRoutingTypeIntermediateNodeHelper):
    """
    Unrecognized Routing Type - Type 0

    Verify that a node properly processes an IPv6 packet as the intermediate
    node that contains a Routing header with an unrecognized Routing Type
    value.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.10b)
    """

    def set_up(self):
        self.rt = 0
