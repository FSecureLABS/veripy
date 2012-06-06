from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase(ComplianceTestCase):
    """
    Extension Header Processing Order - Destination Options Header precedes
    Fragment Header, Error from Destination Options Header
    
    Verify that a node properly processes the headers of an IPv6 packet in
    the correct order.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.4a)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with hop-by-hop, destination options and fragment extension headers.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0, plen=37)/
                IPv6ExtHdrHopByHop(nh=60, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    IPv6ExtHdrDestOpt(nh=44,len=0,options=[HBHOptUnknown(otype=135,optlen=4)])/
                        IPv6ExtHdrFragment(nh=58, offset=0, m=1)/
                            ICMPv6EchoRequest(data="\0\0\0\0\0", seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        self.logger.info("Found all possible responses, validating them...")
        assertEqual(1, len(r1), "expected to receive a single ICMPv6 Parameter Problem message, got %s" % (len(r1)))
        assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem to have a Code Field of 2, got %s" % (r1[0].getlayer(ICMPv6ParamProblem).code))
        assertEqual(50, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem to have a Pointer Field of 50, got %s" % (r1[0].getlayer(ICMPv6ParamProblem).ptr))


class DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase(ComplianceTestCase):
    """
    Extension Header Processing Order - Destination Options Header precedes
    Fragment Header, Error from Fragment Header
    
    Verify that a node properly processes the headers of an IPv6 packet in
    the correct order.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.4b)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with hop-by-hop, destination options and fragment extension headers.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0, plen=37)/
                IPv6ExtHdrHopByHop(nh=60, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    IPv6ExtHdrDestOpt(nh=44,len=0,options=[HBHOptUnknown(otype=7,optlen=4)])/
                        IPv6ExtHdrFragment(nh=58, offset=0, m=1)/
                            ICMPv6EchoRequest(data="\0\0\0\0\0", seq=self.next_seq()))
                            
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        self.logger.info("Got %s. Expecting ICMPv6 Parameter Problem.", repr(r1))
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")
        assertEqual(0, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem to have a Code Field of 0, got %s" % (r1[0].getlayer(ICMPv6ParamProblem).code))
        assertEqual(4, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem to have a Pointer Field of 4, got %s" % (r1[0].getlayer(ICMPv6ParamProblem).ptr))

class FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase(ComplianceTestCase):
    """
    Extension Header Processing Order - Fragment Header precedes Destination
    Options Header, Error from Fragment Header
    
    Verify that a node properly processes the headers of an IPv6 packet in the
    correct order.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.4c)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with hop-by-hop, destination options and fragment extension headers.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0, plen=37)/
                IPv6ExtHdrHopByHop(nh=44, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    IPv6ExtHdrFragment(nh=60, offset=0, m=1)/
                        IPv6ExtHdrDestOpt(nh=58,len=0,options=[HBHOptUnknown(otype=135,optlen=4)])/
                            ICMPv6EchoRequest(data="\0\0\0\0\0", seq=self.next_seq()))

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        self.logger.info("Found all possible responses, validating them...")
        assertEqual(1, len(r1), "expecting to receive an ICMPv6 Parameter Problem")
        assertEqual(0, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem to have a Code Field of 0")
        assertEqual(4, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem to have a Pointer Field of 4")

class FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase(ComplianceTestCase):
    """
    Extension Header Processing Order - Fragment Header precedes Destination
    Options Header, Error from Destination Options Header
    
    Verify that a node properly processes the headers of an IPv6 packet in
    the correct order.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.4d)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with hop-by-hop, destination options and fragment extension headers.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0, plen=37)/
                IPv6ExtHdrHopByHop(nh=44, len=0, options=[PadN(otype='PadN', optlen=4)])/
                    IPv6ExtHdrFragment(nh=60, offset=0, m=0)/
                        IPv6ExtHdrDestOpt(nh=58,len=0,options=[HBHOptUnknown(otype=135,optlen=4)])/
                            ICMPv6EchoRequest(data="\0\0\0\0\0", seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)
        self.logger.info("Found all possible responses, validating them...")
        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")
        
        if r1[0].getlayer(ICMPv6ParamProblem).haslayer(IPv6ExtHdrFragment):
            assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 0")
            assertEqual(58, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 0x3a")
        else:
            assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 0")
            assertEqual(50, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 0x32")
