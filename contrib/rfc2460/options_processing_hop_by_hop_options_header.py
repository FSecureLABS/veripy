from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class OptionsProcessingHopByHopOptionsHeaderPad1TestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Pad1 Option
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6a)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[Pad1(), Pad1(), Pad1(), Pad1(), Pad1(), Pad1()])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")

class OptionsProcessingHopByHopOptionsHeaderPadNTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - PadN Option
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6b)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[PadN(optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")

class OptionsProcessingHopByHopOptionsHeaderMostSignificantBits00TestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Most Significant Bits 00b
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6c)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=7,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Echo Reply")

class OptionsProcessingHopByHopOptionsHeaderMostSignificantBits01TestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Most Significant Bits 01b
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6d)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=71,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), seq=self.seq(), type=ICMPv6EchoReply)

        assertEqual(0, len(r1), "did not expect to receive a reply")

class OptionsProcessingHopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Most Significant Bits 10b, unicast destination
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6e)
    """
    
    def run(self):
        self.logger.info("Sending a IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=135,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))
        
        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")

	assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 2")
	assertEqual(42, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 42.")
        assertLessThan(1280, len(r1[0].getlayer(IPv6)), "received message exceeds minimum IPv6 MTU")

class OptionsProcessingHopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Most Significant Bits 11b, unicast destination
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6f)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst=str(self.target(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=199,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")

	assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem message to have a Code Field of 2")
	assertEqual(42, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem message to have a Pointer Field of 42.")
	assertLessThan(1280, len(r1[0].getlayer(IPv6)), "received message exceeds minimum IPv6 MTU")

class OptionsProcessingHopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Most Significant Bits 10b, multicast destination
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6g)
    """
    
    def run(self):
        self.logger.info("Sending IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::1", nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=135,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for a reply...")
        r1 = self.node(1).received(src=self.target(1).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r1), "expected to receive an ICMPv6 Parameter Problem")

	assertEqual(2, r1[0].getlayer(ICMPv6ParamProblem).code, "expected the Parameter Problem to have a Code Field of 2")
	assertEqual(42, r1[0].getlayer(ICMPv6ParamProblem).ptr, "expected the Parameter Problem to have a Pointer Field of 0x2a")
	assertLessThan(1280, len(r1[0].getlayer(IPv6)), "the received message exceeds minimum IPv6 MTU")

class OptionsProcessingHopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (End Node) - Most Significant Bits 11b, multicast destination
    
    Verify that a node properly processes both known and unknown options,
    and acts in accordance with the highest order two bits of the option.
    
    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.6h)
    """
    
    def run(self):
        self.logger.info("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(1).send( \
            IPv6(src=str(self.node(1).global_ip()), dst="ff02::1", nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=199,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.seq()))

        self.logger.info("Checking for a reply...")
	r1 = self.node(1).received(src=self.target(1).global_ip())

        assertEqual(0, len(r1), "did not expect to receive a reply")
