from scapy.all import *
from veripy.assertions import *
from veripy.models import ComplianceTestCase


class HopByHopOptionsHeaderPad1TestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header - Pad1 Option

    Verify that a node properly processes both known and unknown options, and
    acts in accordance with the highest order two bits of the option.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.7a)
    """
    def run(self):
        self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[Pad1(), Pad1(), Pad1(), Pad1(), Pad1(), Pad1()])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for forwarded packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))
        assertTrue(r1[0].haslayer(IPv6ExtHdrHopByHop))


class HopByHopOptionsHeaderPadNTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header - PadN Option

    Verify that a node properly processes both known and unknown options, and
    acts in accordance with the highest order two bits of the option.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.7b)
    """
    def run(self):
        self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[PadN(optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for forwarded packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))
        assertTrue(r1[0].haslayer(IPv6ExtHdrHopByHop))


class HopByHopOptionsHeaderMostSignificantBits00TestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header - Most Significant Bits 00b

    Verify that a node properly processes both known and unknown options, and
    acts in accordance with the highest order two bits of the option.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.7c)
    """
    def run(self):
        self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=7,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(1, len(r1), "expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))
        assertTrue(r1[0].haslayer(IPv6ExtHdrHopByHop))


class HopByHopOptionsHeaderMostSignificantBits01TestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header - Most Significant Bits 01b

    Verify that a node properly processes both known and unknown options, and
    acts in accordance with the highest order two bits of the option.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.7d)
    """
    def run(self):
        self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=71,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

class HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header - Most Significant Bits 10b,
    unicast destination

    Verify that a node properly processes both known and unknown options, and
    acts in accordance with the highest order two bits of the option.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification Core
                    Protocols (v6LC.1.2.7e)
    """
    def run(self):
        self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=135,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for forwarded packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

        self.logger.info("Checking for Parameter Problems returned to TN4...")
        r2 = self.node(4).received(src=self.target(2).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r2), "expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

        assertEqual(2, r2[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem code 2, got %d" % (r2[0].getlayer(ICMPv6ParamProblem).code))
        assertEqual(0x2A, r2[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem pointer 0x2A, got %d" % (r2[0].getlayer(ICMPv6ParamProblem).code))
        assertLessThan(1280, len(r2[0]), "did not expect ICMPv6 Parameter Problem packet to exceed 1280 (IPv6 MTU)")


class HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (Intermediate Node) - Most Significant Bits 11b unicast destination

    Verify that a node properly processes both known and unknown options, and acts in accordance with the highest order two bits of the option.

    @private
    Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core Protocols (v6LC.1.2.7f)
    """
    def run(self):
        self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
        self.node(4).send( \
            IPv6(src=str(self.node(4).global_ip()), dst=str(self.node(1).global_ip()), nh=0)/
                IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=199,optlen=4)])/
                    ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for forwarded packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

        self.logger.info("Checking for Parameter Problems returned to TN4...")
        r2 = self.node(4).received(src=self.target(2).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(1, len(r2), "expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

        assertEqual(2, r2[0].getlayer(ICMPv6ParamProblem).code,"expected the ICMPv6 Parameter Problem code to = 2")
        assertEqual(0x2A, r2[0].getlayer(ICMPv6ParamProblem).ptr,"expected the ICMPv6 Parameter Problem pointer to = 0x2A")
        assertLessThan(1280, len(r2[0]),"did not expect ICMPv6 Parameter Problem packet to exceed 1280 (IPv6 MTU)")


class HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header (Intermediate Node) - Most Significant Bits 10b, multicast destination

    Verify that a node properly processes both known and unknown options, and acts in accordance with the highest order two bits of the option.

    @private
    Source:           IPv6 Ready Phase-1/Phase-2 Test Specification Core Protocols (v6LC.1.2.7g)
    """
    def run(self):
        if not self.ui.ask('Does the UUT support multicast routing?'):
            assertEqual(True,True,'Test omitted because UUT doesn\'t support multicast routing')
        else:
            self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
            self.node(4).send( \
                IPv6(src=str(self.node(4).global_ip()), dst='ff02::1', nh=0)/
                    IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=135,optlen=4)])/
                        ICMPv6EchoRequest(seq=self.next_seq()))

            self.logger.info("Checking for forwarded packets...")
            r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

            assertEqual(0, len(r1), "did not expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

            self.logger.info("Checking for Parameter Problems returned to TN4...")
            r2 = self.node(4).received(src=self.target(2).global_ip(), type=ICMPv6ParamProblem)

            assertEqual(1, len(r2), "expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))
            
            assertEqual(2, r2[0].getlayer(ICMPv6ParamProblem).code, "expected the ICMPv6 Parameter Problem code to = 2")
            assertEqual(0x2A, r2[0].getlayer(ICMPv6ParamProblem).ptr, "expected the ICMPv6 Parameter Problem pointer to = 0x2A")
            assertLessThan(1280,len(r2[0]),"did not expect ICMPv6 Parameter Problem packet to exceed 1280 (IPv6 MTU)")


class HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase(ComplianceTestCase):
    """
    Option Processing, Hop-by-Hop Options Header - Most Significant Bits 10b,
    multicast destination

    Verify that a node properly processes both known and unknown options, and
    acts in accordance with the highest order two bits of the option.

    @private
    Source:         IPv6 Ready Phase-1/Phase-2 Test Specification
                    Core Protocols (v6LC.1.2.7g)
    """
    def run(self):
        if not self.ui.ask('Does the UUT support multicast routing?'):
            assertEqual(True,True,'Test omitted because UUT doesn\'t support multicast routing')
        else:
            self.logger.debug("Sending an IPv6 packet header with a hop-by-hop options header.")
            self.node(4).send( \
                IPv6(src=str(self.node(4).global_ip()), dst='ff02::1', nh=0)/
                    IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=199,optlen=4)])/
                        ICMPv6EchoRequest(seq=self.next_seq()))

        self.logger.info("Checking for forwarded packets...")
        r1 = self.node(1).received(src=self.node(4).global_ip(), seq=self.seq(), type=ICMPv6EchoRequest)

        assertEqual(0, len(r1), "did not expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))

        self.logger.info("Checking for Parameter Problems returned to TN4...")
        r2 = self.node(4).received(src=self.target(2).global_ip(), type=ICMPv6ParamProblem)

        assertEqual(0, len(r2), "did not expected to receive an ICMPv6EchoRequest (seq: %d)" % (self.seq()))
        