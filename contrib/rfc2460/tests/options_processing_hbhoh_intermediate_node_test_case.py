from contrib.rfc2460 import options_processing_hbhoh_intermediate_node as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class HopByHopOptionsHeaderPad1TestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[Pad1(), Pad1(), Pad1(), Pad1(), Pad1(), Pad1()])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.HopByHopOptionsHeaderPad1TestCase)
        
        self.assertCheckPasses(o)

    def test_no_payload(self):
        o = self.get_outcome(suite.HopByHopOptionsHeaderPad1TestCase)

        self.assertCheckFails(o)


class HopByHopOptionsHeaderPadNTestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[PadN(optlen=4)])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.HopByHopOptionsHeaderPadNTestCase)
        
        self.assertCheckPasses(o)

    def test_no_payload(self):
        o = self.get_outcome(suite.HopByHopOptionsHeaderPadNTestCase)
        
        self.assertCheckFails(o)


class HopByHopOptionsHeaderMostSignificantBits00TestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=7,optlen=4)])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits00TestCase)
        
        self.assertCheckPasses(o)

    def test_no_payload(self):
        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits00TestCase)
        
        self.assertCheckFails(o)


class HopByHopOptionsHeaderMostSignificantBits01TestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=71,optlen=4)])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits01TestCase)

        self.assertCheckFails(o)

    def test_no_payload(self):
        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits01TestCase)
        
        self.assertCheckPasses(o)


class HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=135,optlen=4)])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)

    def test_param_problem_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckPasses(o)

    def test_param_problem_delivered_incorrect_code(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=0,ptr=0x2A))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)

    def test_param_problem_delivered_incorrect_ptr(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0xAA))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)

    def test_param_problem_delivered_too_large(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A)/Raw('A'*1300))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)

    def test_param_problem_delivered_large_but_not_too_large(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A)/Raw('A'*1200))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckPasses(o)


class HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=199,optlen=4)])/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)

        self.assertCheckPasses(o)

    def test_param_problem_delivered_incorrect_code(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=0,ptr=0x2A))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered_incorrect_ptr(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0xAA))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered_too_large(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A)/Raw('A'*1300))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered_large_but_not_too_large(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A)/Raw('A'*1200))

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)

        self.assertCheckPasses(o)


class HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst='ff02::1', nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[HBHOptUnknown(otype=135,optlen=4)])/ICMPv6EchoRequest())
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckFails(o)

    def test_param_problem_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckPasses(o)

    def test_param_problem_delivered_incorrect_code(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=0,ptr=0x2A))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered_incorrect_ptr(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0xAA))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered_too_large(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A)/Raw('A'*1300))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckFails(o)

    def test_param_problem_delivered_large_but_not_too_large(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=58)/ICMPv6ParamProblem(code=2,ptr=0x2A)/Raw('A'*1200))
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckPasses(o)

    def test_multicast_not_supported(self):
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckPasses(o)

class HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase(ComplianceTestTestCase):

    def test_payload_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), nh=0)/IPv6ExtHdrHopByHop(nh=58, len=0, options=[Pad1(), Pad1(), Pad1(), Pad1(), Pad1(), Pad1()])/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)

        self.assertCheckFails(o)

    def test_icmp_param_problem_delivered(self):
        self.ify.replies_with(IPv6(src=str(self.ify.global_ip()), dst=str(self.tn4.global_ip()), nh=0)/ICMPv6ParamProblem())
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)

        self.assertCheckFails(o)

    def test_no_payload(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)

        self.assertCheckPasses(o)

    def test_multicast_not_supported(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.HopByHopOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)

        self.assertCheckPasses(o)
