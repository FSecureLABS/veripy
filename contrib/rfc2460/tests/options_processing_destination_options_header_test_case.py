from contrib.rfc2460 import options_processing_destination_options_header as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class OptionsProcessingDestinationOptionsHeaderTestCase(ComplianceTestTestCase):

    def test_pad1_option_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderPad1TestCase)

        self.assertCheckPasses(o)
    
    def test_pad1_option_no_reply_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderPad1TestCase)
        
        self.assertCheckFails(o)
    
    def test_padn_option_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderPadNTestCase)
        
        self.assertCheckPasses(o)
    
    def test_padn_option_no_reply_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderPadNTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_00_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits00TestCase)

        self.assertCheckPasses(o)
    
    def test_most_significant_bits_00_no_reply_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits00TestCase)

        self.assertCheckFails(o)
    
    def test_most_significant_bits_01_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits01TestCase)

        self.assertCheckPasses(o)

    def test_most_significant_bits_01_reply_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits01TestCase)

        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_unicast_destination_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)

        self.assertCheckPasses(o)

    def test_most_significant_bits_10_unicast_destination_incorrect_code_test_case(self):
	self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=3,ptr=42))
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_unicast_destination_incorrect_pointer_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=32))
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_unicast_destination_no_reply_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_unicast_destination_exceed_minimum_mtu_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42)/("\0"*3000))
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_unicast_destination_incorrect_destination_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.ifx.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_unicast_destination_incorrect_source_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_unicast_destination_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckPasses(o)
    
    def test_most_significant_bits_11_unicast_destination_incorrect_code_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_unicast_destination_incorrect_pointer_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=32))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_unicast_destination_no_reply_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_unicast_destination_exceed_minimum_mtu_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42)/("\0"*3000))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_unicast_destination_incorrect_destination_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.ifx.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_unicast_destination_incorrect_source_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11UnicastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_multicast_destination_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckPasses(o)
    
    def test_most_significant_bits_10_multicast_destination_incorrect_code_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=3,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_multicast_destination_incorrect_pointer_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=32))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckFails(o)
        
    def test_most_significant_bits_10_multicast_destination_no_reply_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_multicast_destination_exceed_minimum_mtu_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42)/("\0"*3000))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_10_multicast_destination_incorrect_destination_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.ifx.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))

        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits10MulticastDestinationTestCase)
        
        self.assertCheckFails(o)
    
    def test_most_significant_bits_11_multicast_destination_test_case(self):
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)

        self.assertCheckPasses(o)
    
    def test_most_significant_bits_11_multicast_destination_reply_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=42))
        
        o = self.get_outcome(suite.OptionsProcessingDestinationOptionsHeaderMostSignificantBits11MulticastDestinationTestCase)

        self.assertCheckFails(o)
        