from contrib.rfc2460 import option_processing_order as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class OptionProcessingOrderTestCaseTestCase(ComplianceTestTestCase):

    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_01(self):
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits01TestCase)
        
        self.assertCheckPasses(o)
    
    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_01_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits01TestCase)
        
        self.assertCheckFails(o)
    
    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_10(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=48))
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase)
        
        self.assertCheckPasses(o)

    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_10_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase)

        self.assertCheckFails(o)

    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_10_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=48))
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase)
        
        self.assertCheckFails(o)
    
    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_10_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=38))
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits10TestCase)
        
        self.assertCheckFails(o)

    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_11(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=48))
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase)

        self.assertCheckPasses(o)


    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_11_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase)
        
        self.assertCheckFails(o)

    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_11_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=48))
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase)
        
        self.assertCheckFails(o)

    def test_first_option_has_most_significant_bits_00_next_has_most_significant_bits_11_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2,ptr=38))
        
        o = self.get_outcome(suite.FirstOptionHasMostSignificantBits00NextHasMostSignificantBits11TestCase)
        
        self.assertCheckFails(o)
