from contrib.rfc2460 import unrecognised_next_header_in_extension_header as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UnrecognisedNextHeaderInExtensionHeaderTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UnrecognisedNextHeaderInExtensionHeaderTestCase, self).setUp()

        suite.UnrecognisedNextHeaderInExtensionHeaderTestCase.NextHeaderUnassignedValues = [143]
    
    def test_multiple_values(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=40))
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnrecognisedNextHeaderInExtensionHeaderTestCase)

        self.assertCheckPasses(o)
    
    def test_multiple_values_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=40))
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
                            
        o = self.get_outcome(suite.UnrecognisedNextHeaderInExtensionHeaderTestCase)
        
        self.assertCheckFails(o)
    
    def test_multiple_values_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=30))
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnrecognisedNextHeaderInExtensionHeaderTestCase)
        
        self.assertCheckFails(o)
    
    def test_multiple_values_no_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=40))
        
        o = self.get_outcome(suite.UnrecognisedNextHeaderInExtensionHeaderTestCase)
        
        self.assertCheckFails(o)
    
    
    def test_single_value(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=50))
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInExtensionHeaderTestCase)
        
        self.assertCheckPasses(o)
    
    def test_single_value_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=50))
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInExtensionHeaderTestCase)
        
        self.assertCheckFails(o)
    
    def test_single_value_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=40))
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInExtensionHeaderTestCase)

        self.assertCheckFails(o)
        