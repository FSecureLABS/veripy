from contrib.rfc2460 import unrecognised_next_header as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UnrecognisedNextHeaderTestCase(ComplianceTestTestCase):

    def setUp(self):
        super(UnrecognisedNextHeaderTestCase, self).setUp()

        suite.UnrecognisedNextHeaderInIPv6HeaderTestCase.NextHeaderUnassignedValues = [143]
    
    def test_unrecognised_next_header_in_ipv6_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=6))
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnrecognisedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckPasses(o)

    def test_unrecognised_next_header_in_ipv6_header_no_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=6))
        
        o = self.get_outcome(suite.UnrecognisedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckFails(o)

    def test_unrecognised_next_header_in_ipv6_header_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=6))
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.UnrecognisedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckFails(o)
    
    def test_unrecognised_next_header_in_ipv6_header_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=4))
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnrecognisedNextHeaderInIPv6HeaderTestCase)
        
        self.assertCheckFails(o)
    
    def test_unexpected_next_header_in_ipv6_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=46))
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckPasses(o)
    
    def test_unexpected_next_header_in_ipv6_header_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckFails(o)
    
    def test_unexpected_next_header_in_ipv6_header_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=46))
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckFails(o)
    
    def test_unexpected_next_header_in_ipv6_header_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=20))
        
        o = self.get_outcome(suite.UnexpectedNextHeaderInIPv6HeaderTestCase)

        self.assertCheckFails(o)
