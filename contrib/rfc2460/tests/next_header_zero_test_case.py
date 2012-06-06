from contrib.rfc2460 import next_header_zero as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class NextHeaderZeroTestCase(ComplianceTestTestCase):

    def test_next_header_zero(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=40))
        
        o = self.get_outcome(suite.NextHeaderZeroTestCase)
        
        self.assertCheckPasses(o)
    
    def test_next_header_zero_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=40))

        o = self.get_outcome(suite.NextHeaderZeroTestCase)

        self.assertCheckFails(o)

    def test_next_header_zero_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=20))
        
        o = self.get_outcome(suite.NextHeaderZeroTestCase)
        
        self.assertCheckFails(o)
    
    def test_next_header_zero_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.NextHeaderZeroTestCase)

        self.assertCheckFails(o)
        