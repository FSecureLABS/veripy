from contrib.rfc2460 import hop_limit_zero as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class HopLimitZeroTestCaseTestCase(ComplianceTestTestCase):
    
    def test_hop_limit_zero(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()), hlim=64)/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.HopLimitZeroTestCase)
        
        self.assertCheckPasses(o)

    def test_hop_limit_zero_no_reply(self):
        self.ifx.replies_with(None)
        
        o = self.get_outcome(suite.HopLimitZeroTestCase)
        
        self.assertCheckFails(o)
    
    def test_hop_limit_zero_not_greater_than_zero(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()), hlim=0)/ICMPv6EchoReply())

        o = self.get_outcome(suite.HopLimitZeroTestCase)

        self.assertCheckFails(o)
