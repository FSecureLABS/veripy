from contrib.rfc4443 import hop_limit_exceeded as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class ReceiveHopLimit0TestCase(ComplianceTestTestCase):
    
    def test_hop_0_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0))
        
        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckPasses(o)
        
    
    def test_hop_0_no_reply(self):   
        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_0_invalid_unused(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0, unused=1))

        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_0_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_0_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_0_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))

        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_0_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1))

        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_0_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0)/Raw(load="a" * 1300))

        o = self.get_outcome(suite.ReceiveHopLimit0TestCase)

        self.assertCheckFails(o)

        
class DecrementHopLimitTo0TestCase(ComplianceTestTestCase):
    
    def test_hop_1_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckPasses(o)
        
    
    def test_hop_1_no_reply(self):   
        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_1_invalid_unused(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0, unused=1))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_1_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_1_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_1_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_1_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=1))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        
    def test_hop_1_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0)/Raw(load="a" * 1300))

        o = self.get_outcome(suite.DecrementHopLimitTo0TestCase)

        self.assertCheckFails(o)
        