from contrib.rfc4443 import erroneous_header_field as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class ErroneousHeaderFieldTestCase(ComplianceTestTestCase):
    
    def test_erroneous_header_valid(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=4))

        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckPasses(o)
    
    def test_erroneous_header_no_reply(self):   
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
        
    def test_erroneous_header_invalid_ptr(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=6))
        
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
        
    def test_erroneous_header_invalid_src(self):
        self.ifx.replies_with(IPv6(src="::", dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=4))
        
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
        
    def test_erroneous_header_invalid_dst(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst="::")/ICMPv6ParamProblem(code=0, ptr=4))
        
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
        
    def test_erroneous_header_invalid_layer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip())))
        
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
        
    def test_erroneous_header_invalid_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=4))
        
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
        
    def test_erroneous_header_invalid_mtu(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=4)/Raw(load='A'*1300))
        
        o = self.get_outcome(suite.ErroneousHeaderFieldTestCase)

        self.assertCheckFails(o)
