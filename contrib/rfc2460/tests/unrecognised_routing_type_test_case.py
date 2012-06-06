from contrib.rfc2460 import unrecognised_routing_type as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UnrecognisedRoutingTypeTestCase(ComplianceTestTestCase):

    def test_type_33(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33TestCase)

        self.assertCheckPasses(o)
    
    def test_type_33_no_reply(self):
        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33TestCase)
        
        self.assertCheckFails(o)
    
    def test_type_0(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.UnrecognisedRoutingTypeType0TestCase)
        
        self.assertCheckPasses(o)
    
    def test_type_0_no_reply(self):
        o = self.get_outcome(suite.UnrecognisedRoutingTypeType0TestCase)
        
        self.assertCheckFails(o)

class UnrecognisedRoutingTypeType33IntermediateNodeTestCase(ComplianceTestTestCase):
    
    def test_parameter_problem_returned(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ParamProblem(ptr=0x2a, code=0))

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_echo_request_not_forwarded_but_no_parameter_problem(self):
        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_echo_request_is_forwarded(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_parameter_problem_has_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ParamProblem(ptr=0x00, code=0))

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_parameter_problem_has_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ParamProblem(ptr=0x2a, code=5))

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)


class UnrecognisedRoutingTypeType0IntermediateNodeTestCase(ComplianceTestTestCase):

    def test_parameter_problem_returned(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ParamProblem(ptr=0x2a, code=0))

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_echo_request_not_forwarded_but_no_parameter_problem(self):
        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_echo_request_is_forwarded(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_parameter_problem_has_incorrect_pointer(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ParamProblem(ptr=0x00, code=0))

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_parameter_problem_has_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn2.global_ip()))/ICMPv6ParamProblem(ptr=0x2a, code=5))

        o = self.get_outcome(suite.UnrecognisedRoutingTypeType33IntermediateNodeTestCase)

        self.assertCheckFails(o)
