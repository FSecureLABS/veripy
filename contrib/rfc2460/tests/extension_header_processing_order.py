from contrib.rfc2460 import extension_header_processing_order as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class ExtensionHeaderProcessingOrderTestCaseTestCase(ComplianceTestTestCase):
    
    def test_destination_options_header_precedes_fragment_header_and_error_from_destination_options_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=50))
        
        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase)
        
        self.assertCheckPasses(o)

    def test_destination_options_header_precedes_fragment_header_and_error_from_destination_options_header_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=50))
        
        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase)
        
        self.assertCheckFails(o)
        
    def test_destination_options_header_precedes_fragment_header_and_error_from_destination_options_header_incorrect_ptr(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=40))

        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase)

        self.assertCheckFails(o)
    
    def test_destination_options_header_precedes_fragment_header_and_error_from_destination_options_header_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromDstOptnsHdrTestCase)
        
        self.assertCheckFails(o)


    def test_destination_options_header_precedes_fragment_header_and_error_from_fragment_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=4))

        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase)

        self.assertCheckPasses(o)
    
    def test_destination_options_header_precedes_fragment_header_and_error_from_fragment_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=4))

        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase)
        
        self.assertCheckFails(o)
    
    def test_destination_options_header_precedes_fragment_header_and_error_from_fragment_header_incorrect_ptr(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=5))

        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase)

        self.assertCheckFails(o)
    
    def test_destination_options_header_precedes_fragment_header_and_error_from_fragment_header_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.DstOptnsHdrPrecedesFragHdrAndErrorFromFragHdrTestCase)

        self.assertCheckFails(o)


    def test_fragment_header_precedes_destination_options_header_and_error_from_fragment_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=4))

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase)

        self.assertCheckPasses(o)
    
    def test_fragment_header_precedes_destination_options_header_and_error_from_fragment_header_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=4))
        
        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase)
        
        self.assertCheckFails(o)
    
    def test_fragment_header_precedes_destination_options_header_and_error_from_fragment_header_incorrect_ptr(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=0, ptr=5))
        
        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase)
        
        self.assertCheckFails(o)
    
    def test_fragment_header_precedes_destination_options_header_and_error_from_fragment_header_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromFragHdrTestCase)

        self.assertCheckFails(o)


    def test_fragment_header_precedes_destination_options_header_and_error_from_destination_options_header(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=50))

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase)

        self.assertCheckPasses(o)

    def test_fragment_header_precedes_destination_options_header_and_error_from_destination_options_header_incorrect_code(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=1, ptr=50))

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase)

        self.assertCheckFails(o)
        
    def test_fragment_header_precedes_destination_options_header_and_error_from_destination_options_header_incorrect_ptr(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem(code=2, ptr=60))

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase)

        self.assertCheckFails(o)

    def test_fragment_header_precedes_destination_options_header_and_error_from_destination_options_header_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase)

        self.assertCheckFails(o)
    
    def test_fragment_header_precedes_destination_options_header_and_error_from_destination_options_header_fragment(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/IPerror6()/IPv6ExtHdrFragment())

        o = self.get_outcome(suite.FragHdrPrecedesDstOptnsHdrAndErrorFromDstOptnsHdrTestCase)

        self.assertCheckFails(o)
