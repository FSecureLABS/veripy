from contrib.rfc2460 import flow_label_non_zero as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase

class FlowLabelNonZeroTestCaseTestCase(ComplianceTestTestCase):

    def test_flow_label_non_zero_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()), fl=0)/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.FlowLabelNonZeroTestCase)
        
        self.assertCheckPasses(o)
    
    def test_flow_label_non_zero_no_reply_test_case(self):
        self.ifx.replies_with(None)

        o = self.get_outcome(suite.FlowLabelNonZeroTestCase)

        self.assertCheckFails(o)
    
    def test_flow_label_non_zero_specific_usage(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()), fl=0)/ICMPv6EchoReply())
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.FlowLabelNonZeroTestCase)

        self.assertCheckPasses(o)

    def test_flow_label_non_zero_no_specific_usage(self):
        self.ifx.replies_with(None)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.FlowLabelNonZeroTestCase)

        self.assertCheckFails(o)

class FlowLabelNonZeroIntermediateNodeTestCase(ComplianceTestTestCase):

    def test_unmodified_fl_does_not_support_use(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), fl=0x34567)/ICMPv6EchoRequest(), to=self.ify)
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.FlowLabelNonZeroIntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_unmodified_fl_does_support_use(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), fl=0x34567)/ICMPv6EchoRequest(), to=self.ify)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.FlowLabelNonZeroIntermediateNodeTestCase)

        self.assertCheckPasses(o)
    
    def test_modified_fl_does_not_support_use(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), fl=0)/ICMPv6EchoRequest(), to=self.ify)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.FlowLabelNonZeroIntermediateNodeTestCase)

        self.assertCheckFails(o)
    
    def test_modified_fl_does_support_use(self):
        self.ifx.replies_with(IPv6(src=str(self.tn1.global_ip()), dst=str(self.tn4.global_ip()), fl=0)/ICMPv6EchoRequest(), to=self.ify)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.FlowLabelNonZeroIntermediateNodeTestCase)

        self.assertCheckPasses(o)