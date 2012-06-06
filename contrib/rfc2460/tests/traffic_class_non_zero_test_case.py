from contrib.rfc2460 import traffic_class_non_zero as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class TrafficClassNonZeroEndNodeTestCase(ComplianceTestTestCase):

    def test_traffic_class_non_zero(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.TrafficClassNonZeroEndNodeTestCase)
        
        self.assertCheckPasses(o)
    
    def test_traffic_class_non_zero_no_reply(self):
        o = self.get_outcome(suite.TrafficClassNonZeroEndNodeTestCase)

        self.assertCheckFails(o)

    def test_traffic_class_non_zero_specific_usage(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()), tc=0)/ICMPv6EchoReply())
        
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.TrafficClassNonZeroEndNodeTestCase)
        
        self.assertCheckPasses(o)
    
    def test_traffic_class_non_zero_no_specific_usage(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()), tc=5)/ICMPv6EchoReply())

        self.ui.inputs.append('n')

        o = self.get_outcome(suite.TrafficClassNonZeroEndNodeTestCase)

        self.assertCheckFails(o)


class TrafficClassNonZeroIntermediateNodeTestCase(ComplianceTestTestCase):

    def test_unmodified_response_supports_specific_use_of_traffic_class(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), tc=32)/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.TrafficClassNonZeroIntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_unmodified_response_no_supports_specific_use_of_traffic_class(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), tc=32)/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.TrafficClassNonZeroIntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_non_zero_response_supports_specific_use_of_traffic_class(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), tc=1)/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.TrafficClassNonZeroIntermediateNodeTestCase)

        self.assertCheckPasses(o)

    def test_non_zero_response_no_supports_specific_use_of_traffic_class(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), tc=1)/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.TrafficClassNonZeroIntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_zero_response_supports_specific_use_of_traffic_class(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), tc=0)/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.TrafficClassNonZeroIntermediateNodeTestCase)

        self.assertCheckFails(o)

    def test_zero_response_no_supports_specific_use_of_traffic_class(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=(self.tn1.global_ip()), tc=0)/ICMPv6EchoRequest(), to=self.ifx)
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.TrafficClassNonZeroIntermediateNodeTestCase)

        self.assertCheckFails(o)
        