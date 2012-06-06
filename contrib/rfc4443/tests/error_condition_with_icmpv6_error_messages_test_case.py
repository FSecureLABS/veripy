from contrib.rfc4443 import error_condition_with_icmpv6_error_messages as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class FlawedDstUnreachableCode0WithDestinationUnreachableTestCase(ComplianceTestTestCase):
    
    def test_flawed_destination_address_valid(self):
        o = self.get_outcome(suite.FlawedDstUnreachableCode0WithDestinationUnreachableTestCase)

        self.assertCheckPasses(o)

    def test_flawed_destination_address_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=3))

        o = self.get_outcome(suite.FlawedDstUnreachableCode0WithDestinationUnreachableTestCase)

        self.assertCheckFails(o)
        

class FlawedDstUnreachableCode3WithHopLimit0TestCase(ComplianceTestTestCase):

    def test_flawed_destination_hop_valid(self):
        o = self.get_outcome(suite.FlawedDstUnreachableCode3WithHopLimit0TestCase)

        self.assertCheckPasses(o)


    def test_flawed_destination_hop_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.FlawedDstUnreachableCode3WithHopLimit0TestCase)

        self.assertCheckFails(o)


class FlawedTimeExceededCode0WithNoRouteToDestinationTestCase(ComplianceTestTestCase):

    def test_flawed_time_code_0_valid(self):
        o = self.get_outcome(suite.FlawedTimeExceededCode0WithNoRouteToDestinationTestCase)

        self.assertCheckPasses(o)


    def test_flawed_time_code_0_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=0))

        o = self.get_outcome(suite.FlawedTimeExceededCode0WithNoRouteToDestinationTestCase)

        self.assertCheckFails(o)


class FlawedTimeExceededCode1WithNoRouteToDestinationTestCase(ComplianceTestTestCase):

    def test_flawed_time_code_1_valid(self):
        o = self.get_outcome(suite.FlawedTimeExceededCode1WithNoRouteToDestinationTestCase)

        self.assertCheckPasses(o)


    def test_flawed_time_code_1_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=0))

        o = self.get_outcome(suite.FlawedTimeExceededCode1WithNoRouteToDestinationTestCase)

        self.assertCheckFails(o)


class FlawedDstPacketTooBigWithAddressUnreachableTestCase(ComplianceTestTestCase):

    def test_flawed_size_address_valid(self):
        o = self.get_outcome(suite.FlawedDstPacketTooBigWithAddressUnreachableTestCase)

        self.assertCheckPasses(o)


    def test_flawed_size_address_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach(code=3))

        o = self.get_outcome(suite.FlawedDstPacketTooBigWithAddressUnreachableTestCase)

        self.assertCheckFails(o)


class FlawedParamProblemWithHopLimit0TestCase(ComplianceTestTestCase):

    def test_flawed_param_valid(self):
        o = self.get_outcome(suite.FlawedParamProblemWithHopLimit0TestCase)

        self.assertCheckPasses(o)

    def test_flawed_param_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded(code=0))

        o = self.get_outcome(suite.FlawedParamProblemWithHopLimit0TestCase)

        self.assertCheckFails(o)
        