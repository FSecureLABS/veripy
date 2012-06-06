from contrib.rfc4443 import error_condition_with_non_unique_source_anycast as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class UDPPortUnreachableTestCase(ComplianceTestTestCase):

    def test_port_unreachable_valid(self):
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckPasses(o)
        
    def test_port_unreachable_invalid_user_response(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckFails(o)

    def test_port_unreachable_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append('n')

        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckPasses(o)

    def test_port_unreachable_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6DestUnreach())
        self.ui.inputs.append('n')
        
        o = self.get_outcome(suite.UDPPortUnreachableTestCase)

        self.assertCheckFails(o)


class EchoRequestTooBigTestCase(ComplianceTestTestCase):

    def test_packet_too_big_valid(self):
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.EchoRequestTooBigTestCase)

        self.assertCheckPasses(o)
        
    def test_packet_too_big_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.EchoRequestTooBigTestCase)

        self.assertCheckPasses(o)

    def test_packet_too_big_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6PacketTooBig())
        self.ui.inputs.append('y')

        o = self.get_outcome(suite.EchoRequestTooBigTestCase)

        self.assertCheckFails(o)


class EchoRequestReassemblyTimeoutTestCase(ComplianceTestTestCase):

    def test_reassembly_timeout_valid(self):
        o = self.get_outcome(suite.EchoRequestReassemblyTimeoutTestCase)

        self.assertCheckPasses(o)

    def test_reassembly_timeout_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.EchoRequestReassemblyTimeoutTestCase)

        self.assertCheckPasses(o)

    def test_reassembly_timeout_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6TimeExceeded())

        o = self.get_outcome(suite.EchoRequestReassemblyTimeoutTestCase)

        self.assertCheckFails(o)


class EchoRequestWithUnknownOptionInDestinationOptionsTestCase(ComplianceTestTestCase):

    def test_unknown_dest_options_valid(self):
        o = self.get_outcome(suite.EchoRequestWithUnknownOptionInDestinationOptionsTestCase)

        self.assertCheckPasses(o)

    def test_unknown_dest_options_valid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())

        o = self.get_outcome(suite.EchoRequestWithUnknownOptionInDestinationOptionsTestCase)

        self.assertCheckPasses(o)

    def test_unknown_dest_options_invalid_reply(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6ParamProblem())

        o = self.get_outcome(suite.EchoRequestWithUnknownOptionInDestinationOptionsTestCase)

        self.assertCheckFails(o)
    