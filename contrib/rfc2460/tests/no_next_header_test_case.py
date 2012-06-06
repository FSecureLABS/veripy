from contrib.rfc2460 import no_next_header as suite
from scapy.all import *
from veripy.testability import ComplianceTestTestCase


class NoNextHeaderTestCaseTestCase(ComplianceTestTestCase):

    def test_no_next_header_test_case(self):
        o = self.get_outcome(suite.NoNextHeaderTestCase)
        
        self.assertCheckPasses(o)
    
    def test_no_next_header_reply_test_case(self):
        self.ifx.replies_with(IPv6(src=str(self.ifx.global_ip()), dst=str(self.tn1.global_ip()))/ICMPv6EchoReply())
        
        o = self.get_outcome(suite.NoNextHeaderTestCase)

        self.assertCheckFails(o)


class RUTForwardsNoNextHeader(ComplianceTestTestCase):

    def test_payload_unchanged(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=59)/ICMPv6EchoRequest(), to=self.ifx)

        o = self.get_outcome(suite.RUTForwardsNoNextHeader)

        self.assertCheckPasses(o)

    def test_payload_is_not_delivered(self):
        o = self.get_outcome(suite.RUTForwardsNoNextHeader)

        self.assertCheckFails(o)

    def test_payload_changed_after_ipv6_header(self):
        self.ify.replies_with(IPv6(src=str(self.tn4.global_ip()), dst=str(self.tn1.global_ip()), nh=59)/ICMPv6EchoRequest(data='IPv6'), to=self.ifx)

        o = self.get_outcome(suite.RUTForwardsNoNextHeader)

        self.assertCheckFails(o)
        